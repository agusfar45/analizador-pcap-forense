#!/usr/bin/env python3
"""
analizar_pcap.py - Análisis forense de capturas de red (.pcap / .pcapng) con scapy.

Qué saca:
  - SHA-256 de la captura (cadena de custodia), rango horario, protocolos
  - hosts y conversaciones, con bytes en cada sentido
  - consultas y respuestas DNS
  - pedidos HTTP (método, host, URI, User-Agent) y respuestas
  - sitios HTTPS visitados por el SNI del TLS ClientHello (sin descifrar nada)
  - banners SSH
  - alertas (indicios, a confirmar por el perito):
      * posible exfiltración: mucho más subido que bajado hacia una IP pública
      * HTTP PUT/POST grande o con Host que es una IP
      * conexión a una IP pública que nunca se resolvió por DNS
      * fuerza bruta (muchas conexiones cortas al mismo servicio) y la sesión
        "distinta" de esa misma IP, que sugiere que el acceso funcionó
      * nombres DNS con aspecto aleatorio (túnel DNS / DGA)
      * credenciales en texto claro (HTTP Basic, FTP)

Uso:
  python analizar_pcap.py captura.pcap [-o salida/] [--zona -3] [--umbral-subida 500000]
Con -o genera CSV (dns, http, tls_sni, conversaciones, alertas) e informe.html.
"""
import argparse
import csv
import hashlib
import html
import ipaddress
import logging
import math
import re
import statistics
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

logging.getLogger("scapy").setLevel(logging.ERROR)  # sin el aviso de libpcap: para leer archivos no hace falta
from scapy.all import DNS, IP, TCP, UDP, PcapReader, Raw  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402

METODOS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
PUERTOS_ACCESO = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 445: "SMB"}
TIPOS_DNS = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


# ----------------------------------------------------------------------------- parsers

def parsear_sni(payload: bytes):
    """Devuelve el server_name de un TLS ClientHello, o None. Parseo a mano, con chequeo de largos,
    porque los datos vienen de la red y pueden estar truncados o ser maliciosos."""
    try:
        if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
            return None
        p = 5 + 4 + 2 + 32                       # record hdr, handshake hdr, versión, random
        p += 1 + payload[p]                      # session id
        p += 2 + struct.unpack_from(">H", payload, p)[0]   # cipher suites
        p += 1 + payload[p]                      # compresión
        fin_ext = p + 2 + struct.unpack_from(">H", payload, p)[0]
        p += 2
        while p + 4 <= min(fin_ext, len(payload)):
            tipo, largo = struct.unpack_from(">HH", payload, p)
            p += 4
            if tipo == 0:  # server_name
                q = p + 2
                while q + 3 <= p + largo:
                    ntipo, nlargo = payload[q], struct.unpack_from(">H", payload, q + 1)[0]
                    if ntipo == 0:
                        # el SNI va siempre en ASCII (RFC 6066; los IDN viajan como xn--...)
                        return payload[q + 3:q + 3 + nlargo].decode("ascii", "replace")
                    q += 3 + nlargo
                return None
            p += largo
    except (IndexError, struct.error, UnicodeError):
        return None
    return None


def parsear_http(payload: bytes):
    """Pedido HTTP/1.x al comienzo de un segmento: (método, uri, {cabeceras}) o None."""
    if not payload.startswith(METODOS):
        return None
    cabecera = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lineas = cabecera.split("\r\n")
    partes = lineas[0].split(" ")
    if len(partes) < 3 or not partes[2].startswith("HTTP/"):
        return None
    campos = {}
    for linea in lineas[1:]:
        if ":" in linea:
            k, v = linea.split(":", 1)
            campos[k.strip().lower()] = v.strip()
    return partes[0], partes[1], campos


def parsear_respuesta_http(payload: bytes):
    m = re.match(rb"HTTP/1\.[01] (\d{3}) ?([^\r\n]*)", payload)
    return (int(m.group(1)), m.group(2).decode("latin-1")) if m else None


def entropia(texto: str) -> float:
    if not texto:
        return 0.0
    c = Counter(texto)
    return -sum(n / len(texto) * math.log2(n / len(texto)) for n in c.values())


def parece_aleatorio(nombre: str) -> bool:
    """Etiqueta DNS larga y con mucha entropía: típico de túneles DNS o dominios generados (DGA)."""
    etiquetas = nombre.rstrip(".").split(".")
    return any(len(e) >= 20 and entropia(e) > 3.5 for e in etiquetas[:-2] or etiquetas[:1])


def es_publica(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Los rangos de documentación (RFC 5737) se tratan como públicos: así funciona la demo
    doc = any(a in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
    return doc or not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast)


def es_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.rsplit(":", 1)[0].strip("[]"))
        return True
    except ValueError:
        return False


def verificar_integridad(ruta):
    """Recorre los encabezados de registro de un .pcap clásico (sin interpretar paquetes) y avisa si:
      - el archivo termina a mitad de un registro (captura cortada / copia incompleta), o
      - hay paquetes guardados incompletos (incl_len < orig_len, por el snaplen de la captura).
    Devuelve una lista de avisos. Para pcapng solo informa que no se verificó."""
    avisos = []
    with open(ruta, "rb") as f:
        cab = f.read(24)
        formatos = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
        if cab[:4] == b"\x0a\x0d\x0d\x0a":
            return ["pcapng: integridad de registros no verificada (solo se verifica .pcap clásico)"]
        if len(cab) < 24 or cab[:4] not in formatos:
            return ["no es un .pcap clásico reconocible"]
        orden = formatos[cab[:4]]
        snaplen = struct.unpack(orden + "I", cab[16:20])[0]
        n = recortados = 0
        while True:
            reg = f.read(16)
            if not reg:
                break
            if len(reg) < 16:
                avisos.append(f"el archivo termina a mitad del encabezado del registro {n + 1}: captura TRUNCADA")
                break
            _, _, incl, orig = struct.unpack(orden + "IIII", reg)
            datos = f.read(incl)
            if len(datos) < incl:
                avisos.append(f"el último registro (paquete {n + 1}) está cortado: tiene {len(datos)} de {incl} "
                              f"bytes. Captura TRUNCADA: puede faltar tráfico posterior")
                break
            n += 1
            recortados += incl < orig
        if recortados:
            avisos.append(f"{recortados} paquete(s) guardados incompletos por el snaplen ({snaplen} bytes): "
                          "faltan datos de aplicación")
    return avisos


# ----------------------------------------------------------------------------- análisis

class Flujo:
    __slots__ = ("cli", "cport", "srv", "sport", "proto", "inicio", "fin", "paquetes",
                 "bytes_cs", "bytes_ss", "syn", "servicio")

    def __init__(self, cli, cport, srv, sport, proto, t, syn):
        self.cli, self.cport, self.srv, self.sport, self.proto = cli, cport, srv, sport, proto
        self.inicio = self.fin = t
        self.paquetes = self.bytes_cs = self.bytes_ss = 0
        self.syn, self.servicio = syn, ""


def analizar(ruta, umbral_subida=500_000):
    r = {
        "paquetes": 0, "bytes": 0, "inicio": None, "fin": None, "protocolos": Counter(),
        "hosts": defaultdict(lambda: {"enviados": 0, "recibidos": 0, "paquetes": 0}),
        "flujos": {}, "dns": [], "resueltas": {}, "http": [], "sni": [], "ssh": [], "alertas": [],
        "credenciales": [],
    }
    flujos = r["flujos"]

    with PcapReader(str(ruta)) as lector:
        for pkt in lector:
            t = float(pkt.time)
            r["paquetes"] += 1
            r["bytes"] += len(pkt)
            r["inicio"] = t if r["inicio"] is None else min(r["inicio"], t)
            r["fin"] = t if r["fin"] is None else max(r["fin"], t)

            capa_ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
            if capa_ip is None:
                r["protocolos"]["no IP"] += 1
                continue
            src, dst = capa_ip.src, capa_ip.dst
            r["hosts"][src]["enviados"] += len(pkt); r["hosts"][src]["paquetes"] += 1
            r["hosts"][dst]["recibidos"] += len(pkt)

            if TCP in pkt:
                proto, l4 = "TCP", pkt[TCP]
            elif UDP in pkt:
                proto, l4 = "UDP", pkt[UDP]
            else:
                r["protocolos"]["otro IP"] += 1
                continue
            sp, dp = int(l4.sport), int(l4.dport)
            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            syn = proto == "TCP" and (int(l4.flags) & 0x12) == 0x02   # SYN sin ACK: abre el cliente

            # Flujo: el cliente es quien mandó el SYN; si no lo vimos, el puerto más bajo es el servidor
            clave_a, clave_b = (src, sp, dst, dp, proto), (dst, dp, src, sp, proto)
            if clave_a in flujos:
                f, ida = flujos[clave_a], True
            elif clave_b in flujos:
                f, ida = flujos[clave_b], False
            else:
                if syn or dp < sp or (proto == "UDP" and dp in (53, 123)):
                    f, ida = Flujo(src, sp, dst, dp, proto, t, syn), True
                    flujos[clave_a] = f
                else:
                    f, ida = Flujo(dst, dp, src, sp, proto, t, syn), False
                    flujos[clave_b] = f
            f.fin = t
            f.paquetes += 1
            if ida:
                f.bytes_cs += len(payload)
            else:
                f.bytes_ss += len(payload)

            # ---- DNS
            if proto == "UDP" and DNS in pkt and 53 in (sp, dp):
                r["protocolos"]["DNS"] += 1
                d = pkt[DNS]
                preguntas = d.qd if isinstance(d.qd, list) else ([d.qd] if d.qd else [])
                if not d.qr:
                    for q in preguntas:
                        nombre = q.qname.decode("utf-8", "replace").rstrip(".")
                        r["dns"].append({"t": t, "cliente": src, "servidor": dst, "nombre": nombre,
                                         "tipo": TIPOS_DNS.get(int(q.qtype), str(q.qtype)), "respuestas": ""})
                else:
                    respuestas = d.an if isinstance(d.an, list) else ([d.an] if d.an else [])
                    ips = []
                    for rr in respuestas:
                        if int(rr.type) in (1, 28):
                            ip = str(rr.rdata)
                            ips.append(ip)
                            r["resueltas"].setdefault(ip, (t, rr.rrname.decode("utf-8", "replace").rstrip(".")))
                    # completar la consulta correspondiente (última del mismo nombre sin respuesta)
                    if preguntas:
                        nombre = preguntas[0].qname.decode("utf-8", "replace").rstrip(".")
                        for q in reversed(r["dns"]):
                            if q["nombre"] == nombre and not q["respuestas"]:
                                q["respuestas"] = ", ".join(ips) or f"rcode {d.rcode}"
                                break
                continue

            if proto != "TCP" or not payload:
                r["protocolos"]["TCP sin datos (SYN/ACK/FIN)" if proto == "TCP" else "UDP (otro)"] += 1
                continue

            # ---- aplicación (miramos el comienzo de cada segmento)
            if (h := parsear_http(payload)) is not None:
                r["protocolos"]["HTTP"] += 1
                metodo, uri, campos = h
                f.servicio = "HTTP"
                r["http"].append({"t": t, "cliente": src, "servidor": f"{dst}:{dp}", "metodo": metodo,
                                  "host": campos.get("host", ""), "uri": uri,
                                  "user_agent": campos.get("user-agent", ""),
                                  "content_length": campos.get("content-length", ""), "respuesta": "",
                                  "_flujo": f})
                if campos.get("authorization", "").lower().startswith("basic"):
                    r["credenciales"].append((t, src, f"{dst}:{dp}", "HTTP Basic (Authorization)"))
            elif (resp := parsear_respuesta_http(payload)) is not None:
                r["protocolos"]["HTTP"] += 1
                for pedido in reversed(r["http"]):
                    if pedido["_flujo"] is f:
                        if not pedido["respuesta"] or pedido["respuesta"].startswith("100"):
                            pedido["respuesta"] = f"{resp[0]} {resp[1]}"
                        break
            elif (sni := parsear_sni(payload)) is not None:
                r["protocolos"]["TLS"] += 1
                f.servicio = "TLS"
                r["sni"].append({"t": t, "cliente": src, "servidor": f"{dst}:{dp}", "sni": sni})
            elif payload.startswith(b"SSH-"):
                r["protocolos"]["SSH"] += 1
                f.servicio = "SSH"
                r["ssh"].append({"t": t, "origen": src, "destino": f"{dst}:{dp}",
                                 "banner": payload.split(b"\r\n")[0].decode("latin-1")[:80]})
            elif dp == 21 and re.match(rb"(USER|PASS) ", payload):
                r["protocolos"]["FTP"] += 1
                r["credenciales"].append((t, src, f"{dst}:{dp}", "FTP " + payload[:4].decode()))
            else:
                r["protocolos"]["TCP datos (continuación / cifrado)"] += 1

    generar_alertas(r, umbral_subida)
    return r


def alerta(r, t, nivel, tipo, detalle):
    r["alertas"].append({"t": t, "nivel": nivel, "tipo": tipo, "detalle": detalle})


def generar_alertas(r, umbral_subida):
    flujos = list(r["flujos"].values())

    # 1) posible exfiltración
    for f in flujos:
        if not es_publica(f.cli) and es_publica(f.srv) and f.bytes_cs >= umbral_subida \
                and f.bytes_cs > 5 * max(f.bytes_ss, 1):
            alerta(r, f.inicio, "ALTA", "Posible exfiltración",
                   f"{f.cli} subió {f.bytes_cs:,} bytes a {f.srv}:{f.sport} y recibió solo {f.bytes_ss:,} "
                   f"({f.fin - f.inicio:.1f} s)")

    # 2) HTTP sospechoso
    for h in r["http"]:
        largo = int(h["content_length"]) if h["content_length"].isdigit() else 0
        motivos = []
        if h["metodo"] in ("PUT", "POST") and largo >= umbral_subida:
            motivos.append(f"{h['metodo']} de {largo:,} bytes")
        if es_ip_literal(h["host"]):
            motivos.append("el Host es una IP, no un nombre")
        if motivos:
            alerta(r, h["t"], "ALTA" if h["metodo"] in ("PUT", "POST") else "MEDIA", "HTTP sospechoso",
                   f"{h['metodo']} http://{h['host']}{h['uri']} desde {h['cliente']} "
                   f"(User-Agent: {h['user_agent'] or '—'}): {'; '.join(motivos)}")

    # 3) conexiones salientes a IP pública nunca resuelta por DNS antes
    vistos = set()
    for f in sorted(flujos, key=lambda x: x.inicio):
        if f.proto != "TCP" or not f.syn or es_publica(f.cli) or not es_publica(f.srv):
            continue
        resuelta = r["resueltas"].get(f.srv)
        if (resuelta is None or resuelta[0] > f.inicio) and (f.srv, f.sport) not in vistos:
            vistos.add((f.srv, f.sport))
            alerta(r, f.inicio, "MEDIA", "IP directa sin DNS",
                   f"{f.cli} se conectó a {f.srv}:{f.sport} sin haber resuelto ningún nombre que apunte a esa IP")

    # 4) fuerza bruta + sesión distinta de la misma IP
    por_origen = defaultdict(list)
    for f in flujos:
        if f.proto == "TCP" and f.sport in PUERTOS_ACCESO and es_publica(f.cli):
            por_origen[(f.cli, f.srv, f.sport)].append(f)
    for (ip, srv, puerto), lista in por_origen.items():
        if len(lista) < 10:
            continue
        lista.sort(key=lambda x: x.inicio)
        tamanos = [x.bytes_cs + x.bytes_ss for x in lista]
        mediana = statistics.median(tamanos)
        alerta(r, lista[0].inicio, "ALTA", "Fuerza bruta",
               f"{ip} abrió {len(lista)} conexiones a {PUERTOS_ACCESO[puerto]} de {srv} "
               f"({fmt_hora(lista[0].inicio)} → {fmt_hora(lista[-1].inicio)}), mediana {mediana:,.0f} bytes c/u")
        for x, tam in zip(lista, tamanos):
            if tam > 10 * mediana:
                alerta(r, x.inicio, "ALTA", "Sesión distinta tras fuerza bruta",
                       f"{ip} → {srv}:{puerto}: {tam:,} bytes en {x.fin - x.inicio:.0f} s "
                       f"({tam / mediana:.0f} veces la mediana de sus intentos). Sugiere que el acceso funcionó: "
                       f"cruzar con auth.log")

    # 5) DNS con aspecto aleatorio
    for q in r["dns"]:
        if parece_aleatorio(q["nombre"]):
            alerta(r, q["t"], "MEDIA", "DNS con nombre aleatorio",
                   f"{q['cliente']} consultó {q['nombre']} (posible túnel DNS o dominio generado)")

    # 6) credenciales en claro
    for t, src, dst, tipo in r["credenciales"]:
        alerta(r, t, "ALTA", "Credenciales en texto claro", f"{src} → {dst}: {tipo}")

    r["alertas"].sort(key=lambda a: a["t"])


# ----------------------------------------------------------------------------- salida

ZONA = timezone.utc


def fmt(t):
    return datetime.fromtimestamp(t, ZONA).strftime("%d/%m/%Y %H:%M:%S") if t is not None else "—"


def fmt_hora(t):
    return datetime.fromtimestamp(t, ZONA).strftime("%H:%M:%S")


def sha256(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    return h.hexdigest()


def top_conversaciones(r, n=15):
    return sorted(r["flujos"].values(), key=lambda f: f.bytes_cs + f.bytes_ss, reverse=True)[:n]


def imprimir(r, ruta, hash_captura):
    print(f"Captura: {ruta}\nSHA-256: {hash_captura}")
    print(f"{r['paquetes']:,} paquetes, {r['bytes']:,} bytes · {fmt(r['inicio'])} → {fmt(r['fin'])} ({ZONA_TXT})")
    print("Protocolos: " + ", ".join(f"{k} {v}" for k, v in r["protocolos"].most_common()))
    for aviso in r.get("avisos", []):
        print(f"AVISO DE INTEGRIDAD: {aviso}")

    print(f"\n=== Alertas ({len(r['alertas'])}) — indicios a verificar ===")
    for a in r["alertas"]:
        print(f"[{a['nivel']:<5}] {fmt(a['t'])}  {a['tipo']}: {a['detalle']}")

    print("\n=== Consultas DNS ===")
    vistos = Counter(q["nombre"] for q in r["dns"])
    for nombre, n in vistos.most_common():
        resp = next((q["respuestas"] for q in r["dns"] if q["nombre"] == nombre and q["respuestas"]), "")
        print(f"  {n:>3}×  {nombre:<40} → {resp}")

    print("\n=== Sitios HTTPS (SNI) ===")
    for s in r["sni"]:
        print(f"  {fmt(s['t'])}  {s['cliente']:<15} → {s['sni']}  ({s['servidor']})")

    print("\n=== Pedidos HTTP ===")
    for h in r["http"]:
        print(f"  {fmt(h['t'])}  {h['cliente']:<15} {h['metodo']:<5} http://{h['host']}{h['uri']}  "
              f"[{h['respuesta'] or 'sin respuesta'}]  UA: {h['user_agent']}")

    print("\n=== Conversaciones con más tráfico ===")
    for f in top_conversaciones(r, 10):
        print(f"  {f.cli:>15}:{f.cport:<5} → {f.srv:>15}:{f.sport:<5} {f.proto} {f.servicio:<4}  "
              f"↑ {f.bytes_cs:>9,}  ↓ {f.bytes_ss:>9,}  {fmt(f.inicio)}")


def guardar_csv(r, carpeta):
    carpeta.mkdir(parents=True, exist_ok=True)

    def escribir(nombre, filas, campos):
        with open(carpeta / nombre, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=campos, extrasaction="ignore")
            w.writeheader()
            for fila in filas:
                w.writerow({**fila, "fecha_hora": fmt(fila["t"])})

    escribir("dns.csv", r["dns"], ["fecha_hora", "cliente", "servidor", "nombre", "tipo", "respuestas"])
    escribir("http.csv", r["http"], ["fecha_hora", "cliente", "servidor", "metodo", "host", "uri",
                                    "user_agent", "content_length", "respuesta"])
    escribir("tls_sni.csv", r["sni"], ["fecha_hora", "cliente", "servidor", "sni"])
    escribir("alertas.csv", r["alertas"], ["fecha_hora", "nivel", "tipo", "detalle"])
    filas = [{"t": f.inicio, "cliente": f"{f.cli}:{f.cport}", "servidor": f"{f.srv}:{f.sport}", "proto": f.proto,
              "servicio": f.servicio, "paquetes": f.paquetes, "bytes_subida": f.bytes_cs,
              "bytes_bajada": f.bytes_ss, "duracion_s": round(f.fin - f.inicio, 3)}
             for f in sorted(r["flujos"].values(), key=lambda f: f.inicio)]
    escribir("conversaciones.csv", filas, ["fecha_hora", "cliente", "servidor", "proto", "servicio", "paquetes",
                                           "bytes_subida", "bytes_bajada", "duracion_s"])


def guardar_html(r, ruta, hash_captura, salida):
    e = lambda x: html.escape(str(x))  # todo lo que viene de la red lo controla otro: se escapa siempre
    altas = sum(a["nivel"] == "ALTA" for a in r["alertas"])
    p = [f"""<!doctype html><html lang="es"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Análisis de captura de red</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1040px;margin:auto;padding:16px;color:#1d2433;background:#f5f6f8}}
h1{{margin-bottom:4px}} h2{{border-bottom:2px solid #1d2433;padding-bottom:4px;margin-top:32px}}
.meta{{color:#555;font-size:14px}} code{{font-size:13px;word-break:break-all}}
table{{border-collapse:collapse;width:100%;background:#fff;font-size:13.5px}}
th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #e3e5ea;vertical-align:top}} th{{background:#eceef2}}
td.n{{text-align:right;font-variant-numeric:tabular-nums}}
.ALTA td:first-child{{border-left:4px solid #c0392b}} .ALTA{{background:#fdecea}}
.MEDIA td:first-child{{border-left:4px solid #e67e22}} .MEDIA{{background:#fff4e6}}
.tarjetas{{display:flex;gap:12px;flex-wrap:wrap}} .tarjetas div{{background:#fff;padding:10px 14px;border-radius:6px;flex:1;min-width:130px}}
.tarjetas b{{display:block;font-size:24px}} .rojo b{{color:#c0392b}}
.barra{{background:#2c6fbb;height:10px;border-radius:2px;display:inline-block}}
.barra.sube{{background:#c0392b}}
</style>
<h1>Análisis de captura de red</h1>
<p class="meta">Archivo: <code>{e(Path(ruta).name)}</code> · {Path(ruta).stat().st_size:,} bytes<br>
SHA-256: <code>{hash_captura}</code><br>
{fmt(r['inicio'])} → {fmt(r['fin'])} ({ZONA_TXT}) · Generado {datetime.now():%d/%m/%Y %H:%M} con analizar_pcap.py</p>
<div class="tarjetas"><div><b>{r['paquetes']:,}</b>paquetes</div><div><b>{len(r['flujos'])}</b>conversaciones</div>
<div><b>{len({q['nombre'] for q in r['dns']})}</b>nombres DNS</div><div><b>{len(r['sni']) + len(r['http'])}</b>pedidos web</div>
<div class="rojo"><b>{altas}</b>alertas altas</div></div>"""]
    for aviso in r.get("avisos", []):
        p.append(f"<p class='meta' style='color:#c0392b'><b>Aviso de integridad:</b> {e(aviso)}</p>")

    p.append("<h2>Alertas</h2><p class='meta'>Indicios generados automáticamente: cada uno se confirma "
             "contra la captura (Wireshark) y otras fuentes antes de ir a un informe.</p>"
             "<table><tr><th>Hora</th><th>Nivel</th><th>Tipo</th><th>Detalle</th></tr>")
    for a in r["alertas"]:
        p.append(f"<tr class='{e(a['nivel'])}'><td>{fmt(a['t'])}</td><td>{e(a['nivel'])}</td>"
                 f"<td>{e(a['tipo'])}</td><td>{e(a['detalle'])}</td></tr>")
    p.append("</table>")

    tops = top_conversaciones(r)
    maximo = max((max(f.bytes_cs, f.bytes_ss) for f in tops), default=1) or 1
    p.append("<h2>Conversaciones con más tráfico</h2><table><tr><th>Inicio</th><th>Cliente</th><th>Servidor</th>"
             "<th>Servicio</th><th>Subida</th><th>Bajada</th><th>Duración</th></tr>")
    for f in tops:
        p.append(f"<tr><td>{fmt(f.inicio)}</td><td><code>{e(f.cli)}:{f.cport}</code></td>"
                 f"<td><code>{e(f.srv)}:{f.sport}</code></td><td>{e(f.servicio or f.proto)}</td>"
                 f"<td class='n'>{f.bytes_cs:,} <span class='barra sube' style='width:{60 * f.bytes_cs / maximo:.0f}px'></span></td>"
                 f"<td class='n'>{f.bytes_ss:,} <span class='barra' style='width:{60 * f.bytes_ss / maximo:.0f}px'></span></td>"
                 f"<td class='n'>{f.fin - f.inicio:.1f} s</td></tr>")
    p.append("</table>")

    p.append("<h2>Consultas DNS</h2><table><tr><th>Hora</th><th>Cliente</th><th>Nombre</th><th>Tipo</th><th>Respuesta</th></tr>")
    for q in r["dns"]:
        p.append(f"<tr><td>{fmt(q['t'])}</td><td>{e(q['cliente'])}</td><td><code>{e(q['nombre'])}</code></td>"
                 f"<td>{e(q['tipo'])}</td><td>{e(q['respuestas'])}</td></tr>")
    p.append("</table>")

    p.append("<h2>Sitios HTTPS (SNI)</h2><p class='meta'>El nombre del sitio viaja sin cifrar en el TLS "
             "ClientHello; el contenido no se ve.</p><table><tr><th>Hora</th><th>Cliente</th><th>Sitio</th><th>Servidor</th></tr>")
    for s in r["sni"]:
        p.append(f"<tr><td>{fmt(s['t'])}</td><td>{e(s['cliente'])}</td><td><code>{e(s['sni'])}</code></td>"
                 f"<td><code>{e(s['servidor'])}</code></td></tr>")
    p.append("</table>")

    p.append("<h2>Pedidos HTTP</h2><table><tr><th>Hora</th><th>Cliente</th><th>Pedido</th><th>Respuesta</th><th>User-Agent</th></tr>")
    for h in r["http"]:
        largo = f" ({int(h['content_length']):,} B)" if h["content_length"].isdigit() else ""
        p.append(f"<tr><td>{fmt(h['t'])}</td><td>{e(h['cliente'])}</td>"
                 f"<td><code>{e(h['metodo'])} http://{e(h['host'])}{e(h['uri'])}</code>{e(largo)}</td>"
                 f"<td>{e(h['respuesta'])}</td><td>{e(h['user_agent'])}</td></tr>")
    p.append("</table>")

    hosts = sorted(r["hosts"].items(), key=lambda kv: kv[1]["enviados"] + kv[1]["recibidos"], reverse=True)[:15]
    p.append("<h2>Hosts</h2><table><tr><th>IP</th><th>Tipo</th><th>Enviados</th><th>Recibidos</th><th>Nombre DNS</th></tr>")
    for ip, d in hosts:
        nombre = r["resueltas"].get(ip, (None, ""))[1]
        p.append(f"<tr><td><code>{e(ip)}</code></td><td>{'pública' if es_publica(ip) else 'privada'}</td>"
                 f"<td class='n'>{d['enviados']:,}</td><td class='n'>{d['recibidos']:,}</td><td>{e(nombre)}</td></tr>")
    p.append("</table></html>")
    Path(salida).write_text("\n".join(p), encoding="utf-8")


ZONA_TXT = "UTC"


def main():
    global ZONA, ZONA_TXT
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("captura", type=Path)
    ap.add_argument("-o", "--salida", type=Path, help="carpeta para CSV e informe.html")
    ap.add_argument("--zona", type=float, default=0, help="horas respecto de UTC para mostrar (Argentina: -3)")
    ap.add_argument("--umbral-subida", type=int, default=500_000, help="bytes subidos para alertar exfiltración")
    a = ap.parse_args()
    if not a.captura.is_file():
        sys.exit(f"No existe: {a.captura}")

    ZONA = timezone(timedelta(hours=a.zona))
    ZONA_TXT = "UTC" if a.zona == 0 else f"UTC{a.zona:+g}"
    hash_captura = sha256(a.captura)
    avisos = verificar_integridad(a.captura)
    try:
        r = analizar(a.captura, a.umbral_subida)
    except Exception as ex:  # scapy lanza Scapy_Exception u otras según el daño del archivo
        sys.exit(f"No se pudo leer {a.captura} como captura (.pcap/.pcapng): {ex}")
    r["avisos"] = avisos
    imprimir(r, a.captura, hash_captura)
    if a.salida:
        guardar_csv(r, a.salida)
        guardar_html(r, a.captura, hash_captura, a.salida / "informe.html")
        print(f"\nCSV e informe.html en {a.salida}/")
    if sha256(a.captura) != hash_captura:
        print("ATENCIÓN: el hash de la captura cambió durante el análisis")


if __name__ == "__main__":
    main()
