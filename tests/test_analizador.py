"""Pruebas de analizar_pcap.py.   Correr desde la raíz del repo:  python -m unittest -v"""
import logging
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

logging.getLogger("scapy").setLevel(logging.ERROR)
RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

import analizar_pcap as ap  # noqa: E402
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap, wrpcapng  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402


def client_hello(sni: bytes):
    ext = struct.pack(">HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
    cuerpo = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + len(cuerpo).to_bytes(3, "big") + cuerpo
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


class Parsers(unittest.TestCase):
    def test_sni(self):
        self.assertEqual(ap.parsear_sni(client_hello(b"www.ejemplo.example")), "www.ejemplo.example")

    def test_sni_truncado_o_basura_no_rompe(self):
        hello = client_hello(b"www.ejemplo.example")
        for corte in range(len(hello)):
            ap.parsear_sni(hello[:corte])  # no debe lanzar excepciones
        self.assertIsNone(ap.parsear_sni(b"\x16\x03\x01\xff\xff\x01" + b"\xff" * 50))
        self.assertIsNone(ap.parsear_sni(b"GET / HTTP/1.1\r\n"))

    def test_http(self):
        metodo, uri, campos = ap.parsear_http(b"PUT /up HTTP/1.1\r\nHost: 10.0.0.1\r\nContent-Length: 5\r\n\r\nhola!")
        self.assertEqual((metodo, uri, campos["host"], campos["content-length"]), ("PUT", "/up", "10.0.0.1", "5"))
        self.assertIsNone(ap.parsear_http(b"GETTING things done"))
        self.assertEqual(ap.parsear_respuesta_http(b"HTTP/1.1 201 Created\r\n"), (201, "Created"))

    def test_dns_aleatorio(self):
        self.assertTrue(ap.parece_aleatorio("q8zk3x9vbn2lp7wm4rt6yh1c.tunel.example.net"))
        self.assertFalse(ap.parece_aleatorio("api.contable-nube.example.net"))
        self.assertFalse(ap.parece_aleatorio("www.municipalidad-de-salta.example.gob.ar"))

    def test_publica_privada(self):
        self.assertFalse(ap.es_publica("192.168.1.20"))
        self.assertTrue(ap.es_publica("198.51.100.200"))   # documentación: se trata como pública
        self.assertTrue(ap.es_publica("8.8.8.8"))
        self.assertFalse(ap.es_publica("fe80::1"))
        self.assertTrue(ap.es_ip_literal("198.51.100.200:8080"))
        self.assertFalse(ap.es_ip_literal("repo.example.com"))


class Demo(unittest.TestCase):
    """La captura de demo recrea el Caso 3: el analizador tiene que encontrar cada paso del ataque."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pcap = Path(cls.tmp.name) / "demo.pcap"
        subprocess.run([sys.executable, str(RAIZ / "generar_captura_demo.py"), str(cls.pcap)],
                       check=True, capture_output=True)
        cls.r = ap.analizar(cls.pcap)
        cls.tipos = [a["tipo"] for a in cls.r["alertas"]]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_fuerza_bruta_tres_ips(self):
        ips = {a["detalle"].split()[0] for a in self.r["alertas"] if a["tipo"] == "Fuerza bruta"}
        self.assertEqual(ips, {"198.51.100.23", "203.0.113.77", "192.0.2.150"})

    def test_acceso_exitoso_solo_del_atacante(self):
        sesiones = [a for a in self.r["alertas"] if a["tipo"] == "Sesión distinta tras fuerza bruta"]
        self.assertEqual(len(sesiones), 1)
        self.assertTrue(sesiones[0]["detalle"].startswith("203.0.113.77"))
        self.assertFalse(any("192.168.1.10" in a["detalle"] for a in self.r["alertas"]))  # el admin no es alerta

    def test_exfiltracion(self):
        exf = [a for a in self.r["alertas"] if a["tipo"] == "Posible exfiltración"]
        self.assertEqual(len(exf), 1)
        self.assertIn("900,125 bytes a 198.51.100.200:80", exf[0]["detalle"])  # 900.000 de datos + 125 de cabecera
        self.assertIn("IP directa sin DNS", self.tipos)
        put = [h for h in self.r["http"] if h["metodo"] == "PUT"][0]
        self.assertEqual((put["user_agent"], put["respuesta"]), ("curl/8.5.0", "201 Created"))

    def test_sni_y_dns(self):
        self.assertEqual({s["sni"] for s in self.r["sni"]},
                         {"repo.ubuntu-mirror.example.com", "api.contable-nube.example.net"})
        resueltos = {q["nombre"]: q["respuestas"] for q in self.r["dns"]}
        self.assertEqual(resueltos["ntp.example.org"], "192.0.2.123")

    def test_sin_falsos_positivos_de_dns_directo(self):
        # los sitios resueltos por DNS antes de conectarse no tienen que aparecer como "IP directa"
        directas = [a["detalle"] for a in self.r["alertas"] if a["tipo"] == "IP directa sin DNS"]
        self.assertEqual(len(directas), 1)
        self.assertIn("198.51.100.200:80", directas[0])

    def test_integridad_y_truncado(self):
        self.assertEqual(ap.verificar_integridad(self.pcap), [])
        cortada = Path(self.tmp.name) / "cortada.pcap"
        cortada.write_bytes(self.pcap.read_bytes()[:500_000])
        self.assertTrue(any("TRUNCADA" in a for a in ap.verificar_integridad(cortada)))


class Formatos(unittest.TestCase):
    def test_pcapng_ipv6_y_credenciales(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "mixta.pcapng"
            pk = [
                Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IPv6(src="2001:db8::5", dst="2001:db8::53") / UDP(sport=5353, dport=53) /
                DNS(id=7, rd=1, qd=DNSQR(qname="q8zk3x9vbn2lp7wm4rt6yh1c.tunel.example.net")),
                Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IPv6(src="2001:db8::53", dst="2001:db8::5") / UDP(sport=53, dport=5353) /
                DNS(id=7, qr=1, qd=DNSQR(qname="q8zk3x9vbn2lp7wm4rt6yh1c.tunel.example.net"),
                    an=DNSRR(rrname="q8zk3x9vbn2lp7wm4rt6yh1c.tunel.example.net", rdata="192.0.2.9")),
                Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.0.0.5", dst="192.0.2.21") / TCP(sport=40000, dport=21, flags="PA") /
                Raw(b"USER contador\r\n"),
                Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.0.0.5", dst="192.0.2.30") / TCP(sport=40001, dport=80, flags="PA") /
                Raw(b"GET /panel HTTP/1.1\r\nHost: <script>x</script>\r\nAuthorization: Basic YTpi\r\n\r\n"),
            ]
            for i, p in enumerate(pk):
                p.time = 1_800_000_000 + i
            wrpcapng(str(ruta), pk)
            r = ap.analizar(ruta)
            tipos = {a["tipo"] for a in r["alertas"]}
            self.assertIn("DNS con nombre aleatorio", tipos)
            self.assertIn("Credenciales en texto claro", tipos)
            self.assertEqual(r["dns"][0]["respuestas"], "192.0.2.9")
            # el HTML no puede contener la etiqueta inyectada sin escapar
            ap.guardar_html(r, ruta, "0" * 64, Path(tmp) / "i.html")
            contenido = (Path(tmp) / "i.html").read_text(encoding="utf-8")
            self.assertNotIn("<script>x</script>", contenido)
            self.assertIn("&lt;script&gt;", contenido)


if __name__ == "__main__":
    unittest.main()
