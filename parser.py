"""
netscope/parser.py — Parseo de protocolos (Fase 2)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ── Bug fix #1: DNS estaba importado desde scapy.layers.dns, que puede fallar
# en algunas versiones. Se importa todo desde scapy.all. ──────────────────────
from scapy.all import ARP, ICMP, IP, IPv6, UDP, TCP, Ether, Raw, DNS


# ── Puertos TCP conocidos ──────────────────────────────────────────────────────
_TCP_PORT_PROTOCOLS: dict = {
    20: "FTP-DATA",  21: "FTP",       22: "SSH",     23: "TELNET",
    25: "SMTP",      53: "DNS/TCP",   80: "HTTP",    110: "POP3",
    143: "IMAP",    443: "HTTPS/TLS", 445: "SMB",    465: "SMTPS",
    587: "SMTP",    993: "IMAPS",    995: "POP3S",   3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
    3389: "RDP",   5900: "VNC",     8080: "HTTP",   8443: "HTTPS/TLS",
}

# ── Puertos UDP conocidos ──────────────────────────────────────────────────────
_UDP_PORT_PROTOCOLS: dict = {
    53: "DNS",    67: "DHCP",   68: "DHCP",
    123: "NTP",  161: "SNMP",  514: "Syslog",
    1194: "OpenVPN", 4500: "IPSec",
}

# ── Tipos de ICMP ─────────────────────────────────────────────────────────────
_ICMP_TYPES: dict = {
    0: "Echo Reply",   3: "Unreachable",   5: "Redirect",
    8: "Echo Request", 11: "Time Exceeded", 12: "Parameter Problem",
}

_counter: int = 0


@dataclass
class ParsedPacket:
    id: int
    timestamp: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    flags: str
    info: str
    raw_packet: object = field(default=None, repr=False)

    def as_dict(self) -> dict:
        return {
            "id": self.id, "timestamp": self.timestamp,
            "protocol": self.protocol, "src_ip": self.src_ip,
            "dst_ip": self.dst_ip, "src_port": self.src_port,
            "dst_port": self.dst_port, "length": self.length,
            "flags": self.flags, "info": self.info,
        }


def parse_packet(pkt) -> Optional[ParsedPacket]:
    """
    Convierte un paquete Scapy en un ParsedPacket estructurado.
    Devuelve None si el paquete no tiene capa reconocible.
    """
    global _counter
    _counter += 1

    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    length = len(pkt)
    src_ip = dst_ip = "N/A"
    src_port = dst_port = None
    protocol = "Unknown"
    flags = ""
    info = ""

    # Bug fix #2: todo el parsing envuelto en try-except para que un paquete
    # malformado no crashee el loop entero.
    try:
        # ── ARP ───────────────────────────────────────────────────────────────
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            protocol = "ARP"
            src_ip, dst_ip = arp.psrc, arp.pdst
            if arp.op == 1:
                info = f"Who has {arp.pdst}? Tell {arp.psrc}"
            else:
                info = f"{arp.psrc} is at {arp.hwsrc}"

        # ── IPv6 ──────────────────────────────────────────────────────────────
        elif pkt.haslayer(IPv6):
            ipv6 = pkt[IPv6]
            src_ip, dst_ip = str(ipv6.src), str(ipv6.dst)
            protocol = "IPv6"
            info = f"{src_ip} → {dst_ip}"

        # ── IP ────────────────────────────────────────────────────────────────
        elif pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip, dst_ip = ip.src, ip.dst

            if pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                protocol = "ICMP"
                info = _ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")

            elif pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port, dst_port = tcp.sport, tcp.dport
                # Bug fix #3: en Scapy 2.5+, tcp.flags es un objeto FlagValue,
                # no un int. Forzar la conversión a int antes de las operaciones
                # bit a bit para garantizar compatibilidad.
                flags = _parse_tcp_flags(int(tcp.flags))
                protocol, info = _classify_tcp(tcp, pkt, flags)

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port, dst_port = udp.sport, udp.dport
                protocol, info = _classify_udp(udp, pkt)

            else:
                protocol = "IP"
                info = f"proto={ip.proto}"

        else:
            return None

    except Exception:
        # Paquete malformado o capa desconocida: ignorar sin crashear
        return None

    return ParsedPacket(
        id=_counter, timestamp=ts, protocol=protocol,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        length=length, flags=flags, info=info,
        raw_packet=pkt,
    )


def _parse_tcp_flags(raw_flags: int) -> str:
    """Convierte el int de flags TCP a string (e.g., 'SYN ACK')."""
    bits = [
        ("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
        ("PSH", 0x08), ("ACK", 0x10), ("URG", 0x20),
    ]
    return " ".join(name for name, bit in bits if raw_flags & bit)


def _classify_tcp(tcp, pkt, flags: str):
    sport, dport = tcp.sport, tcp.dport
    # Bug fix #4: variable 'port' estaba definida pero nunca usada. Eliminada.
    protocol = _TCP_PORT_PROTOCOLS.get(dport) or _TCP_PORT_PROTOCOLS.get(sport) or "TCP"

    if protocol == "HTTP" and pkt.haslayer(Raw):
        try:
            raw = pkt[Raw].load.decode("utf-8", errors="ignore")
            first_line = raw.split("\r\n")[0]
            return protocol, first_line[:100] if first_line else f"[{flags}] {sport}→{dport}"
        except Exception:
            pass

    return protocol, f"[{flags}] {sport} → {dport}"


def _classify_udp(udp, pkt):
    sport, dport = udp.sport, udp.dport

    if pkt.haslayer(DNS):
        try:
            dns = pkt[DNS]
            protocol = "DNS"
            if dns.qr == 0 and dns.qd:
                # Bug fix #5: en algunas versiones de Scapy, qname ya es str;
                # en otras es bytes. Verificar el tipo antes de decodificar.
                qname = dns.qd.qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="ignore")
                return protocol, f"Query {qname.rstrip('.')}"
            elif dns.qr == 1:
                if dns.an and hasattr(dns.an, "rdata"):
                    return protocol, f"Answer {dns.an.rdata}"
                return protocol, "Response"
        except Exception:
            return "DNS", "DNS"

    protocol = _UDP_PORT_PROTOCOLS.get(dport) or _UDP_PORT_PROTOCOLS.get(sport) or "UDP"
    return protocol, f"{sport} → {dport} len={udp.len}"


def reset_counter() -> None:
    global _counter
    _counter = 0
