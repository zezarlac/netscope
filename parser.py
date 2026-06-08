"""
netscope/parser.py — Parseo de protocolos (Fase 2)

Convierte paquetes crudos de Scapy en objetos ParsedPacket legibles,
detectando hasta capa de aplicación (HTTP, DNS, SSH, etc.).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from scapy.all import ARP, ICMP, IP, UDP, TCP, Ether, Raw
from scapy.layers.dns import DNS

try:
    from scapy.layers.inet6 import IPv6
    HAS_IPV6 = True
except ImportError:
    HAS_IPV6 = False


# ── Puertos TCP conocidos ──────────────────────────────────────────────────────
_TCP_PORT_PROTOCOLS: dict[int, str] = {
    20: "FTP-DATA",  21: "FTP",       22: "SSH",     23: "TELNET",
    25: "SMTP",      53: "DNS/TCP",   80: "HTTP",    110: "POP3",
    143: "IMAP",    443: "HTTPS/TLS", 445: "SMB",    465: "SMTPS",
    587: "SMTP",    993: "IMAPS",    995: "POP3S",   3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
    3389: "RDP",   5900: "VNC",     8080: "HTTP",   8443: "HTTPS/TLS",
}

# ── Puertos UDP conocidos ──────────────────────────────────────────────────────
_UDP_PORT_PROTOCOLS: dict[int, str] = {
    53: "DNS",    67: "DHCP",   68: "DHCP",
    123: "NTP",  161: "SNMP",  514: "Syslog",
    1194: "OpenVPN", 4500: "IPSec",
}

# ── Tipos de ICMP ─────────────────────────────────────────────────────────────
_ICMP_TYPES: dict[int, str] = {
    0: "Echo Reply",   3: "Unreachable",   5: "Redirect",
    8: "Echo Request", 11: "Time Exceeded", 12: "Parameter Problem",
}

# Contador global de paquetes para el campo `id`
_counter: int = 0


# ──────────────────────────────────────────────────────────────────────────────
# Dataclass de resultado
# ──────────────────────────────────────────────────────────────────────────────

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
            "id": self.id,
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "length": self.length,
            "flags": self.flags,
            "info": self.info,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Función principal de parseo
# ──────────────────────────────────────────────────────────────────────────────

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

    # ── ARP ───────────────────────────────────────────────────────────────────
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        protocol = "ARP"
        src_ip, dst_ip = arp.psrc, arp.pdst
        if arp.op == 1:
            info = f"Who has {arp.pdst}? Tell {arp.psrc}"
        else:
            info = f"{arp.psrc} is at {arp.hwsrc}"

    # ── IPv6 ──────────────────────────────────────────────────────────────────
    elif HAS_IPV6 and pkt.haslayer(IPv6):
        ipv6 = pkt[IPv6]
        src_ip, dst_ip = ipv6.src, ipv6.dst
        protocol = "IPv6"
        info = f"{src_ip} → {dst_ip}"

    # ── IP ────────────────────────────────────────────────────────────────────
    elif pkt.haslayer(IP):
        ip = pkt[IP]
        src_ip, dst_ip = ip.src, ip.dst

        # ICMP
        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            protocol = "ICMP"
            icmp_name = _ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
            info = f"{icmp_name} (code={icmp.code})"

        # TCP
        elif pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port, dst_port = tcp.sport, tcp.dport
            flags = _parse_tcp_flags(tcp.flags)
            protocol, info = _classify_tcp(tcp, pkt, flags)

        # UDP
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port, dst_port = udp.sport, udp.dport
            protocol, info = _classify_udp(udp, pkt)

        else:
            protocol = "IP"
            info = f"proto={ip.proto}"

    # ── Sin capa reconocida (e.g., solo Ethernet) ─────────────────────────────
    else:
        return None

    return ParsedPacket(
        id=_counter,
        timestamp=ts,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        flags=flags,
        info=info,
        raw_packet=pkt,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Helpers internos
# ──────────────────────────────────────────────────────────────────────────────

def _parse_tcp_flags(raw_flags: int) -> str:
    """Convierte el entero de flags TCP a string legible (e.g., 'SYN ACK')."""
    bits = [
        ("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
        ("PSH", 0x08), ("ACK", 0x10), ("URG", 0x20),
    ]
    return " ".join(name for name, bit in bits if raw_flags & bit)


def _classify_tcp(tcp, pkt, flags: str) -> tuple[str, str]:
    """Devuelve (protocol, info) para un segmento TCP."""
    sport, dport = tcp.sport, tcp.dport
    port = min(sport, dport)

    protocol = _TCP_PORT_PROTOCOLS.get(dport) or _TCP_PORT_PROTOCOLS.get(sport) or "TCP"

    # Intenta extraer la primera línea HTTP si hay payload
    if protocol == "HTTP" and pkt.haslayer(Raw):
        try:
            raw = pkt[Raw].load.decode("utf-8", errors="ignore")
            first_line = raw.split("\r\n")[0]
            info = first_line[:100] if first_line else f"[{flags}] {sport}→{dport}"
            return protocol, info
        except Exception:
            pass

    info = f"[{flags}] {sport} → {dport}"
    return protocol, info


def _classify_udp(udp, pkt) -> tuple[str, str]:
    """Devuelve (protocol, info) para un datagrama UDP."""
    sport, dport = udp.sport, udp.dport

    # DNS
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        protocol = "DNS"
        try:
            if dns.qr == 0 and dns.qd:                        # Query
                name = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                return protocol, f"Query {name}"
            elif dns.qr == 1:                                  # Response
                if dns.an and hasattr(dns.an, "rdata"):
                    return protocol, f"Answer {dns.an.rdata}"
                return protocol, "Response (no answer)"
        except Exception:
            pass
        return protocol, "DNS"

    # Otros por puerto conocido
    protocol = _UDP_PORT_PROTOCOLS.get(dport) or _UDP_PORT_PROTOCOLS.get(sport) or "UDP"
    info = f"{sport} → {dport} len={udp.len}"
    return protocol, info


def reset_counter() -> None:
    """Reinicia el contador de paquetes (útil entre capturas)."""
    global _counter
    _counter = 0
