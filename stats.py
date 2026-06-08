"""
netscope/stats.py — Estadísticas en tiempo real (Fase 3)

Acumula métricas de los paquetes capturados:
  - Totales (paquetes, bytes, velocidad)
  - Distribución de protocolos
  - Top IPs y puertos
  - Seguimiento de conexiones
"""

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from .parser import ParsedPacket


@dataclass
class StatsCollector:
    """
    Acumula estadísticas de paquetes.
    Thread-safe si se usa desde un solo escritor.
    """

    # Contadores globales
    total_packets: int = 0
    total_bytes: int = 0

    # Distribución
    protocol_counts: Counter = field(default_factory=Counter)
    src_ip_counts: Counter = field(default_factory=Counter)
    dst_ip_counts: Counter = field(default_factory=Counter)
    dst_port_counts: Counter = field(default_factory=Counter)

    # Conexiones únicas: (src_ip, dst_ip, proto) → nro. paquetes
    connections: dict = field(default_factory=dict)

    # Tiempo
    _start_time: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Ingestión
    # ------------------------------------------------------------------

    def update(self, pkt: ParsedPacket) -> None:
        """Registra un nuevo paquete en las estadísticas."""
        self.total_packets += 1
        self.total_bytes += pkt.length
        self.protocol_counts[pkt.protocol] += 1

        if pkt.src_ip not in ("N/A", ""):
            self.src_ip_counts[pkt.src_ip] += 1
        if pkt.dst_ip not in ("N/A", ""):
            self.dst_ip_counts[pkt.dst_ip] += 1
        if pkt.dst_port:
            self.dst_port_counts[pkt.dst_port] += 1

        key = (pkt.src_ip, pkt.dst_ip, pkt.protocol)
        self.connections[key] = self.connections.get(key, 0) + 1

    def reset(self) -> None:
        """Reinicia todas las estadísticas."""
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts.clear()
        self.src_ip_counts.clear()
        self.dst_ip_counts.clear()
        self.dst_port_counts.clear()
        self.connections.clear()
        self._start_time = time.time()

    # ------------------------------------------------------------------
    # Propiedades derivadas
    # ------------------------------------------------------------------

    @property
    def elapsed(self) -> float:
        return time.time() - self._start_time

    @property
    def packets_per_second(self) -> float:
        e = self.elapsed
        return self.total_packets / e if e > 0 else 0.0

    @property
    def bytes_per_second(self) -> float:
        e = self.elapsed
        return self.total_bytes / e if e > 0 else 0.0

    @property
    def unique_connections(self) -> int:
        return len(self.connections)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def top_protocols(self, n: int = 8) -> list[tuple[str, int]]:
        return self.protocol_counts.most_common(n)

    def top_src_ips(self, n: int = 5) -> list[tuple[str, int]]:
        return self.src_ip_counts.most_common(n)

    def top_dst_ips(self, n: int = 5) -> list[tuple[str, int]]:
        return self.dst_ip_counts.most_common(n)

    def top_ports(self, n: int = 5) -> list[tuple[int, int]]:
        return self.dst_port_counts.most_common(n)

    @staticmethod
    def format_bytes(b: int) -> str:
        """Convierte bytes a string legible (B/KB/MB/GB)."""
        for unit in ("B", "KB", "MB", "GB"):
            if b < 1024:
                return f"{b:.1f} {unit}"
            b //= 1024
        return f"{b:.1f} TB"

    # ------------------------------------------------------------------
    # Reporte final
    # ------------------------------------------------------------------

    def print_summary(self, console) -> None:
        """Imprime un resumen final en consola usando Rich."""
        from rich.table import Table
        from rich.panel import Panel
        from rich.columns import Columns
        from rich import box

        # ── Resumen general ───────────────────────────────────────────
        duration_str = f"{self.elapsed:.1f}s"
        summary = (
            f"[bold]Duración:[/bold] {duration_str}  │  "
            f"[bold]Paquetes:[/bold] {self.total_packets:,}  │  "
            f"[bold]Datos:[/bold] {self.format_bytes(self.total_bytes)}  │  "
            f"[bold]Velocidad:[/bold] {self.packets_per_second:.1f} pkt/s  │  "
            f"[bold]Conexiones únicas:[/bold] {self.unique_connections}"
        )
        console.print(Panel(summary, title="[green]Resumen de captura[/green]", border_style="green"))

        # ── Tabla de protocolos ───────────────────────────────────────
        proto_table = Table(title="Protocolos", box=box.ROUNDED, show_footer=False)
        proto_table.add_column("Protocolo", style="bold")
        proto_table.add_column("Paquetes", justify="right")
        proto_table.add_column("% del total", justify="right")
        for proto, count in self.top_protocols(10):
            pct = 100 * count / max(self.total_packets, 1)
            proto_table.add_row(proto, f"{count:,}", f"{pct:.1f}%")

        # ── Top IPs ───────────────────────────────────────────────────
        ip_table = Table(title="Top IPs Origen", box=box.ROUNDED)
        ip_table.add_column("IP", style="bold cyan")
        ip_table.add_column("Paquetes", justify="right")
        for ip, count in self.top_src_ips(5):
            ip_table.add_row(ip, f"{count:,}")

        # ── Top puertos ───────────────────────────────────────────────
        port_table = Table(title="Top Puertos Destino", box=box.ROUNDED)
        port_table.add_column("Puerto", style="bold yellow", justify="right")
        port_table.add_column("Paquetes", justify="right")
        for port, count in self.top_ports(5):
            port_table.add_row(str(port), f"{count:,}")

        console.print(Columns([proto_table, ip_table, port_table]))
