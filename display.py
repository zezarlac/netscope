"""
netscope/display.py — Dashboard TUI en tiempo real (Fase 4)

Controles:  q=salir  p=pausar  c=limpiar  s=guardar CSV
"""

import os
import sys
import time
import datetime
import threading
from collections import deque
from typing import Optional

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .parser import ParsedPacket, parse_packet
from .stats import StatsCollector

PROTO_COLORS: dict = {
    "HTTP": "bright_green", "HTTPS/TLS": "green", "DNS": "cyan",
    "DNS/TCP": "cyan", "TCP": "blue", "UDP": "yellow", "ICMP": "magenta",
    "ARP": "bright_yellow", "SSH": "bright_blue", "FTP": "orange3",
    "FTP-DATA": "orange3", "DHCP": "purple", "NTP": "dim cyan",
    "IPv6": "bright_cyan", "SMTP": "bright_magenta", "SMTPS": "bright_magenta",
    "POP3": "magenta", "POP3S": "magenta", "IMAP": "magenta",
    "IMAPS": "magenta", "MySQL": "bright_red", "PostgreSQL": "bright_red",
    "Redis": "red", "MongoDB": "green", "SMB": "orange4",
    "RDP": "bright_white", "VNC": "white", "TELNET": "red",
    "SNMP": "dim yellow", "Syslog": "dim white", "OpenVPN": "dark_green",
}


class Dashboard:
    MAX_VISIBLE_ROWS = 50

    def __init__(self, stats: StatsCollector, max_packets: int = 1000, no_color: bool = False):
        self.stats = stats
        self.no_color = no_color
        self.packets: deque = deque(maxlen=max_packets)
        self.filter_text: str = ""
        self.paused: bool = False
        self.running: bool = False
        self._lock = threading.Lock()
        self.console = Console(highlight=False, no_color=no_color)
        # Sistema de notificaciones: mensajes temporales en pantalla
        self._notify_msg: str = ""
        self._notify_time: float = 0.0
        self._notify_error: bool = False

    # ------------------------------------------------------------------
    # Teclado
    # ------------------------------------------------------------------

    def _keyboard_loop(self) -> None:
        """
        Hilo daemon de lectura de teclado.

        Bug fix #9: readchar llama a tty.setraw() en cada tecla y luego restaura
        el modo. Esto puede interferir con Rich.Live. Se usan dos estrategias:
          1. Primero se intenta con readchar (la más cómoda).
          2. Si falla, se usa un fallback manual con tty.setraw() / select.
        En ambos casos, Ctrl+C (\x03) se captura explícitamente para poder salir
        aunque el terminal esté en raw mode.
        """
        try:
            self._keyboard_with_readchar()
        except Exception:
            try:
                self._keyboard_fallback()
            except Exception:
                pass  # Sin teclado interactivo; Ctrl-C sigue funcionando

    def _keyboard_with_readchar(self) -> None:
        import readchar
        while self.running:
            key = readchar.readchar()
            self._handle_key(key)
            if not self.running:
                break

    def _keyboard_fallback(self) -> None:
        """Fallback para sistemas donde readchar no está disponible."""
        if os.name == "nt":
            # Windows: usar msvcrt
            import msvcrt
            while self.running:
                if msvcrt.kbhit():
                    key = msvcrt.getch().decode("utf-8", errors="ignore")
                    self._handle_key(key)
                else:
                    import time; time.sleep(0.05)
        else:
            # Unix: setraw manual + select no-bloqueante
            import tty, termios, select
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                while self.running:
                    if select.select([sys.stdin], [], [], 0.1)[0]:
                        key = sys.stdin.read(1)
                        self._handle_key(key)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)

    def _handle_key(self, key: str) -> None:
        if key in ("\x03", "q", "Q"):   # \x03 = Ctrl+C en raw mode
            self.running = False
        elif key in ("p", "P"):
            self.paused = not self.paused
            if self.paused:
                self._notify("⏸  Captura PAUSADA — pulsa P para reanudar", error=False)
            else:
                self._notify("▶  Captura REANUDADA", error=False)
        elif key in ("c", "C"):
            with self._lock:
                self.packets.clear()
            self.stats.reset()
            self._notify("🗑  Lista y estadísticas limpiadas", error=False)
        elif key in ("s", "S"):
            self._quick_save()

    def _notify(self, msg: str, error: bool = False) -> None:
        """Muestra un mensaje temporal en la barra de estado (dura 4 segundos)."""
        self._notify_msg = msg
        self._notify_time = time.time()
        self._notify_error = error

    def _quick_save(self) -> None:
        from .exporter import Exporter
        with self._lock:
            pkts = list(self.packets)
        # Guardar en el directorio actual con timestamp para no sobrescribir
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(os.getcwd(), f"netscope_{ts}.csv")
        try:
            Exporter().to_csv(pkts, path)
            self._notify(f"💾  Guardado: {path}  ({len(pkts)} paquetes)", error=False)
        except Exception as e:
            self._notify(f"❌  Error al guardar: {e}", error=True)

    # ------------------------------------------------------------------
    # Renderizado
    # ------------------------------------------------------------------

    def _color(self, protocol: str) -> str:
        return "white" if self.no_color else PROTO_COLORS.get(protocol, "white")

    def _build_packet_table(self) -> Table:
        table = Table(
            box=box.SIMPLE_HEAD, show_header=True,
            header_style="bold white on grey23", padding=(0, 1), expand=True,
        )
        table.add_column("#",       width=6,  justify="right", style="dim")
        table.add_column("Hora",    width=13)
        table.add_column("Proto",   width=11, justify="center")
        table.add_column("Origen",  width=22)
        table.add_column("Destino", width=22)
        table.add_column("Bytes",   width=7,  justify="right")
        table.add_column("Info",    no_wrap=True)

        with self._lock:
            all_pkts = list(self.packets)

        if self.filter_text:
            f = self.filter_text.lower()
            all_pkts = [
                p for p in all_pkts
                if f in p.protocol.lower() or f in p.src_ip.lower()
                or f in p.dst_ip.lower() or f in p.info.lower()
                or (p.src_port and f in str(p.src_port))
                or (p.dst_port and f in str(p.dst_port))
            ]

        for pkt in all_pkts[-self.MAX_VISIBLE_ROWS:]:
            color = self._color(pkt.protocol)
            src = pkt.src_ip + (f":{pkt.src_port}" if pkt.src_port else "")
            dst = pkt.dst_ip + (f":{pkt.dst_port}" if pkt.dst_port else "")
            flags_str = f" [{pkt.flags}]" if pkt.flags else ""
            table.add_row(
                str(pkt.id), pkt.timestamp,
                Text(pkt.protocol, style=f"bold {color}"),
                Text(src, style="bright_white"),
                Text(dst, style="white"),
                str(pkt.length),
                Text(pkt.info + flags_str, style="dim white"),
            )
        return table

    def _build_stats_bar(self) -> Panel:
        s = self.stats

        # ── Línea 1: métricas ─────────────────────────────────────────────────
        status = Text()
        status.append("📦 ", style="dim")
        status.append(f"{s.total_packets:,}", style="bold bright_white")
        status.append(" pkt  │  ⚡ ", style="dim")
        status.append(f"{s.packets_per_second:.1f} pkt/s", style="bold yellow")
        status.append("  │  💾 ", style="dim")
        status.append(s.format_bytes(s.total_bytes), style="bold cyan")
        status.append("  │  🔗 ", style="dim")
        status.append(f"{s.unique_connections} conn", style="bold green")
        status.append("  │  ⏱ ", style="dim")
        status.append(f"{s.elapsed:.0f}s", style="white")
        if self.filter_text:
            status.append(f"  │  🔍 {self.filter_text}", style="bold magenta")

        # ── Línea 2: distribución de protocolos ───────────────────────────────
        proto_line = Text()
        for proto, count in s.top_protocols(6):
            c = self._color(proto)
            proto_line.append(f" {proto}", style=f"bold {c}")
            proto_line.append(f"({count})", style="dim")

        # ── Línea 3 (opcional): notificación temporal ─────────────────────────
        notif_active = self._notify_msg and (time.time() - self._notify_time) < 4.0
        if notif_active:
            color = "bold red" if self._notify_error else "bold bright_green"
            notif_line = Text(f" {self._notify_msg}", style=color)
            content = Text.assemble(status, "\n", proto_line, "\n", notif_line)
        else:
            content = Text.assemble(status, "\n", proto_line)

        # ── Panel: borde rojo y título diferente cuando está en pausa ─────────
        if self.paused:
            title    = "[bold red]⏸  PAUSADO[/bold red]  —  [bold cyan]NetScope[/bold cyan]"
            border   = "red"
            subtitle = "[dim]P=reanudar  q=salir  c=limpiar  s=guardar[/dim]"
        else:
            title    = "[bold cyan]🔍 NetScope — Analizador de tráfico[/bold cyan]"
            border   = "cyan"
            subtitle = "[dim]q=salir  p=pausar  c=limpiar  s=guardar[/dim]"

        return Panel(
            content,
            title=title, title_align="left",
            subtitle=subtitle, subtitle_align="right",
            border_style=border,
        )

    def _render(self) -> Layout:
        # El panel crece una línea cuando hay notificación activa
        notif_active = self._notify_msg and (time.time() - self._notify_time) < 4.0
        header_size = 6 if notif_active else 5
        layout = Layout()
        layout.split_column(
            Layout(self._build_stats_bar(),    name="header", size=header_size),
            Layout(self._build_packet_table(), name="body"),
        )
        return layout

    # ------------------------------------------------------------------
    # Loop principal
    # ------------------------------------------------------------------

    def run(self, sniffer, packet_limit: int = 0) -> None:
        self.running = True

        kb_thread = threading.Thread(target=self._keyboard_loop, daemon=True)
        kb_thread.start()

        captured = 0
        try:
            with Live(
                self._render(),
                console=self.console,
                refresh_per_second=10,
                screen=True,
            ) as live:
                while self.running:
                    raw = sniffer.get_packet(timeout=0.05)
                    if raw is not None and not self.paused:
                        parsed = parse_packet(raw)
                        if parsed:
                            with self._lock:
                                self.packets.append(parsed)
                            self.stats.update(parsed)
                            captured += 1
                            if packet_limit and captured >= packet_limit:
                                self.running = False
                                break
                    live.update(self._render())
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False

    def get_packets(self) -> list:
        with self._lock:
            return list(self.packets)
