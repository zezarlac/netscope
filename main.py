#!/usr/bin/env python3
"""
main.py — Punto de entrada CLI de NetScope (Fase 5)

Comandos disponibles:
  netscope capture     Captura tráfico en tiempo real
  netscope interfaces  Lista interfaces disponibles
  netscope analyze     Analiza un archivo PCAP existente

Requiere privilegios de root/administrador para captura en vivo.
"""

import os
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

BANNER = """[bold cyan]
 _   _      _   ____
| \\ | | ___| |_/ ___|  ___ ___  _ __   ___
|  \\| |/ _ \\ __\\___ \\ / __/ _ \\| '_ \\ / _ \\
| |\\  |  __/ |_ ___) | (_| (_) | |_) |  __/
|_| \\_|\\___|\\__|____/ \\___\\___/| .__/ \\___|
                                |_|
[/bold cyan][dim]User-friendly Network Traffic Analyzer[/dim]"""


# ──────────────────────────────────────────────────────────────────────────────
# Utilidades
# ──────────────────────────────────────────────────────────────────────────────

def _check_root() -> bool:
    """Comprueba si el proceso tiene permisos de captura."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _abort_no_root() -> None:
    console.print("[red]❌ Se requieren permisos de root/administrador para capturar paquetes.[/red]")
    console.print("[yellow]Usa: [bold]sudo python main.py capture[/bold][/yellow]")
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# Grupo principal
# ──────────────────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """🔍 NetScope — Analizador de tráfico de red amigable."""
    pass


# ──────────────────────────────────────────────────────────────────────────────
# Comando: capture
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--interface", "-i",  default=None,
              help="Interfaz de red (ej: eth0, wlan0). Auto-detecta si se omite.")
@click.option("--filter",    "-f",  "bpf_filter", default="",
              help="Filtro BPF (ej: 'tcp port 80', 'host 192.168.1.1')")
@click.option("--count",     "-c",  default=0, type=int,
              help="Límite de paquetes (0 = ilimitado)")
@click.option("--output",    "-o",  default=None,
              help="Guardar captura en archivo al salir")
@click.option("--format",    "-F",  "fmt", default="csv",
              type=click.Choice(["csv", "json"], case_sensitive=False),
              help="Formato del archivo de salida")
@click.option("--protocol",  "-p",  default=None,
              type=click.Choice(["tcp","udp","icmp","arp","dns"],
                                case_sensitive=False),
              help="Filtrar por protocolo (atajo de BPF)")
@click.option("--no-color",        is_flag=True, default=False,
              help="Desactivar colores (modo accesible)")
def capture(interface, bpf_filter, count, output, fmt, protocol, no_color):
    """🚀 Captura tráfico de red en tiempo real."""

    if not _check_root():
        _abort_no_root()

    from netscope.sniffer import NetworkSniffer
    from netscope.display import Dashboard
    from netscope.stats import StatsCollector

    # Si se usa --protocol sin --filter, construye el filtro
    if protocol and not bpf_filter:
        bpf_filter = protocol.lower()

    # Mostrar cabecera
    console.print(BANNER)
    console.print(Panel.fit(
        f"Interfaz: [green]{interface or 'auto'}[/green]  │  "
        f"Filtro: [yellow]{bpf_filter or 'ninguno'}[/yellow]  │  "
        f"Límite: [magenta]{count if count else '∞'} paquetes[/magenta]\n"
        f"[dim]Presiona [bold]q[/bold] para salir, "
        f"[bold]p[/bold] pausar, [bold]c[/bold] limpiar, "
        f"[bold]s[/bold] guardar snapshot[/dim]",
        border_style="cyan",
    ))

    # Inicializar componentes
    stats   = StatsCollector()
    sniffer = NetworkSniffer(interface=interface, bpf_filter=bpf_filter)
    dash    = Dashboard(stats=stats, max_packets=1000, no_color=no_color)

    # Capturar
    sniffer.start()
    try:
        dash.run(sniffer=sniffer, packet_limit=count)
    finally:
        sniffer.stop()

    # Exportar si se pidió
    if output:
        from netscope.exporter import Exporter
        pkts = dash.get_packets()
        saved = Exporter().export(pkts, output, fmt)
        console.print(f"\n[green]✅ {len(pkts)} paquetes guardados en '{saved}'[/green]")

    # Resumen final
    console.print()
    stats.print_summary(console)


# ──────────────────────────────────────────────────────────────────────────────
# Comando: interfaces
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
def interfaces():
    """📋 Lista las interfaces de red disponibles."""
    from netscope.sniffer import list_interfaces

    ifaces = list_interfaces()
    table = Table(
        title="Interfaces de red disponibles",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#",          style="dim", width=4)
    table.add_column("Interfaz",   style="bold")
    table.add_column("IP",         style="green")

    for i, (name, ip) in enumerate(ifaces, 1):
        table.add_row(str(i), name, ip)

    console.print(table)
    console.print(f"\n[dim]Usa [bold]-i <interfaz>[/bold] en el comando capture[/dim]")


# ──────────────────────────────────────────────────────────────────────────────
# Comando: analyze (lee un PCAP guardado)
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--output", "-o", default=None,
              help="Exportar análisis a archivo")
@click.option("--format", "-F", "fmt", default="csv",
              type=click.Choice(["csv", "json"], case_sensitive=False))
def analyze(pcap_file, output, fmt):
    """📂 Analiza un archivo PCAP existente."""
    from scapy.all import rdpcap
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

    from netscope.parser import parse_packet, reset_counter
    from netscope.stats  import StatsCollector
    from netscope.exporter import Exporter

    reset_counter()
    console.print(f"[cyan]Cargando [bold]{pcap_file}[/bold]...[/cyan]")

    try:
        raw_packets = rdpcap(pcap_file)
    except Exception as e:
        console.print(f"[red]Error al leer el archivo: {e}[/red]")
        sys.exit(1)

    stats   = StatsCollector()
    parsed  = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analizando paquetes...", total=len(raw_packets))
        for pkt in raw_packets:
            p = parse_packet(pkt)
            if p:
                parsed.append(p)
                stats.update(p)
            progress.advance(task)

    console.print(f"[green]✅ {len(parsed)}/{len(raw_packets)} paquetes procesados[/green]\n")
    stats.print_summary(console)

    if output:
        saved = Exporter().export(parsed, output, fmt)
        console.print(f"\n[green]Exportado a '{saved}'[/green]")


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
