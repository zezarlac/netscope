#!/usr/bin/env python3
"""
main.py — Punto de entrada CLI de NetScope
"""

import os
import sys

# ── Fix de path robusto ────────────────────────────────────────────────────────
# Con `sudo python main.py`, __file__ puede resolverse contra el CWD de root
# en vez del CWD real, dando una ruta incorrecta. En vez de confiar en un solo
# mecanismo, probamos tres estrategias y usamos la primera que contenga la
# carpeta 'netscope/'. Si ninguna la encuentra, salimos con un mensaje claro.
def _setup_path() -> None:
    candidates = [
        # 1. Directorio del script según __file__ (falla si sudo cambia el CWD)
        os.path.dirname(os.path.abspath(__file__)),
        # 2. Directorio del argumento invocado (sys.argv[0] → 'main.py' o ruta completa)
        os.path.dirname(os.path.abspath(sys.argv[0])) if sys.argv else "",
        # 3. Directorio de trabajo actual (funciona si se ejecuta desde la raíz)
        os.getcwd(),
    ]

    for path in candidates:
        if path and os.path.isdir(os.path.join(path, "netscope")):
            if path not in sys.path:
                sys.path.insert(0, path)
            return   # encontrado ✓

    # Ninguna estrategia funcionó → la carpeta netscope/ no existe donde se espera
    expected = candidates[0]
    print(
        f"\n❌  No se encontró el paquete 'netscope/' en ninguna ruta buscada.\n"
        f"    Ruta esperada: {expected}/netscope/\n\n"
        f"    La estructura del proyecto debe ser:\n"
        f"      {expected}/\n"
        f"      ├── main.py\n"
        f"      └── netscope/\n"
        f"          ├── __init__.py\n"
        f"          ├── sniffer.py\n"
        f"          ├── parser.py\n"
        f"          ├── stats.py\n"
        f"          ├── display.py\n"
        f"          └── exporter.py\n",
        file=sys.stderr,
    )
    sys.exit(1)

_setup_path()

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
# Pre-flight: verificar dependencias antes de ejecutar nada
# ──────────────────────────────────────────────────────────────────────────────

def check_dependencies() -> bool:
    """
    Verifica que las dependencias críticas estén disponibles para el Python
    actual. Esto es especialmente importante con sudo, donde el PATH y el
    entorno pueden diferir del usuario normal.
    """
    missing = []
    for pkg, import_name in [
        ("scapy",    "scapy.all"),
        ("rich",     "rich"),
        ("click",    "click"),
    ]:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pkg)

    if missing:
        console.print(f"\n[red]❌ Paquetes no encontrados: {', '.join(missing)}[/red]")
        console.print(
            "\n[yellow]Esto suele pasar al usar [bold]sudo[/bold] porque sudo usa un "
            "Python diferente al del usuario.\n"
            "Soluciones (elige una):\n\n"
            "  [bold]1. Instalar para el Python de sistema:[/bold]\n"
            "     sudo pip3 install scapy rich click readchar --break-system-packages\n\n"
            "  [bold]2. Usar el mismo Python que tiene los paquetes:[/bold]\n"
            "     sudo $(which python3) main.py interfaces\n\n"
            "  [bold]3. Usar un entorno virtual:[/bold]\n"
            "     python3 -m venv venv && source venv/bin/activate\n"
            "     pip install -r requirements.txt\n"
            "     sudo venv/bin/python3 main.py capture[/yellow]\n"
        )
        return False
    return True


def check_root() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def abort_no_root() -> None:
    console.print("[red]❌ Se necesitan permisos de root para capturar paquetes.[/red]")
    console.print("[yellow]Usa: [bold]sudo python3 main.py capture[/bold][/yellow]")
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """🔍 NetScope — Analizador de tráfico de red amigable."""
    pass


# ── capture ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--interface", "-i",  default=None,
              help="Interfaz de red (ej: eth0, wlan0).")
@click.option("--filter",    "-f",  "bpf_filter", default="",
              help="Filtro BPF (ej: 'tcp port 80', 'host 192.168.1.1').")
@click.option("--count",     "-c",  default=0, type=int,
              help="Límite de paquetes (0 = ilimitado).")
@click.option("--output",    "-o",  default=None,
              help="Guardar captura en archivo al salir.")
@click.option("--format",    "-F",  "fmt", default="csv",
              type=click.Choice(["csv", "json"], case_sensitive=False),
              help="Formato del archivo de salida.")
@click.option("--protocol",  "-p",  default=None,
              type=click.Choice(["tcp", "udp", "icmp", "arp", "dns"],
                                case_sensitive=False),
              help="Filtrar por protocolo.")
@click.option("--no-color",        is_flag=True, default=False,
              help="Desactivar colores.")
def capture(interface, bpf_filter, count, output, fmt, protocol, no_color):
    """🚀 Captura tráfico de red en tiempo real."""

    if not check_dependencies():
        sys.exit(1)

    if not check_root():
        abort_no_root()

    from netscope.sniffer import NetworkSniffer
    from netscope.display import Dashboard
    from netscope.stats import StatsCollector

    if protocol and not bpf_filter:
        bpf_filter = protocol.lower()

    console.print(BANNER)
    console.print(Panel.fit(
        f"Interfaz: [green]{interface or 'auto'}[/green]  │  "
        f"Filtro: [yellow]{bpf_filter or 'ninguno'}[/yellow]  │  "
        f"Límite: [magenta]{count if count else '∞'} paquetes[/magenta]\n"
        f"[dim]q=salir  p=pausar  c=limpiar  s=guardar snapshot  Ctrl-C=salir[/dim]",
        border_style="cyan",
    ))

    stats   = StatsCollector()
    sniffer = NetworkSniffer(interface=interface, bpf_filter=bpf_filter)
    dash    = Dashboard(stats=stats, max_packets=1000, no_color=no_color)

    # Iniciar captura con mensaje claro si falla
    try:
        sniffer.start()
    except RuntimeError as e:
        console.print(f"\n[red]❌ {e}[/red]")
        sys.exit(1)

    try:
        dash.run(sniffer=sniffer, packet_limit=count)
    finally:
        sniffer.stop()

    if output:
        from netscope.exporter import Exporter
        pkts = dash.get_packets()
        saved = Exporter().export(pkts, output, fmt)
        console.print(f"\n[green]✅ {len(pkts)} paquetes guardados en '{saved}'[/green]")

    console.print()
    stats.print_summary(console)


# ── interfaces ────────────────────────────────────────────────────────────────

@cli.command()
def interfaces():
    """📋 Lista las interfaces de red disponibles."""

    if not check_dependencies():
        sys.exit(1)

    from netscope.sniffer import list_interfaces

    ifaces = list_interfaces()
    if not ifaces:
        console.print("[yellow]No se encontraron interfaces de red.[/yellow]")
        return

    table = Table(
        title="Interfaces de red disponibles",
        box=box.ROUNDED, show_header=True, header_style="bold cyan",
    )
    table.add_column("#",        style="dim", width=4)
    table.add_column("Interfaz", style="bold")
    table.add_column("IP",       style="green")

    for i, (name, ip) in enumerate(ifaces, 1):
        table.add_row(str(i), name, ip)

    console.print(table)
    console.print(f"\n[dim]Usa [bold]-i <interfaz>[/bold] con el comando capture.[/dim]")


# ── analyze ───────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Exportar análisis.")
@click.option("--format", "-F", "fmt", default="csv",
              type=click.Choice(["csv", "json"], case_sensitive=False))
def analyze(pcap_file, output, fmt):
    """📂 Analiza un archivo PCAP guardado."""

    if not check_dependencies():
        sys.exit(1)

    from scapy.all import rdpcap
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

    from netscope.parser import parse_packet, reset_counter
    from netscope.stats  import StatsCollector

    reset_counter()
    console.print(f"[cyan]Cargando [bold]{pcap_file}[/bold]...[/cyan]")

    try:
        raw_packets = rdpcap(pcap_file)
    except Exception as e:
        console.print(f"[red]Error al leer el archivo: {e}[/red]")
        sys.exit(1)

    stats  = StatsCollector()
    parsed = []

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TextColumn("{task.completed}/{task.total}"),
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
        from netscope.exporter import Exporter
        saved = Exporter().export(parsed, output, fmt)
        console.print(f"\n[green]Exportado a '{saved}'[/green]")


if __name__ == "__main__":
    cli()
