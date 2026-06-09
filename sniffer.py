"""
netscope/sniffer.py — Motor de captura de paquetes (Fase 1)
"""

import queue
from typing import Optional

from scapy.all import AsyncSniffer, conf, get_if_list, get_if_addr


def list_interfaces() -> list:
    """Devuelve lista de (nombre, IP) para cada interfaz del sistema."""
    result = []
    for iface in get_if_list():
        try:
            addr = get_if_addr(str(iface))
            # Filtrar IPs vacías o 0.0.0.0 que no aportan información
            if not addr or addr == "0.0.0.0":
                addr = "sin IP"
        except Exception:
            addr = "N/A"
        result.append((str(iface), addr))
    return result


def get_default_interface() -> Optional[str]:
    """Devuelve la interfaz activa por defecto como string.

    Bug fix #6: En Scapy 2.5+, conf.iface devuelve un objeto NetworkInterface,
    no un str. Sin str() esto causaba errores al pasarlo a AsyncSniffer y al
    mostrarlo en pantalla.
    """
    try:
        iface = conf.iface
        return str(iface) if iface else None
    except Exception:
        return None


class NetworkSniffer:
    """Envuelve AsyncSniffer de Scapy para captura no-bloqueante."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "",
        max_queue_size: int = 10_000,
    ):
        self.interface = interface or get_default_interface()
        self.bpf_filter = bpf_filter
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._sniffer: Optional[AsyncSniffer] = None
        self.running: bool = False
        self.total_captured: int = 0
        self.total_dropped: int = 0

    def start(self) -> None:
        """Inicia la captura. Lanza RuntimeError con mensaje claro si falla."""
        kwargs: dict = {"prn": self._on_packet, "store": False}
        if self.interface:
            kwargs["iface"] = self.interface
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter

        # Bug fix #7: AsyncSniffer.start() no estaba envuelto en try-except.
        # Si la interfaz no existe o faltan permisos, el error original de Scapy
        # es críptico. Ahora se relanza con un mensaje de diagnóstico claro.
        try:
            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            self.running = True
        except PermissionError:
            raise RuntimeError(
                "Permiso denegado al abrir el socket de captura.\n"
                "Ejecuta el comando con sudo:\n"
                "  sudo python3 main.py capture"
            )
        except Exception as e:
            iface_name = self.interface or "auto"
            raise RuntimeError(
                f"No se pudo iniciar la captura en la interfaz '{iface_name}'.\n"
                f"Comprueba: (1) que la interfaz existe  (2) que libpcap está instalado  "
                f"(3) que tienes permisos de root.\n"
                f"Error original: {e}\n"
                f"Interfaces disponibles: {[i for i, _ in list_interfaces()]}"
            )

    def stop(self) -> None:
        if self._sniffer and self.running:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        self.running = False

    def is_running(self) -> bool:
        return self.running

    def get_packet(self, timeout: float = 0.1):
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def _on_packet(self, pkt) -> None:
        self.total_captured += 1
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            self.total_dropped += 1
