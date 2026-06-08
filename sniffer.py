"""
netscope/sniffer.py — Motor de captura de paquetes (Fase 1)

Usa AsyncSniffer de Scapy para no bloquear el hilo principal.
Los paquetes se envían a una Queue thread-safe.
"""

import queue
from typing import Optional

from scapy.all import AsyncSniffer, conf, get_if_list, get_if_addr


def list_interfaces() -> list[tuple[str, str]]:
    """Devuelve lista de (interfaz, IP) disponibles en el sistema."""
    result = []
    for iface in get_if_list():
        try:
            addr = get_if_addr(iface)
        except Exception:
            addr = "N/A"
        result.append((iface, addr))
    return result


def get_default_interface() -> Optional[str]:
    """Devuelve la interfaz activa por defecto de Scapy."""
    try:
        return conf.iface
    except Exception:
        return None


class NetworkSniffer:
    """
    Envuelve AsyncSniffer de Scapy para captura no-bloqueante.

    Uso:
        sniffer = NetworkSniffer(interface="eth0", bpf_filter="tcp port 80")
        sniffer.start()
        while sniffer.is_running():
            pkt = sniffer.get_packet(timeout=0.1)
            ...
        sniffer.stop()
    """

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

        # Contadores para diagnóstico
        self.total_captured: int = 0
        self.total_dropped: int = 0

    # ------------------------------------------------------------------
    # Control
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Inicia la captura en un hilo de fondo."""
        kwargs: dict = {"prn": self._on_packet, "store": False}
        if self.interface:
            kwargs["iface"] = self.interface
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()
        self.running = True

    def stop(self) -> None:
        """Detiene la captura limpiamente."""
        if self._sniffer and self.running:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        self.running = False

    def is_running(self) -> bool:
        return self.running

    # ------------------------------------------------------------------
    # Consumo de paquetes
    # ------------------------------------------------------------------

    def get_packet(self, timeout: float = 0.1):
        """
        Obtiene el siguiente paquete de la cola.
        Devuelve None si no hay paquetes en `timeout` segundos.
        """
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    # ------------------------------------------------------------------
    # Callback interno
    # ------------------------------------------------------------------

    def _on_packet(self, pkt) -> None:
        """Llamado por Scapy en el hilo de captura."""
        self.total_captured += 1
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            self.total_dropped += 1
