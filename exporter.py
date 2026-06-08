"""
netscope/exporter.py — Exportación de datos (Fase 5)

Soporta CSV y JSON. Acepta lista de ParsedPacket.
"""

import csv
import json
from pathlib import Path
from typing import List

from .parser import ParsedPacket


class Exporter:

    def export(self, packets: List[ParsedPacket], filepath: str, fmt: str = "csv") -> Path:
        """Exporta `packets` al archivo indicado. Devuelve la ruta final."""
        if fmt == "csv":
            return self.to_csv(packets, filepath)
        elif fmt == "json":
            return self.to_json(packets, filepath)
        raise ValueError(f"Formato desconocido: {fmt!r}. Usa 'csv' o 'json'.")

    # ------------------------------------------------------------------

    def to_csv(self, packets: List[ParsedPacket], filepath: str) -> Path:
        path = _ensure_ext(filepath, ".csv")
        fields = ["id", "timestamp", "protocol", "src_ip", "src_port",
                  "dst_ip", "dst_port", "length", "flags", "info"]

        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for p in packets:
                writer.writerow({
                    "id":        p.id,
                    "timestamp": p.timestamp,
                    "protocol":  p.protocol,
                    "src_ip":    p.src_ip,
                    "src_port":  p.src_port or "",
                    "dst_ip":    p.dst_ip,
                    "dst_port":  p.dst_port or "",
                    "length":    p.length,
                    "flags":     p.flags,
                    "info":      p.info,
                })
        return path

    def to_json(self, packets: List[ParsedPacket], filepath: str) -> Path:
        path = _ensure_ext(filepath, ".json")
        data = [
            {
                "id":          p.id,
                "timestamp":   p.timestamp,
                "protocol":    p.protocol,
                "source":      {"ip": p.src_ip, "port": p.src_port},
                "destination": {"ip": p.dst_ip, "port": p.dst_port},
                "length":      p.length,
                "flags":       p.flags,
                "info":        p.info,
            }
            for p in packets
        ]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        return path


def _ensure_ext(filepath: str, ext: str) -> Path:
    path = Path(filepath)
    if path.suffix.lower() != ext:
        path = path.with_suffix(ext)
    return path
