NetScope — Analizador de Tráfico de Red

Herramienta CLI para capturar y analizar tráfico de red en tiempo real,
inspirada en Wireshark pero con una interfaz mucho más amigable.

---

## Características

- **Captura en vivo** 
- **Detección de protocolos**: ARP, ICMP, TCP, UDP, DNS, HTTP, HTTPS/TLS, SSH, FTP, DHCP, NTP y más
- **Dashboard TUI** con Rich: tabla de paquetes, colores por protocolo, estadísticas en tiempo real
- **Controles de teclado**: pausar, filtrar, guardar snapshot
- **Exportar** a CSV o JSON
- **Analizar** archivos PCAP existentes
- **Resumen final** con distribución de protocolos y top IPs

---

## Instalación

```bash
git clone https://github.com/zezarlac/netscope.git
cd netscope-analyzer
pip install -r requirements.txt
```

### Dependencias

| Paquete    | Uso                              |
|------------|----------------------------------|
| `scapy`    | Captura y parseo de paquetes     |
| `rich`     | Interfaz TUI en terminal         |
| `click`    | CLI                              |
| `readchar` | Atajos de teclado interactivos   |

---

## Uso

### Captura en vivo (requiere sudo/admin)

```bash
# Captura básica en la interfaz por defecto
sudo python main.py capture

# En una interfaz específica
sudo python main.py capture -i eth0

# Solo tráfico HTTP
sudo python main.py capture -p tcp --filter "port 80"

# Capturar 200 paquetes y guardar en JSON
sudo python main.py capture -c 200 -o captura.json -F json

# Filtrar por IP
sudo python main.py capture --filter "host 192.168.1.100"
```

### Listar interfaces disponibles

```bash
python main.py interfaces
```

### Analizar un archivo PCAP

```bash
python main.py analyze captura.pcap
python main.py analyze captura.pcap -o resultado.csv
```

---

## Controles durante la captura

| Tecla | Acción                       |
|-------|------------------------------|
| `q`   | Salir                        |
| `p`   | Pausar / Reanudar            |
| `c`   | Limpiar lista de paquetes    |
| `s`   | Guardar snapshot CSV         |

---

## Estructura del proyecto

```
netscope-analyzer/
├── main.py              # Punto de entrada (CLI con Click)
├── requirements.txt
├── ROADMAP.md
└── netscope/
    ├── __init__.py
    ├── sniffer.py       # Motor de captura (AsyncSniffer)
    ├── parser.py        # Parseo de protocolos
    ├── stats.py         # Estadísticas en tiempo real
    ├── display.py       # Dashboard TUI (Rich.Live)
    └── exporter.py      # Exportación CSV / JSON
```

---

## Protocolos soportados

| Capa        | Protocolos detectados                                              |
|-------------|--------------------------------------------------------------------|
| Enlace      | Ethernet, ARP                                                      |
| Red         | IP, IPv6, ICMP                                                     |
| Transporte  | TCP (con flags), UDP                                               |
| Aplicación  | HTTP, HTTPS/TLS, SSH, FTP, DNS, DHCP, NTP, SMTP, POP3, IMAP, RDP, MySQL, Redis, MongoDB… |


---

## Notas legales

Esta herramienta es para uso educativo y en redes propias o con autorización explícita.
Capturar tráfico en redes ajenas sin permiso es ilegal.
