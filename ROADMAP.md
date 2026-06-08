# NetScope — Pauta de Desarrollo

## Fase 1 — Núcleo de Captura
- [x] 1.1 Clase `NetworkSniffer` con `AsyncSniffer` de Scapy (no bloquea el hilo principal)
- [x] 1.2 Cola thread-safe para comunicar paquetes entre hilos
- [x] 1.3 Detección automática de interfaz activa
- [x] 1.4 Soporte de filtros BPF por línea de comandos

## Fase 2 — Parseo de Protocolos
- [x] 2.1 Ethernet / ARP
- [x] 2.2 IP / IPv6 / ICMP
- [x] 2.3 TCP — detección de flags (SYN, ACK, FIN, RST…)
- [x] 2.4 UDP — DNS, DHCP, NTP
- [x] 2.5 Capa de aplicación — HTTP (Puerto 80), HTTPS/TLS (443), SSH (22)
- [x] 2.6 Identificación de puertos conocidos (MySQL, Redis, FTP, SMTP, RDP…)

## Fase 3 — Estadísticas
- [x] 3.1 Contador global (paquetes, bytes, velocidad)
- [x] 3.2 Distribución por protocolo
- [x] 3.3 Top IPs origen y destino
- [x] 3.4 Puertos más activos
- [x] 3.5 Seguimiento de conexiones (src_ip, dst_ip, proto)

## Fase 4 — Interfaz TUI (Rich)
- [x] 4.1 Dashboard en vivo con `Rich.Live`
- [x] 4.2 Tabla de paquetes con colores por protocolo
- [x] 4.3 Panel de estadísticas en tiempo real
- [x] 4.4 Filtro interactivo (por protocolo, IP o texto libre)
- [x] 4.5 Atajos de teclado: q=salir, p=pausar, c=limpiar, s=guardar
- [x] 4.6 Soporte de alto contraste / sin colores

## Fase 5 — CLI y Exportación
- [x] 5.1 CLI con Click: `capture`, `interfaces`, `analyze`
- [x] 5.2 Exportar a CSV
- [x] 5.3 Exportar a JSON
- [x] 5.4 Leer y analizar archivos PCAP existentes
- [x] 5.5 Resumen final al salir

## Fase 6 — Mejoras futuras (opcionales)
- [ ] 6.1 Interfaz web con Flask + WebSocket
- [ ] 6.2 Gráficas de tráfico en tiempo real (Plotext)
- [ ] 6.3 Detección de anomalías (port scan, ARP spoofing)
- [ ] 6.4 Modo de seguimiento de conexiones TCP (stream reassembly)
- [ ] 6.5 Soporte de captura remota (SSH tunnel)
