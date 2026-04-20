# NetSpy — Network Packet Sniffer

A Python-based CLI packet sniffer for educational purposes, built with Scapy.

---

## ⚠️ Legal & Ethical Notice
**Only use on networks you own or have explicit permission to monitor.**  
Unauthorized packet sniffing may violate local laws and regulations.

---

## Features

| Feature | Details |
|---|---|
| Live capture | Captures packets in real time via Scapy |
| Protocol filter | Filter by TCP / UDP / ICMP |
| IP filter | Filter by source or destination IP |
| Payload display | Optional ASCII payload view (`--payload`) |
| Suspicious detection | Flags unusual ports, port scans, ICMP floods |
| Color-coded output | TCP=green, UDP=cyan, ICMP=yellow, alerts=red |
| Live statistics | Real-time packet count, rate, protocol breakdown |
| Save capture | Export to `.txt` (human-readable) or `.pcap` (Wireshark) |
| Stop controls | Ctrl+C, `--count N`, `--timeout N` |

---

## Installation

```bash
pip install scapy colorama
```

On Linux/macOS, `scapy` requires root:
```bash
sudo pip install scapy colorama
```

---

## Usage

```bash
sudo python sniffer.py [OPTIONS]
```

### Options

| Flag | Description |
|---|---|
| `-i / --iface` | Network interface (e.g. `eth0`, `wlan0`) |
| `-p / --proto` | Protocol filter: `tcp`, `udp`, `icmp` |
| `--ip <addr>` | Filter by IP address (src or dst) |
| `-c / --count N` | Stop after N packets |
| `-t / --timeout N` | Stop after N seconds |
| `--payload` | Show payload data |
| `--save FILE` | Save to `.txt` or `.pcap` |
| `-q / --quiet` | Show stats only, suppress per-packet output |

---

## Examples

```bash
# Capture all packets on default interface
sudo python sniffer.py

# Capture only TCP on eth0
sudo python sniffer.py -p tcp -i eth0

# Watch traffic to/from a specific host, show payloads
sudo python sniffer.py --ip 192.168.1.100 --payload

# Capture 50 packets and save as Wireshark file
sudo python sniffer.py -c 50 --save capture.pcap

# Monitor UDP for 30 seconds, save text report
sudo python sniffer.py -p udp --timeout 30 --save report.txt
```

---

## Suspicious Packet Detection

NetSpy automatically flags:

- **Suspicious ports** — Known malware/backdoor ports (1337, 4444, 31337, etc.)
- **Port scan detection** — >20 SYN packets from the same IP in 10 seconds
- **ICMP flood** — >15 ICMP packets from the same IP in 5 seconds
- **Large payload on uncommon port** — potential data exfiltration indicator

Suspicious packets are highlighted in **red** with a `⚠ SUSPICIOUS` badge.

---

## Output Format

```
──────────────────────────────────────────────────────────────────────
#12    14:33:07.421
 TCP   192.168.1.5:54321  →  :80  (HTTP)
  ↓  93.184.216.34  94B
  ↳  GET / HTTP/1.1\r\nHost: example.com...
──────────────────────────────────────────────────────────────────────
```

Live stats bar (bottom of terminal):
```
pkts: 47 | TCP: 31 | UDP: 12 | ICMP: 4 | ⚠ 1 | 3.2 pkt/s
```

---

## Architecture

```
sniffer.py
├── Colors          — Terminal color abstractions (colorama wrapper)
├── Stats           — Thread-safe packet statistics tracker
├── PacketSniffer   — Core engine
│   ├── _passes_filter()    — BPF + Python-level filtering
│   ├── _is_suspicious()    — Heuristic threat detection
│   ├── _handle_packet()    — Scapy callback
│   ├── _format_packet()    — Human-readable display
│   └── _save_packets()     — txt / pcap export
└── main()          — CLI entry point (argparse)
```

---

## Tech Stack
- **Python 3.8+**
- **Scapy** — packet capture & parsing
- **colorama** — cross-platform terminal colors

---

*Built for learning — not for harm.*

👨‍💻 Author

Aditya Udugade.

---

## 📬 Connect With Me

LinkedIn: www.linkedin.com/in/aditya-udugade-28147b345 

GitHub: https://github.com/adiiitya01  


---
