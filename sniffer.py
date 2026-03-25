#!/usr/bin/env python3
"""
NetSpy - Network Packet Sniffer
Educational tool for packet analysis and network monitoring.
Use only on networks you own or have explicit permission to monitor.
"""

import argparse
import sys
import os
import signal
import threading
import time
import json
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap, rdpcap
    from scapy.layers.dns import DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# ─── Color helpers ───────────────────────────────────────────────────────────

class Colors:
    if COLORAMA_AVAILABLE:
        RED     = Fore.RED
        GREEN   = Fore.GREEN
        YELLOW  = Fore.YELLOW
        CYAN    = Fore.CYAN
        MAGENTA = Fore.MAGENTA
        BLUE    = Fore.BLUE
        WHITE   = Fore.WHITE
        BRIGHT  = Style.BRIGHT
        DIM     = Style.DIM
        RESET   = Style.RESET_ALL
    else:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ""
        BRIGHT = DIM = RESET = ""

def colored(text, *codes):
    return "".join(codes) + text + Colors.RESET

# ─── Suspicious port detection ────────────────────────────────────────────────

SUSPICIOUS_PORTS = {
    # Known malware / C2
    1337, 31337, 4444, 6666, 6667, 6668, 6669,
    # Common scan targets
    23, 135, 137, 138, 139, 445, 3389,
    # Backdoor-associated
    2222, 5554, 9999, 12345, 54321,
}

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 25: "SMTP",
    53: "DNS",  80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 465: "SMTPS", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
}

# ─── Statistics tracker ───────────────────────────────────────────────────────

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.by_proto = defaultdict(int)
        self.by_src   = defaultdict(int)
        self.by_dst   = defaultdict(int)
        self.suspicious = 0
        self.start_time = time.time()
        self.bytes_total = 0

    def record(self, proto, src, dst, size, suspicious=False):
        with self.lock:
            self.total += 1
            self.by_proto[proto] += 1
            self.by_src[src] += 1
            self.by_dst[dst] += 1
            self.bytes_total += size
            if suspicious:
                self.suspicious += 1

    def elapsed(self):
        return time.time() - self.start_time

    def pps(self):
        e = self.elapsed()
        return self.total / e if e > 0 else 0

    def summary(self):
        lines = [
            "",
            colored("╔══════════════════════════════════════╗", Colors.CYAN, Colors.BRIGHT),
            colored("║        CAPTURE SESSION SUMMARY        ║", Colors.CYAN, Colors.BRIGHT),
            colored("╚══════════════════════════════════════╝", Colors.CYAN, Colors.BRIGHT),
            f"  Duration    : {self.elapsed():.1f}s",
            f"  Total pkts  : {colored(str(self.total), Colors.GREEN, Colors.BRIGHT)}",
            f"  Suspicious  : {colored(str(self.suspicious), Colors.RED, Colors.BRIGHT)}",
            f"  Bytes seen  : {self._human_bytes(self.bytes_total)}",
            f"  Avg pkt/s   : {self.pps():.1f}",
            "",
            colored("  Protocol Breakdown:", Colors.YELLOW),
        ]
        for proto, count in sorted(self.by_proto.items(), key=lambda x: -x[1]):
            bar = "█" * min(count, 30)
            lines.append(f"    {proto:<8} {bar} {count}")

        lines.append("")
        lines.append(colored("  Top Source IPs:", Colors.YELLOW))
        for ip, count in sorted(self.by_src.items(), key=lambda x: -x[1])[:5]:
            lines.append(f"    {ip:<20} {count} packets")

        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _human_bytes(n):
        for unit in ["B", "KB", "MB", "GB"]:
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"


# ─── Sniffer core ─────────────────────────────────────────────────────────────

class PacketSniffer:
    def __init__(self, args):
        self.args = args
        self.stats = Stats()
        self.running = False
        self.packet_buffer = []
        self.lock = threading.Lock()
        self.packet_count = 0
        self._last_src_time = defaultdict(list)   # for repeat-request detection

    # ── Filtering ──────────────────────────────────────────────────────────

    def _passes_filter(self, pkt):
        if not pkt.haslayer(IP):
            return False

        proto = self._get_proto(pkt)

        if self.args.proto and proto.lower() != self.args.proto.lower():
            return False

        if self.args.ip:
            src = pkt[IP].src
            dst = pkt[IP].dst
            if self.args.ip not in (src, dst):
                return False

        return True

    # ── Protocol helpers ───────────────────────────────────────────────────

    @staticmethod
    def _get_proto(pkt):
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        return "OTHER"

    @staticmethod
    def _get_ports(pkt):
        if pkt.haslayer(TCP):
            return pkt[TCP].sport, pkt[TCP].dport
        if pkt.haslayer(UDP):
            return pkt[UDP].sport, pkt[UDP].dport
        return None, None

    @staticmethod
    def _get_flags(pkt):
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            flag_str = ""
            if flags & 0x02: flag_str += "SYN "
            if flags & 0x10: flag_str += "ACK "
            if flags & 0x01: flag_str += "FIN "
            if flags & 0x04: flag_str += "RST "
            if flags & 0x08: flag_str += "PSH "
            if flags & 0x20: flag_str += "URG "
            return flag_str.strip()
        return ""

    @staticmethod
    def _get_payload(pkt):
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)
            # Try printable ASCII
            try:
                text = raw.decode("utf-8", errors="replace")
                text = "".join(c if 32 <= ord(c) < 127 else "." for c in text)
                return text[:120]
            except Exception:
                return raw[:60].hex()
        return None

    # ── Suspicious detection ───────────────────────────────────────────────

    def _is_suspicious(self, pkt):
        reasons = []
        sport, dport = self._get_ports(pkt)

        if sport in SUSPICIOUS_PORTS or dport in SUSPICIOUS_PORTS:
            reasons.append(f"suspicious port ({sport or dport})")

        # Repeated SYN packets from same source (basic port scan detection)
        if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:
            src = pkt[IP].src
            now = time.time()
            times = self._last_src_time[src]
            times.append(now)
            # Keep only last 10 seconds
            self._last_src_time[src] = [t for t in times if now - t < 10]
            if len(self._last_src_time[src]) > 20:
                reasons.append("possible port scan (>20 SYNs in 10s)")

        # Large payload on uncommon port
        if pkt.haslayer(Raw) and len(pkt[Raw].load) > 1400:
            if dport and dport not in WELL_KNOWN_PORTS:
                reasons.append("large payload on uncommon port")

        # ICMP flood
        if pkt.haslayer(ICMP):
            src = pkt[IP].src
            now = time.time()
            times = self._last_src_time[f"icmp_{src}"]
            times.append(now)
            self._last_src_time[f"icmp_{src}"] = [t for t in times if now - t < 5]
            if len(self._last_src_time[f"icmp_{src}"]) > 15:
                reasons.append("ICMP flood")

        return reasons

    # ── Display ────────────────────────────────────────────────────────────

    def _proto_color(self, proto):
        return {
            "TCP":   Colors.GREEN,
            "UDP":   Colors.CYAN,
            "ICMP":  Colors.YELLOW,
            "OTHER": Colors.WHITE,
        }.get(proto, Colors.WHITE)

    def _format_packet(self, pkt, suspicious_reasons):
        proto   = self._get_proto(pkt)
        src_ip  = pkt[IP].src
        dst_ip  = pkt[IP].dst
        sport, dport = self._get_ports(pkt)
        flags   = self._get_flags(pkt)
        payload = self._get_payload(pkt)
        size    = len(pkt)
        ts      = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        pc      = self.packet_count

        proto_c = self._proto_color(proto)
        sus     = bool(suspicious_reasons)

        # Header line
        port_info = f":{sport} → :{dport}" if sport else ""
        flag_info = f"  [{flags}]" if flags else ""
        service   = WELL_KNOWN_PORTS.get(dport, "") or WELL_KNOWN_PORTS.get(sport, "")
        svc_info  = f"  ({service})" if service else ""

        lines = []
        sep = colored("─" * 70, Colors.DIM)
        lines.append(sep)

        # Packet number + timestamp
        num_ts = colored(f"#{pc:<5}", Colors.DIM) + "  " + colored(ts, Colors.DIM)
        lines.append(num_ts)

        # Core info
        proto_tag = colored(f" {proto} ", proto_c, Colors.BRIGHT)
        if sus:
            alert = colored(" ⚠ SUSPICIOUS ", Colors.RED, Colors.BRIGHT)
        else:
            alert = ""

        core = (
            proto_tag + alert + "  " +
            colored(src_ip, Colors.WHITE, Colors.BRIGHT) +
            colored(port_info, Colors.DIM) +
            colored(flag_info, Colors.YELLOW) +
            colored(svc_info, Colors.CYAN)
        )
        lines.append(core)

        # Arrow + destination
        lines.append(
            colored("  ↓ ", Colors.DIM) +
            colored(dst_ip, Colors.WHITE) +
            colored(f"  {size}B", Colors.DIM)
        )

        # Suspicious reasons
        for r in suspicious_reasons:
            lines.append(colored(f"  ⚠  {r}", Colors.RED))

        # Payload
        if payload and self.args.payload:
            trunc = payload[:100] + ("…" if len(payload) > 100 else "")
            lines.append(colored(f"  ↳ {trunc}", Colors.DIM))

        return "\n".join(lines)

    def _print_live_stats(self):
        stats = self.stats
        bar = (
            colored(f" pkts: {stats.total} ", Colors.BRIGHT) +
            colored(f"| TCP: {stats.by_proto['TCP']} ", Colors.GREEN) +
            colored(f"| UDP: {stats.by_proto['UDP']} ", Colors.CYAN) +
            colored(f"| ICMP: {stats.by_proto['ICMP']} ", Colors.YELLOW) +
            colored(f"| ⚠ {stats.suspicious} ", Colors.RED) +
            colored(f"| {stats.pps():.1f} pkt/s", Colors.DIM)
        )
        print(f"\r{bar}    ", end="", flush=True)

    # ── Packet callback ────────────────────────────────────────────────────

    def _handle_packet(self, pkt):
        if not self.running:
            return

        if not self._passes_filter(pkt):
            return

        self.packet_count += 1
        proto   = self._get_proto(pkt)
        src_ip  = pkt[IP].src
        dst_ip  = pkt[IP].dst
        size    = len(pkt)
        sus     = self._is_suspicious(pkt)
        is_sus  = bool(sus)

        self.stats.record(proto, src_ip, dst_ip, size, is_sus)

        # Buffer for saving
        if self.args.save:
            with self.lock:
                self.packet_buffer.append(pkt)

        # Print live stats line (overwrite) then packet below
        if not self.args.quiet:
            print()  # newline before packet block
            print(self._format_packet(pkt, sus))
            self._print_live_stats()

        # Limit
        if self.args.count and self.packet_count >= self.args.count:
            self.stop()

    # ── Save helpers ───────────────────────────────────────────────────────

    def _save_packets(self):
        if not self.packet_buffer:
            return

        fn = self.args.save
        if fn.endswith(".pcap"):
            wrpcap(fn, self.packet_buffer)
            print(colored(f"\n  Saved {len(self.packet_buffer)} packets → {fn}", Colors.GREEN))
        else:
            # Text format
            if not fn.endswith(".txt"):
                fn += ".txt"
            with open(fn, "w") as f:
                f.write(f"NetSpy Capture  |  {datetime.now()}\n")
                f.write("=" * 70 + "\n\n")
                for p in self.packet_buffer:
                    if p.haslayer(IP):
                        proto = self._get_proto(p)
                        sport, dport = self._get_ports(p)
                        port_info = f":{sport}→:{dport}" if sport else ""
                        f.write(
                            f"{proto:<6} {p[IP].src}{port_info}  →  {p[IP].dst}  "
                            f"[{len(p)}B]\n"
                        )
            print(colored(f"\n  Saved {len(self.packet_buffer)} packets → {fn}", Colors.GREEN))

    # ── Start / Stop ───────────────────────────────────────────────────────

    def _configure_windows_l3(self):
        """
        Force Scapy to use Windows L3 raw sockets (no Npcap needed).
        Probes several attribute names that differ across Scapy versions.
        """
        try:
            import scapy.arch.windows as _win
            from scapy.all import conf

            socket_cls = None
            for name in ("WindowsL3Socket", "L3socket", "L3RawSocket"):
                socket_cls = getattr(_win, name, None)
                if socket_cls:
                    break

            if socket_cls:
                conf.L3socket  = socket_cls
                conf.L3socket6 = socket_cls
            else:
                conf.use_pcap = False

            print(colored(
                "[*] Windows L3 socket mode active — Npcap not required.\n"
                "    BPF filters disabled; Python-level filtering in use.",
                Colors.YELLOW
            ))
            return True
        except Exception as e:
            print(colored(f"[!] L3 socket config warning: {e}", Colors.YELLOW))
            return False

    def _sniff_raw_windows(self):
        """
        Pure-Python raw socket sniffer for Windows.
        Used when Scapy layer-2 and layer-3 both fail.
        """
        import socket as _socket

        print(colored(
            "[*] Using raw socket fallback (IP-level capture).\n"
            "    Must be run as Administrator.",
            Colors.YELLOW
        ))

        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_IP)
            s.bind((_socket.gethostbyname(_socket.gethostname()), 0))
            s.setsockopt(_socket.IPPROTO_IP, _socket.IP_HDRINCL, 1)
            s.ioctl(_socket.SIO_RCVALL, _socket.RCVALL_ON)
        except PermissionError:
            print(colored(
                "\n[!] Permission denied — please re-run PowerShell as Administrator.",
                Colors.RED, Colors.BRIGHT
            ))
            sys.exit(1)
        except OSError as e:
            print(colored(f"\n[!] Raw socket error: {e}", Colors.RED))
            sys.exit(1)

        print(colored("[*] Raw socket sniffer started. Press Ctrl+C to stop.\n", Colors.GREEN))

        try:
            while self.running:
                try:
                    s.settimeout(1.0)
                    data, _ = s.recvfrom(65535)
                except _socket.timeout:
                    continue
                try:
                    from scapy.all import IP as ScapyIP
                    pkt = ScapyIP(data)
                    self._handle_packet(pkt)
                except Exception:
                    pass
        finally:
            try:
                s.ioctl(_socket.SIO_RCVALL, _socket.RCVALL_OFF)
            except Exception:
                pass
            s.close()

    def start(self):
        self.running = True
        is_windows = sys.platform == "win32"

        # Pre-configure L3 sockets on Windows
        if is_windows:
            self._configure_windows_l3()

        self._print_banner()

        # BPF filters only work on Linux/macOS with Npcap
        bpf = ""
        if not is_windows:
            if self.args.proto:
                bpf = self.args.proto.lower()
            if self.args.ip:
                ip_filter = f"host {self.args.ip}"
                bpf = f"{bpf} and {ip_filter}" if bpf else ip_filter

        try:
            sniff(
                iface=self.args.iface or None,
                filter=bpf or None,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self.running,
                timeout=self.args.timeout or None,
            )
        except PermissionError:
            print(colored(
                "\n[!] Permission denied.\n"
                "    Windows : Run PowerShell / CMD as Administrator\n"
                "    Linux   : Use  sudo python sniffer.py",
                Colors.RED, Colors.BRIGHT
            ))
            sys.exit(1)
        except RuntimeError as e:
            err = str(e).lower()
            if any(kw in err for kw in ("winpcap", "npcap", "layer 2", "layer2")):
                print(colored(
                    "\n[!] Scapy layer-2/3 unavailable — switching to raw socket fallback…",
                    Colors.YELLOW
                ))
                self._sniff_raw_windows()
            else:
                print(colored(f"\n[!] Runtime error: {e}", Colors.RED))
                sys.exit(1)
        except OSError as e:
            print(colored(f"\n[!] Interface error: {e}", Colors.RED))
            sys.exit(1)

        self._finish()

    def stop(self):
        self.running = False

    def _finish(self):
        print()
        if self.args.save:
            self._save_packets()
        print(self.stats.summary())

    # ── Banner ─────────────────────────────────────────────────────────────

    def _print_banner(self):
        banner = f"""
{colored('╔══════════════════════════════════════════════════════╗', Colors.CYAN, Colors.BRIGHT)}
{colored('║', Colors.CYAN, Colors.BRIGHT)}  {colored('NetSpy', Colors.GREEN, Colors.BRIGHT)} — Network Packet Sniffer                    {colored('║', Colors.CYAN, Colors.BRIGHT)}
{colored('║', Colors.CYAN, Colors.BRIGHT)}  {colored('For educational and ethical use only', Colors.YELLOW)}                {colored('║', Colors.CYAN, Colors.BRIGHT)}
{colored('╚══════════════════════════════════════════════════════╝', Colors.CYAN, Colors.BRIGHT)}
  Interface : {colored(self.args.iface or 'default', Colors.WHITE, Colors.BRIGHT)}
  Filter    : proto={colored(self.args.proto or 'all', Colors.WHITE, Colors.BRIGHT)}  ip={colored(self.args.ip or 'any', Colors.WHITE, Colors.BRIGHT)}
  Save to   : {colored(self.args.save or 'none', Colors.WHITE, Colors.BRIGHT)}
  Payload   : {colored('shown' if self.args.payload else 'hidden', Colors.WHITE, Colors.BRIGHT)}
  Press {colored('Ctrl+C', Colors.YELLOW)} to stop.
"""
        print(banner)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="netspy",
        description="NetSpy — Educational Network Packet Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python sniffer.py
  sudo python sniffer.py -p tcp -i eth0
  sudo python sniffer.py --ip 192.168.1.1 --payload
  sudo python sniffer.py -c 50 --save capture.pcap
  sudo python sniffer.py -p udp --timeout 30 --save dump.txt
        """
    )
    p.add_argument("-i", "--iface",   help="Network interface (e.g. eth0, wlan0)")
    p.add_argument("-p", "--proto",   choices=["tcp", "udp", "icmp"], help="Filter by protocol")
    p.add_argument("--ip",            help="Filter by IP address (src or dst)")
    p.add_argument("-c", "--count",   type=int, help="Stop after N packets")
    p.add_argument("-t", "--timeout", type=int, help="Stop after N seconds")
    p.add_argument("--payload",       action="store_true", help="Display payload data")
    p.add_argument("--save",          metavar="FILE", help="Save to file (.txt or .pcap)")
    p.add_argument("-q", "--quiet",   action="store_true", help="Suppress per-packet output (stats only)")
    return p


def check_dependencies():
    if not SCAPY_AVAILABLE:
        print(colored(
            "[!] Scapy is not installed.\n    Run:  pip install scapy",
            Colors.RED if COLORAMA_AVAILABLE else "", Colors.BRIGHT if COLORAMA_AVAILABLE else ""
        ))
        sys.exit(1)
    if not COLORAMA_AVAILABLE:
        print("[!] colorama not installed — output will be uncolored.\n    Run: pip install colorama\n")


def main():
    check_dependencies()
    parser = build_parser()
    args = parser.parse_args()

    sniffer = PacketSniffer(args)

    def _sigint(sig, frame):
        print(colored("\n\n[*] Stopping capture…", Colors.YELLOW))
        sniffer.stop()

    signal.signal(signal.SIGINT, _sigint)
    sniffer.start()


if __name__ == "__main__":
    main()
