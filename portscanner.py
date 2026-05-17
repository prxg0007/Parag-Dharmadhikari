#!/usr/bin/env python3
"""
portscanner.py — Real-time multithreaded port scanner
Usage: python portscanner.py <target> [options]
"""

import socket
import threading
import argparse
import sys
import time
import queue
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ──────────────────────────────────────────────
# Known service names
# ──────────────────────────────────────────────
SERVICES = {
    20: "FTP-Data",    21: "FTP",         22: "SSH",
    23: "Telnet",      25: "SMTP",        53: "DNS",
    67: "DHCP",        68: "DHCP",        69: "TFTP",
    80: "HTTP",       110: "POP3",       111: "RPC",
    123: "NTP",       135: "MSRPC",      137: "NetBIOS",
    139: "NetBIOS",   143: "IMAP",       161: "SNMP",
    389: "LDAP",      443: "HTTPS",      445: "SMB",
    465: "SMTPS",     514: "Syslog",     587: "SMTP-Sub",
    636: "LDAPS",     993: "IMAPS",      995: "POP3S",
    1080: "SOCKS",   1433: "MSSQL",     1521: "Oracle",
    1723: "PPTP",    2049: "NFS",       2375: "Docker",
    2376: "Docker-TLS", 3000: "Dev",    3306: "MySQL",
    3389: "RDP",     4000: "Dev",       5000: "Flask/UPnP",
    5432: "PostgreSQL", 5900: "VNC",    5985: "WinRM",
    6379: "Redis",   6443: "Kubernetes", 7000: "Cassandra",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9090: "Prometheus", 9092: "Kafka",  9200: "Elasticsearch",
    10250: "Kubelet", 11211: "Memcached", 27017: "MongoDB",
    50070: "HDFS",
}

# ──────────────────────────────────────────────
# ANSI color codes
# ──────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    DIM    = "\033[2m"
    BLUE   = "\033[94m"

def colored(text, color):
    return f"{color}{text}{C.RESET}"

# ──────────────────────────────────────────────
# Port parsing
# ──────────────────────────────────────────────
def parse_ports(port_str):
    """Parse port string like '1-1024' or '80,443,8080' into a list."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            n = int(part)
            if 1 <= n <= 65535:
                ports.add(n)
    return sorted(ports)

# ──────────────────────────────────────────────
# Banner grabber
# ──────────────────────────────────────────────
def grab_banner(host, port, timeout=2.0):
    """Attempt to grab a service banner from an open port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Send HTTP GET for web ports
            if port in (80, 8080, 8000, 8008, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            data = s.recv(256)
            return data.decode(errors="replace").strip().split("\n")[0][:80]
    except Exception:
        return ""

# ──────────────────────────────────────────────
# TCP scan
# ──────────────────────────────────────────────
def scan_tcp(host, port, timeout=1.0, grab=False):
    """
    Attempt a TCP connection. Returns:
        ('open',     service, banner)
        ('filtered', service, '')
        ('closed',   service, '')
    """
    svc = SERVICES.get(port, "unknown")
    try:
        with socket.create_connection((host, port), timeout=timeout):
            banner = grab_banner(host, port) if grab else ""
            return "open", svc, banner
    except socket.timeout:
        return "filtered", svc, ""
    except ConnectionRefusedError:
        return "closed", svc, ""
    except OSError:
        return "filtered", svc, ""

# ──────────────────────────────────────────────
# UDP scan (best-effort; not as reliable as TCP)
# ──────────────────────────────────────────────
def scan_udp(host, port, timeout=2.0):
    """
    Send an empty UDP datagram and wait for a response.
    ICMP port-unreachable → closed. No response → open|filtered.
    Requires root/admin on most systems for proper ICMP detection.
    """
    svc = SERVICES.get(port, "unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00" * 8, (host, port))
            s.recvfrom(1024)
            return "open", svc, ""
    except socket.timeout:
        return "open|filtered", svc, ""
    except ConnectionRefusedError:
        return "closed", svc, ""
    except PermissionError:
        return "open|filtered", svc, "requires root for ICMP"
    except Exception:
        return "filtered", svc, ""

# ──────────────────────────────────────────────
# Progress tracker (thread-safe)
# ──────────────────────────────────────────────
class Progress:
    def __init__(self, total):
        self.total = total
        self.done = 0
        self.open = 0
        self.filtered = 0
        self.closed = 0
        self._lock = threading.Lock()

    def update(self, state):
        with self._lock:
            self.done += 1
            if state == "open":
                self.open += 1
            elif "filtered" in state:
                self.filtered += 1
            else:
                self.closed += 1

    def bar(self, width=40):
        pct = self.done / self.total if self.total else 0
        filled = int(pct * width)
        bar = "█" * filled + "░" * (width - filled)
        return f"[{bar}] {pct*100:5.1f}%  {self.done}/{self.total} ports"

# ──────────────────────────────────────────────
# Main scanner
# ──────────────────────────────────────────────
def run_scan(args):
    host = args.target
    protocol = args.protocol.upper()
    timeout = args.timeout
    threads = args.threads
    grab = args.banner
    show_closed = args.closed
    output_file = args.output

    # Resolve hostname
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(colored(f"[!] Cannot resolve host: {host}", C.RED))
        sys.exit(1)

    ports = parse_ports(args.ports)
    total = len(ports) * (2 if protocol == "BOTH" else 1)
    prog = Progress(total)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    divider = "─" * 62

    header = f"""
{colored('╔══════════════════════════════════════════════════════════╗', C.CYAN)}
{colored('║', C.CYAN)}  {colored('PORTSCANNER.PY', C.BOLD + C.GREEN)}  —  Real-time Network Port Discovery   {colored('║', C.CYAN)}
{colored('╚══════════════════════════════════════════════════════════╝', C.CYAN)}

  {colored('Target   :', C.DIM)} {colored(host, C.BOLD)} ({colored(ip, C.CYAN)})
  {colored('Ports    :', C.DIM)} {ports[0]}–{ports[-1]}  ({len(ports)} ports)
  {colored('Protocol :', C.DIM)} {protocol}
  {colored('Threads  :', C.DIM)} {threads}
  {colored('Timeout  :', C.DIM)} {timeout}s
  {colored('Started  :', C.DIM)} {now}
{divider}
  {'PORT':<8} {'PROTO':<6} {'STATE':<12} {'SERVICE':<18} {'BANNER'}
{divider}"""
    print(header)

    results = []
    results_lock = threading.Lock()
    start_time = time.time()

    def task(port, proto):
        if proto == "TCP":
            state, svc, banner = scan_tcp(host, port, timeout, grab)
        else:
            state, svc, banner = scan_udp(host, port, timeout)
        prog.update(state)

        # Format output
        if state == "open":
            state_str = colored(f"{'open':<12}", C.GREEN + C.BOLD)
        elif "filtered" in state:
            state_str = colored(f"{state:<12}", C.YELLOW)
        else:
            state_str = colored(f"{'closed':<12}", C.DIM)

        line = (
            f"  {colored(str(port), C.BOLD):<16}"
            f"{colored(proto, C.BLUE):<14}"
            f"{state_str}"
            f"{colored(svc, C.CYAN):<26}"
            f"{colored(banner, C.DIM)}"
        )

        with results_lock:
            if state == "open" or "filtered" in state or show_closed:
                print(f"\r{line}")
                print(f"  {colored(prog.bar(), C.DIM)}", end="\r", flush=True)
            results.append({
                "port": port, "proto": proto,
                "state": state, "service": svc, "banner": banner
            })

    # Run with thread pool
    protos = ["TCP", "UDP"] if protocol == "BOTH" else [protocol]
    tasks = [(port, proto) for port in ports for proto in protos]

    try:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(task, p, pr): (p, pr) for p, pr in tasks}
            for f in as_completed(futures):
                pass  # progress updates happen inside task()
    except KeyboardInterrupt:
        print(colored("\n\n[!] Scan interrupted by user.", C.YELLOW))

    elapsed = time.time() - start_time

    # Summary
    open_results = [r for r in results if r["state"] == "open"]
    summary = f"""
{divider}
  {colored('Scan complete', C.BOLD + C.GREEN)}  in {elapsed:.2f}s

  {colored(str(prog.open), C.GREEN + C.BOLD)} open    •  \
{colored(str(prog.filtered), C.YELLOW)} filtered    •  \
{colored(str(prog.closed), C.DIM)} closed

  Host {colored(host, C.BOLD)} is {colored('UP', C.GREEN + C.BOLD) if open_results else colored('DOWN or heavily filtered', C.RED)}
{divider}"""
    print(summary)

    # Open ports summary
    if open_results:
        print(f"  {colored('Open ports:', C.BOLD)}")
        for r in sorted(open_results, key=lambda x: x["port"]):
            b = f"  {colored(r['banner'], C.DIM)}" if r.get("banner") else ""
            print(f"    {colored(str(r['port']), C.GREEN + C.BOLD)}/{r['proto'].lower():<6}  {colored(r['service'], C.CYAN)}{b}")
        print()

    # Write output file
    if output_file:
        with open(output_file, "w") as f:
            f.write(f"Port Scan Results — {host} ({ip})\n")
            f.write(f"Scan date: {now}\n")
            f.write(f"{'─'*60}\n")
            f.write(f"{'PORT':<8}{'PROTO':<8}{'STATE':<14}{'SERVICE':<20}BANNER\n")
            f.write(f"{'─'*60}\n")
            for r in sorted(results, key=lambda x: (x["port"], x["proto"])):
                if r["state"] == "open" or show_closed:
                    f.write(
                        f"{r['port']:<8}{r['proto']:<8}{r['state']:<14}"
                        f"{r['service']:<20}{r.get('banner','')}\n"
                    )
        print(f"  Results saved to {colored(output_file, C.CYAN)}\n")

    return results

# ──────────────────────────────────────────────
# CLI argument parsing
# ──────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="portscanner.py",
        description="Real-time multithreaded port scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python portscanner.py 192.168.1.1
  python portscanner.py scanme.nmap.org -p 1-1024
  python portscanner.py 10.0.0.1 -p 80,443,8080 --banner
  python portscanner.py 10.0.0.1 -p 1-65535 -t 200 --protocol TCP -o results.txt
  python portscanner.py 10.0.0.1 -p 22,53,161 --protocol BOTH --closed
        """
    )
    p.add_argument("target", help="Target hostname or IP address")
    p.add_argument("-p", "--ports", default="1-1024",
                   help="Port range or list (default: 1-1024)\n"
                        "Examples: 1-65535  |  80,443,8080  |  22,1-100,3306")
    p.add_argument("--protocol", default="TCP", choices=["TCP", "UDP", "BOTH"],
                   help="Protocol to use (default: TCP)")
    p.add_argument("-t", "--threads", type=int, default=100,
                   help="Number of worker threads (default: 100)")
    p.add_argument("--timeout", type=float, default=1.0,
                   help="Socket timeout per port in seconds (default: 1.0)")
    p.add_argument("--banner", action="store_true",
                   help="Attempt to grab service banners from open ports")
    p.add_argument("--closed", action="store_true",
                   help="Also print closed ports (verbose)")
    p.add_argument("-o", "--output",
                   help="Save results to a text file")
    return p

# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────
if __name__ == "__main__":
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    args = parser.parse_args()
    run_scan(args)
