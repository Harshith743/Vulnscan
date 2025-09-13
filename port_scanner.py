#!/usr/bin/env python3
"""
Simple port scanner + banner grabbing with optional Nmap enrichment.
Usage examples:
  python port_scanner.py -t 192.168.1.100 -p 1-1024
  python port_scanner.py -t 192.168.1.100 -p 22,80,443 --nmap --output reports/sample_report.json
"""
import socket
import argparse
import json
import time
from pathlib import Path

# try to import nmap integration (optional)
try:
    from modules.nmap_integration import nmap_scan
    HAVE_NMAP = True
except Exception:
    HAVE_NMAP = False

DEFAULT_TIMEOUT = 0.8


def parse_ports(ports_str):
    """Accepts '1-1000' or '22,80,443' or mixed like '1-100,443'"""
    ports = set()
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            if part:
                ports.add(int(part))
    return sorted(ports)


def tcp_scan(host, ports, timeout=DEFAULT_TIMEOUT):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            res = sock.connect_ex((host, port))
            if res == 0:
                open_ports.append(port)
            sock.close()
        except KeyboardInterrupt:
            raise
        except Exception:
            # ignore transient errors
            continue
    return open_ports


def grab_banner(host, port, timeout=1.0, recv_bytes=1024):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        # attempt to receive; some services send immediately, others don't
        try:
            data = s.recv(recv_bytes)
            banner = data.decode(errors="ignore").strip()
        except Exception:
            banner = ""
        s.close()
        return banner
    except Exception:
        return ""


def build_report(target, open_ports, banners, nmap_info=None):
    report = {
        "target": target,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": open_ports,
        "banners": banners,
    }
    if nmap_info:
        report["nmap"] = nmap_info
    return report


def save_json(report, outpath):
    p = Path(outpath)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved to: {p}")


def main():
    parser = argparse.ArgumentParser(description="VulnScan - basic scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports (1-1000 or 22,80,443)")
    parser.add_argument("--nmap", action="store_true", help="Run Nmap enrichment (requires python-nmap and local nmap)")
    parser.add_argument("--output", "-o", default="reports/sample_report.json", help="Output JSON file")
    parser.add_argument("--timeout", type=float, default=0.8, help="Socket connect timeout (seconds)")
    args = parser.parse_args()

    target = args.target
    ports = parse_ports(args.ports)
    print(f"[+] Scanning {target} ports {min(ports)}-{max(ports)} (total {len(ports)}) ...")

    open_ports = tcp_scan(target, ports, timeout=args.timeout)
    print(f"[+] Open ports: {open_ports}")

    banners = {}
    for p in open_ports:
        b = grab_banner(target, p, timeout=1.0)
        banners[str(p)] = b
        if b:
            print(f"    Port {p}: banner: {b[:140]!r}")

    nmap_info = None
    if args.nmap:
        if not HAVE_NMAP:
            print("[!] Nmap integration not available (missing module or python-nmap). Skipping nmap.")
        else:
            try:
                print("[+] Running nmap enrichment ...")
                nmap_info = nmap_scan(target, open_ports)
                print("[+] Nmap data received.")
            except Exception as e:
                print(f"[!] Nmap scan failed: {e}")

    report = build_report(target, open_ports, banners, nmap_info=nmap_info)
    save_json(report, args.output)


if __name__ == "__main__":
    main()
