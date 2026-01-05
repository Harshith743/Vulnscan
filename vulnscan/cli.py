import argparse
from .core import run_scan

def build_parser():
    p = argparse.ArgumentParser(prog="vulnscan", description="VulnScan CLI")
    p.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    p.add_argument("-p", "--ports", default="1-1024", help="Ports (e.g., 1-1024 or 22,80,443)")
    p.add_argument("--nmap", action="store_true", help="Enable Nmap enrichment")
    p.add_argument("-o", "--output", default="reports/scan.json", help="Output JSON file")
    p.add_argument("--html", help="Optional HTML report path (e.g., reports/scan.html)")
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    run_scan(target=args.target, ports=args.ports, use_nmap=args.nmap, outpath=args.output, outhtml=args.html)
