import time
from .scanner.tcp import parse_ports, tcp_scan, grab_banner
from .reporters.json_reporter import save_json_report
from .reporters.html_reporter import save_html_report
from .enrichers.vulnmatcher import match_banners_to_vulns

# Try to import nmap integration (support top-level modules or package)
try:
    # prefer package scanner nmap if present
    from vulnscan.scanner import nmap_integration as nm_mod
except Exception:
    try:
        import modules.nmap_integration as nm_mod
    except Exception:
        nm_mod = None

def run_scan(target: str, ports: str, use_nmap: bool, outpath: str, outhtml: str=None):
    port_list = parse_ports(ports)
    print(f"[core] scanning {target} ports {min(port_list)}-{max(port_list)} ({len(port_list)})")
    open_ports = tcp_scan(target, port_list)
    banners = {str(p): grab_banner(target, p) for p in open_ports}
    report = {
        "target": target,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": open_ports,
        "banners": banners
    }

    nmap_info = None
    if use_nmap:
        if nm_mod is None:
            print("[core] nmap integration not available on this machine.")
        else:
            try:
                print("[core] running nmap enrichment...")
                nmap_info = nm_mod.nmap_scan(target, open_ports)
                report["nmap"] = nmap_info
            except Exception as e:
                print(f"[core] nmap enrichment failed: {e}")

    # vuln matching (local DB)
    issues = match_banners_to_vulns(banners)
    report["issues"] = issues

    # save JSON
    save_json_report(report, outpath)

    # save HTML (optional)
    if outhtml:
        save_html_report(report, issues, outhtml)

    print("[core] scan complete")
