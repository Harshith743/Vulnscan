"""
Simple wrapper around python-nmap to scan specific ports and return structured info.
Requires: python-nmap and nmap binary installed on system.
"""
import nmap  # python-nmap

def nmap_scan(target, ports):
    """
    ports: list of ports (ints) or empty list to scan default
    returns: dict of port -> dict(service, product, version, state)
    """
    nm = nmap.PortScanner()
    port_str = ",".join(str(p) for p in ports) if ports else None
    args = "-sV --version-intensity 0"
    if port_str:
        scan_target = f"{target} -p {port_str}"
        res = nm.scan(hosts=target, ports=port_str, arguments=args)
    else:
        res = nm.scan(hosts=target, arguments=args)

    out = {}
    try:
        host = list(res["scan"].keys())[0]
        tcp = res["scan"][host].get("tcp", {})
        for p_str, info in tcp.items():
            out[p_str] = {
                "state": info.get("state"),
                "name": info.get("name"),
                "product": info.get("product"),
                "version": info.get("version"),
                "extrainfo": info.get("extrainfo"),
            }
    except Exception:
        # empty or unexpected format
        pass
    return out
