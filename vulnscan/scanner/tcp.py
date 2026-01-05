import socket

DEFAULT_TIMEOUT = 0.8

def parse_ports(ports_str):
    ports = set()
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            a,b = part.split("-",1)
            ports.update(range(int(a), int(b)+1))
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
        except Exception:
            continue
    return open_ports

def grab_banner(host, port, timeout=1.0, recv_bytes=1024):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        try:
            data = s.recv(recv_bytes)
            banner = data.decode(errors="ignore").strip()
        except Exception:
            banner = ""
        s.close()
        return banner
    except Exception:
        return ""
