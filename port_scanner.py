import socket
import argparse

def scan_target(host, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("-t", "--target", type=str, required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports", type=str, default="1-1024", help="Port range (e.g., 1-1000)")
    args = parser.parse_args()

    start_port, end_port = map(int, args.ports.split("-"))
    ports_to_scan = range(start_port, end_port + 1)

    print(f"Scanning {args.target} ports {start_port}-{end_port} ...")
    open_ports = scan_target(args.target, ports_to_scan)
    print(f"Open ports: {open_ports}")
