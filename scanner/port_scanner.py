import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        result = sock.connect_ex((target, port))
        sock.close()
        
        if result == 0:
            return port
    except:
        return None


def port_scanner(target, ports):
    print(f"\n[+] Scanning Target: {target}")
    print(f"[+] Scan started at: {datetime.now()}\n")

    open_ports = []

    # Thread pool
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda port: scan_port(target, port), ports)

    for port in results:
        if port:
            print(f"[OPEN] Port {port}")
            open_ports.append(port)

    print(f"\n[+] Scan completed at: {datetime.now()}")
    return open_ports


if __name__ == "__main__":
    target = input("Enter target (IP or domain): ")

    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]

    port_scanner(target, ports)