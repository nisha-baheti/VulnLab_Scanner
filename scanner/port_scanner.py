import socket
from datetime import datetime

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # timeout for faster scanning
        
        result = sock.connect_ex((target, port))  # returns 0 if open
        sock.close()
        
        return result == 0
    except:
        return False


def port_scanner(target, ports):
    print(f"\n[+] Scanning Target: {target}")
    print(f"[+] Scan started at: {datetime.now()}\n")

    open_ports = []

    for port in ports:
        if scan_port(target, port):
            print(f"[OPEN] Port {port}")
            open_ports.append(port)

    print(f"\n[+] Scan completed at: {datetime.now()}")
    return open_ports


if __name__ == "__main__":
    target = input("Enter target (IP or domain): ")

    # Common ports
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]

    port_scanner(target, ports)