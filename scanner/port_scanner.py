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


def port_scanner(target, ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]

    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda port: scan_port(target, port), ports)

    for port in results:
        if port:
            open_ports.append(port)

    # 🔹 Convert to standardized result format
    findings = []

    for port in open_ports:
        severity = "Medium"

        # 🔥 Assign higher severity for sensitive ports
        if port in [21, 22, 23, 445]:
            severity = "High"

        findings.append({
            "type": "Open Port",
            "port": port,
            "description": f"Port {port} is open",
            "severity": severity
        })

    return findings