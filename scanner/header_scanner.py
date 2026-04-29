import requests

# 🔹 Define required headers and their purpose
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Prevents XSS and code injection attacks",
        "severity": "High"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "Medium"
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "severity": "High"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "Medium"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": "Low"
    }
}


def fetch_headers(url):
    """Send request and get normalized headers"""
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        
        # Normalize headers (case-insensitive handling)
        normalized_headers = {k.lower(): v for k, v in response.headers.items()}
        
        return normalized_headers

    except Exception as e:
        return {"error": str(e)}


def analyze_headers(headers):
    """Check for missing headers"""
    if "error" in headers:
        return {"error": headers["error"]}

    missing = []

    for header, details in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            missing.append({
                "header": header,
                "description": details["description"],
                "severity": details["severity"]
            })

    return missing

def scan_headers(url):
    headers = fetch_headers(url)
    missing_headers = analyze_headers(headers)

    results = []

    # 🔴 Handle error case
    if isinstance(missing_headers, dict) and "error" in missing_headers:
        return [{
            "type": "Header Scan Error",
            "description": missing_headers["error"],
            "severity": "Critical"
        }]

    # 🔹 Convert each missing header into a finding
    for h in missing_headers:
        results.append({
            "type": "Missing Security Header",
            "header": h["header"],
            "description": h["description"],
            "severity": h["severity"]
        })

    return results