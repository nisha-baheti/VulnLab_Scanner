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


def format_result(url, missing_headers):
    """Prepare final structured output"""

    # 🔹 Handle error case
    if isinstance(missing_headers, dict) and "error" in missing_headers:
        return {
            "type": "Missing Security Headers",
            "target": url,
            "status": "Error",
            "vulnerability": False,
            "message": missing_headers["error"]
        }

    # 🔹 Severity summary
    high = sum(1 for h in missing_headers if h["severity"] == "High")
    medium = sum(1 for h in missing_headers if h["severity"] == "Medium")
    low = sum(1 for h in missing_headers if h["severity"] == "Low")

    return {
        "type": "Missing Security Headers",
        "category": "Security Misconfiguration",
        "target": url,
        "status": "Vulnerable" if missing_headers else "Safe",
        "vulnerability": True if missing_headers else False,
        "total_issues": len(missing_headers),
        "severity_summary": {
            "High": high,
            "Medium": medium,
            "Low": low
        },
        "issues": missing_headers
    }


def scan_headers(url):
    """Main function to call from backend"""
    headers = fetch_headers(url)
    missing_headers = analyze_headers(headers)
    result = format_result(url, missing_headers)

    return result


# 🔹 For testing locally
if __name__ == "__main__":
    test_url = "https://example.com/"
    result = scan_headers(test_url)
    print(result)    
#We detect missing security headers as part of security misconfiguration vulnerabilities.