import requests
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from bs4 import BeautifulSoup

# 🔹 Test payloads (safe, non-destructive)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>"
]


def fetch_page(url):
    """Fetch page content"""
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return response.text
    except Exception as e:
        return {"error": str(e)}


def extract_forms(html, base_url):
    """Extract all forms from page"""
    soup = BeautifulSoup(html, "html.parser")
    forms = []

    for form in soup.find_all("form"):
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = []

        for input_tag in form.find_all(["input", "textarea"]):
            name = input_tag.get("name")
            if name:
                inputs.append(name)

        forms.append({
            "action": urljoin(base_url, action) if action else base_url,
            "method": method,
            "inputs": inputs
        })

    return forms


def test_forms(forms):
    """Inject payloads into forms"""
    findings = []

    for form in forms:
        for payload in XSS_PAYLOADS:
            data = {input_name: payload for input_name in form["inputs"]}

            try:
                if form["method"] == "post":
                    response = requests.post(form["action"], data=data, timeout=5)
                else:
                    response = requests.get(form["action"], params=data, timeout=5)

                if payload in response.text:
                    findings.append({
                        "type": "Reflected XSS",
                        "url": form["action"],
                        "method": form["method"].upper(),
                        "payload": payload,
                        "evidence": "Payload reflected in response",
                        "severity": "High"
                    })

            except:
                continue

    return findings


def test_url_parameters(url):
    """Test query parameters in URL"""
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = {k: payload for k in params}
            test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()

            try:
                response = requests.get(test_url, timeout=5)

                if payload in response.text:
                    findings.append({
                        "type": "Reflected XSS (URL parameter)",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": "Payload reflected in response",
                        "severity": "High"
                    })

            except:
                continue

    return findings


def format_result(url, findings):
    """Format final output"""

    # Remove duplicates (same URL + payload)
    unique = {(f["url"], f["payload"]): f for f in findings}.values()

    high = len(unique)

    return {
        "type": "Cross-Site Scripting (XSS)",
        "target": url,
        "status": "Vulnerable" if unique else "Safe",
        "vulnerability": True if unique else False,
        "total_issues": len(unique),
        "severity_summary": {
            "High": high,
            "Medium": 0,
            "Low": 0
        },
        "issues": list(unique)
    }


def scan_xss(url):
    """Main function"""
    html = fetch_page(url)

    if isinstance(html, dict) and "error" in html:
        return {
            "type": "Cross-Site Scripting (XSS)",
            "target": url,
            "status": "Error",
            "vulnerability": False,
            "message": html["error"]
        }

    forms = extract_forms(html, url)
    form_findings = test_forms(forms)
    param_findings = test_url_parameters(url)

    all_findings = form_findings + param_findings

    return format_result(url, all_findings)


# 🔹 Local test
if __name__ == "__main__":
    test_url = "http://localhost:8000"
    result = scan_xss(test_url)
    print(result)