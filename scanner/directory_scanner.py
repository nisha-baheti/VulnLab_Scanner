#file structure

# directory_scanner.py

import requests

# 🔹 Common sensitive paths to test
COMMON_PATHS = {
    "/": {"description": "Root directory listing", "severity": "High"},
    "/admin": {"description": "Admin panel exposure", "severity": "High"},
    "/backup": {"description": "Backup files exposure", "severity": "High"},
    "/config": {"description": "Configuration files exposure", "severity": "High"},
    "/.git": {"description": "Git repository exposure", "severity": "High"},
    "/.env": {"description": "Environment file exposure", "severity": "High"},
    "/uploads": {"description": "Unrestricted file uploads access", "severity": "Medium"},
    "/test": {"description": "Test environment exposure", "severity": "Low"}
}


def check_paths(base_url):
    findings = []

    for path, details in COMMON_PATHS.items():
        url = base_url.rstrip("/") + path

        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            page_content = response.text.lower()

        # 🔴 Check directory listing FIRST
            if "index of" in page_content or "directory listing for" in page_content:
                findings.append({
                    "path": path,
                    "url": url,
                    "status_code": response.status_code,
                    "description": "Directory listing enabled",
                    "severity": "High"
                })

        # 🟡 Then check general exposure
            elif response.status_code == 200 and len(response.text) > 50:
                findings.append({
                    "path": path,
                    "url": url,
                    "status_code": response.status_code,
                    "description": details["description"],
                    "severity": details["severity"]
                })

        except Exception as e:
            continue

    return findings  


#def format_result(base_url, findings):
#     """Prepare final structured output"""

#     # 🔹 Severity summary
#     high = sum(1 for f in findings if f["severity"] == "High")
#     medium = sum(1 for f in findings if f["severity"] == "Medium")
#     low = sum(1 for f in findings if f["severity"] == "Low")

#     return {
#         "type": "Directory / File Exposure",
#         "target": base_url,
#         "status": "Vulnerable" if findings else "Safe",
#         "vulnerability": True if findings else False,
#         "total_issues": len(findings),
#         "severity_summary": {
#             "High": high,
#             "Medium": medium,
#             "Low": low
#         },
#         "issues": findings
#     }


def scan_directories(base_url):
    findings = check_paths(base_url)

    results = []

    for f in findings:
        results.append({
            "type": "Directory Exposure",
            "path": f["path"],
            "url": f["url"],
            "status_code": f["status_code"],
            "description": f["description"],
            "severity": f["severity"]
        })

    return results
