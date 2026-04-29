from scanner.sql_scanner import scan_sql_injection
from scanner.xss_scanner import scan_xss
from scanner.directory_scanner import scan_directories
from scanner.header_scanner import scan_headers
from scanner.port_scanner import port_scanner

import json
from datetime import datetime


def run_all_scanners(target):
    all_results = []

    scanners = [
        scan_sql_injection,
        scan_xss,
        scan_directories,
        scan_headers,
        port_scanner
    ]

    for scanner in scanners:
        print(f"[+] Running {scanner.__name__}...")
        try:
            result = scanner(target)

            # 🔴 FIX: normalize output
            if isinstance(result, list):
                all_results.extend(result)
            elif isinstance(result, dict):
                all_results.append(result)
            elif result is not None:
                all_results.append({
                    "type": "Scanner Output",
                    "description": str(result),
                    "severity": "Info"
                })

        except Exception as e:
            all_results.append({
                "type": "Scanner Error",
                "description": f"{scanner.__name__} failed: {str(e)}",
                "severity": "Critical"
            })

    return all_results

def generate_summary(results):
    summary = {"High": 0, "Medium": 0, "Low": 0, "Critical": 0, "Info": 0}

    for r in results:
        sev = r.get("severity", "Info")
        if sev in summary:
            summary[sev] += 1
        else:
            summary["Info"] += 1

    return summary


def print_report(results, target):
    print("\n========== FINAL REPORT ==========")
    print(f"Target: {target}")
    print(f"Total Findings: {len(results)}\n")

    if not results:
        print("[SAFE] No vulnerabilities found 🎉")
        return

    for r in results:
        if not isinstance(r, dict):
            continue
        
        print(f"[{r.get('severity', 'Info')}] {r.get('type', 'Unknown')}")
        print(f"  Description: {r.get('description', 'N/A')}")

        # Optional fields
        if "parameter" in r:
            print(f"  Parameter: {r['parameter']}")
        if "payload" in r:
            print(f"  Payload: {r['payload']}")
        if "port" in r:
            print(f"  Port: {r['port']}")
        if "url" in r:
            print(f"  URL: {r['url']}")
        if "header" in r:
            print(f"  Header: {r['header']}")

        print()


def save_json_report(results, target):
    report = {
        "target": target,
        "timestamp": str(datetime.now()),
        "total_findings": len(results),
        "summary": generate_summary(results),
        "findings": results
    }

    with open("report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("\n[+] JSON report saved as report.json")


def main():
    target = input("Enter target URL or IP: ").strip()

    if not target.startswith("http"):
        # assume http if not specified
        target = "https://" + target

    start_time = datetime.now()

    results = run_all_scanners(target)

    end_time = datetime.now()

    print_report(results, target)
    save_json_report(results, target)

    print(f"\n[+] Scan started at: {start_time}")
    print(f"[+] Scan finished at: {end_time}")
    print(f"[+] Duration: {end_time - start_time}")


if __name__ == "__main__":
    main()

    #git commit -m "Build vulnerability scanner pipeline: integrated SQL, XSS, directory, header and port scanners with centralized reporting"