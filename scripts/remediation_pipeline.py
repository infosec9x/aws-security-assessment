#!/usr/bin/env python3
"""
AWS Security Posture Assessment - Remediation Pipeline
Author: Abel Omambia
"""
import csv, json, os
from datetime import datetime

SEVERITY_MAP = {
    "critical": {"cvss_range": "9.0-10.0", "priority": 1, "sla_days": 3,  "color": "CRITICAL"},
    "high":     {"cvss_range": "7.0-8.9",  "priority": 2, "sla_days": 7,  "color": "HIGH"},
    "medium":   {"cvss_range": "4.0-6.9",  "priority": 3, "sla_days": 30, "color": "MEDIUM"},
    "low":      {"cvss_range": "0.1-3.9",  "priority": 4, "sla_days": 90, "color": "LOW"},
    "informational": {"cvss_range": "0.0", "priority": 5, "sla_days": 180,"color": "INFO"},
}

def load_prowler(path):
    findings = []
    if not os.path.exists(path):
        print(f"[!] Not found: {path}"); return findings
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter=';')
        for row in reader:
            if row.get("STATUS","").upper() == "FAIL":
                sev = row.get("SEVERITY","informational").lower()
                findings.append({
                    "source": "Prowler",
                    "check_id": row.get("CHECK_ID","N/A"),
                    "title": row.get("CHECK_TITLE","N/A"),
                    "service": row.get("SERVICE_NAME","N/A"),
                    "severity": sev,
                    "resource": row.get("RESOURCE_UID","N/A"),
                    "region": row.get("REGION","N/A"),
                    "remediation": row.get("REMEDIATION_RECOMMENDATION_TEXT","See Prowler docs"),
                    "status": "OPEN",
                    "discovered": datetime.now().strftime("%Y-%m-%d"),
                    **SEVERITY_MAP.get(sev, SEVERITY_MAP["informational"])
                })
    return findings

def load_guardduty(path):
    findings = []
    if not os.path.exists(path):
        print(f"[!] Not found: {path}"); return findings
    with open(path) as f:
        data = json.load(f)
    for finding in data.get("Findings", []):
        s = finding.get("Severity", 0)
        sev = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
        findings.append({
            "source": "GuardDuty",
            "check_id": finding.get("Id","N/A")[:16],
            "title": finding.get("Title","N/A"),
            "service": finding.get("Type","N/A").split(":")[0],
            "severity": sev,
            "resource": finding.get("Resource",{}).get("ResourceType","N/A"),
            "region": finding.get("Region","N/A"),
            "remediation": "Investigate affected resource per GuardDuty recommendation",
            "status": "OPEN",
            "discovered": datetime.now().strftime("%Y-%m-%d"),
            **SEVERITY_MAP.get(sev, SEVERITY_MAP["informational"])
        })
    return findings

def write_tracker(findings, out):
    findings = sorted(findings, key=lambda x: x["priority"])
    fields = ["Priority","Severity","CVSS Range","Source","Service","Check ID",
              "Title","Resource","Region","SLA (Days)","Status","Discovered","Remediation"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for x in findings:
            w.writerow({"Priority": x["priority"], "Severity": x["severity"].upper(),
                        "CVSS Range": x["cvss_range"], "Source": x["source"],
                        "Service": x["service"], "Check ID": x["check_id"],
                        "Title": x["title"][:80], "Resource": x["resource"][:60],
                        "Region": x["region"], "SLA (Days)": x["sla_days"],
                        "Status": x["status"], "Discovered": x["discovered"],
                        "Remediation": x["remediation"][:120]})
    return findings

def summary(findings):
    print("\n" + "="*60)
    print("   AWS SECURITY POSTURE ASSESSMENT — EXECUTIVE SUMMARY")
    print("="*60)
    print(f"   Date:           {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"   Total Findings: {len(findings)}\n")
    for sev in ["critical","high","medium","low","informational"]:
        n = sum(1 for f in findings if f["severity"] == sev)
        bar = "█" * min(n, 35)
        print(f"   {sev.upper():<15} {n:>4}  {bar}")
    print("\n   TOP CRITICAL/HIGH FINDINGS:")
    for i, f in enumerate([x for x in findings if x["severity"] in ("critical","high")][:5], 1):
        print(f"   {i}. [{f['source']}] {f['title'][:55]}")
        print(f"      SLA: Remediate within {f['sla_days']} days | Resource: {f['resource'][:40]}")
    print("="*60)

base = os.path.dirname(os.path.abspath(__file__))
results = os.path.join(base, "..", "results")
remediation = os.path.join(base, "..", "remediation")
os.makedirs(remediation, exist_ok=True)

print("[*] Loading Prowler findings...")
p = load_prowler(os.path.join(results, "prowler_scan_before.csv"))
print(f"    {len(p)} failed checks found")

print("[*] Loading GuardDuty findings...")
g = load_guardduty(os.path.join(results, "guardduty_findings.json"))
print(f"    {len(g)} GuardDuty findings found")

all_findings = write_tracker(p + g, os.path.join(remediation, "remediation_tracker.csv"))
summary(all_findings)
print(f"\n[+] Tracker saved: remediation/remediation_tracker.csv")
print("[+] Open that file in Excel or Google Sheets for the dashboard view")