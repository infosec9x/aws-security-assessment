#!/usr/bin/env python3
"""Delta Report — Before vs After Remediation"""
import csv, os
from collections import Counter

def count_fails(path):
    c = Counter()
    if not os.path.exists(path): return c
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if row.get("STATUS","").upper() == "FAIL":
                c[row.get("SEVERITY","informational").lower()] += 1
    return c

base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
before = count_fails(os.path.join(base, "prowler_scan_before.csv"))
after  = count_fails(os.path.join(base, "prowler_scan_after.csv"))

print("\n" + "="*55)
print("  REMEDIATION DELTA REPORT — Before vs After")
print("="*55)
print(f"  {'Severity':<14} {'Before':>7} {'After':>7} {'Fixed':>7} {'% Reduced':>10}")
print("-"*55)
tb = ta = 0
for sev in ["critical","high","medium","low"]:
    b, a = before.get(sev,0), after.get(sev,0)
    fixed = b - a
    pct = f"{int(fixed/b*100)}%" if b > 0 else "N/A"
    print(f"  {sev.upper():<14} {b:>7} {a:>7} {fixed:>7} {pct:>10}")
    tb += b; ta += a
print("-"*55)
print(f"  {'TOTAL':<14} {tb:>7} {ta:>7} {tb-ta:>7} {f'{int((tb-ta)/tb*100)}%' if tb else 'N/A':>10}")
print("="*55)
print(f"\n  Risk reduced by {tb-ta} findings after remediation.")
