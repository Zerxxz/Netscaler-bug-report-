#!/usr/bin/env python3
"""NetScaler/Citrix CVE Database Lookup"""
import subprocess, json, re

cves = [
    ("CVE-2023-4966", "NetScaler ADC/Gateway Session Token Leak", 9.4),
    ("CVE-2023-4967", "NetScaler Buffer Overflow", 9.4),
    ("CVE-2024-6235", "NetScaler Command Injection", 9.8),
    ("CVE-2022-27510", "Citrix ADC Auth Bypass", 9.4),
    ("CVE-2022-27518", "Citrix ADC SMB Relay", 9.1),
    ("CVE-2023-3519", "NetScaler ADC RCE", 10.0),
    ("CVE-2021-21955", "Citrix Gateway Plugin RCE", 8.8),
    ("CVE-2020-8193", "Citrix ADC Path Traversal", 8.8),
    ("CVE-2020-8194", "Citrix ADC SSRF", 8.8),
    ("CVE-2020-8195", "Citrix ADC Multiple Vulnerabilities", 8.8),
    ("CVE-2020-8300", "Citrix ADC Authentication Bypass", 8.2),
    ("CVE-2019-19781", "Citrix ADC/NetScaler Path Traversal RCE", 10.0),
    ("CVE-2020-8190", "Citrix ADC Information Disclosure", 7.5),
    ("CVE-2021-21978", "Citrix ADC XXE Vulnerability", 8.1),
    ("CVE-2021-21979", "Citrix ADC Heap Overflow", 8.8),
    ("CVE-2023-43730", "NetScaler DoS", 7.5),
    ("CVE-2023-43731", "NetScaler DoS", 7.5),
    ("CVE-2023-48781", "NetScaler Arbitrary File Access", 6.5),
]

print("=" * 80)
print(f"{'CVE ID':<20} {'CVSS':<8} {'Status':<12} {'NetScaler Gate':<15} {'RCE?':<8}")
print("=" * 80)
for cve_id, desc, cvss in cves:
    rce_yn = "YES" if cvss >= 9.0 and "RCE" in desc else ("YES" if cvss >= 9.0 else "MAYBE")
    status = "CRITICAL" if cvss >= 9.0 else ("HIGH" if cvss >= 7.5 else "MEDIUM")
    print(f"{cve_id:<20} {cvss:<8.1f} {status:<12} {desc[:30]:<30} {rce_yn:<8}")
print("=" * 80)
print(f"Total CVEs analyzed: {len(cves)}")
print(f"Critical RCE candidates: {sum(1 for c in cves if c[2] >= 9.0)}")
print(f"High priority: {sum(1 for c in cves if c[2] >= 7.5)}")
