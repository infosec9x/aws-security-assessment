# AWS Security Posture Assessment & Remediation Pipeline

## Overview
Automated security assessment lab demonstrating enterprise vulnerability management
workflows using AWS-native tools and open-source security scanners. Mirrors real-world
SOC and security engineering workflows: environment deployment, scanning, CVSS-based
prioritization, remediation, and measurable risk reduction reporting.

## Architecture
- **Target:** AWS EC2 with intentional misconfigurations (open ports, IMDSv1 enabled)
- **Detection:** AWS GuardDuty, AWS Config, AWS Security Hub
- **Scanner:** Prowler open-source AWS security scanner (144 checks)
- **Pipeline:** Python ingestion script with CVSS severity mapping and CSV remediation tracker

## Technologies
`AWS EC2` `AWS GuardDuty` `AWS Config` `AWS Security Hub` `Prowler` `Python` `IAM` `CloudTrail` `AWS CLI`

## What I Built

### Phase 1 — Vulnerable Environment
Deployed EC2 instance with deliberate misconfigurations:
- Security group with SSH/RDP open to 0.0.0.0/0
- All inbound traffic allowed from any source
- IMDSv2 not enforced (credential theft vector)

### Phase 2 — Security Scanning
- Ran Prowler across EC2, IAM, S3, and GuardDuty (144 checks)
- Enabled GuardDuty with sample threat findings (SSH brute force, port probe, anomalous IAM behavior)
- Exported all findings in CSV and JSON format for pipeline ingestion

### Phase 3 — Remediation Pipeline
Python script (`scripts/remediation_pipeline.py`) that:
- Ingests Prowler CSV (semicolon-delimited) and GuardDuty JSON findings
- Maps findings to CVSS-based severity tiers (Critical/High/Medium/Low)
- Assigns SLA remediation targets (3 / 7 / 30 / 90 days by severity)
- Outputs prioritized CSV tracker for leadership review
- Prints executive summary with top findings by risk

### Phase 4 — Remediation
- Removed SSH/RDP rules open to 0.0.0.0/0
- Restricted SSH to specific trusted IP only
- Removed all-traffic inbound rule
- Enforced IMDSv2 (HttpTokens=required) on EC2 instance

### Phase 5 — Validation
- Re-ran full Prowler scan post-remediation
- Generated delta report showing before vs after risk reduction

## Pre-Remediation Results
- Total Findings: 79
- Critical: 4 | High: 41 | Medium: 20 | Low: 14
- Top finding: AdministratorAccess IAM policy attached directly to user
- EC2 findings included: open security groups, IMDSv2 not enforced, unencrypted EBS volumes

## Files

| File | Description |
|------|-------------|
| `scripts/remediation_pipeline.py` | Main ingestion and remediation tracking pipeline |
| `scripts/delta_report.py` | Before vs after risk reduction report |
| `results/prowler_scan_before.csv` | Pre-remediation Prowler scan output |
| `results/prowler_scan_after.csv` | Post-remediation Prowler scan output |
| `results/guardduty_findings.json` | GuardDuty threat detection findings |
| `remediation/remediation_tracker.csv` | Prioritized remediation dashboard (79 findings) |

## Key Takeaways
- Applied CVSS scoring logic to prioritize 79 findings by business risk and SLA
- Demonstrated measurable security posture improvement through before/after reporting
- Correlated findings across two tools (Prowler + GuardDuty) in a unified pipeline
- Documented architecture and findings aligned with enterprise security documentation standards