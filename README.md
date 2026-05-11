# AWS Security Posture Assessment & Remediation Pipeline

## Overview
Automated security assessment lab demonstrating enterprise vulnerability management workflows using AWS-native tools and open-source security scanners.

This project mirrors real-world SOC and security engineering workflows including:
- Environment deployment
- Vulnerability scanning
- CVSS-based prioritization
- Remediation tracking
- Risk reduction validation

---

## Architecture

- **Target:** AWS EC2 instance with intentional security misconfigurations
- **Detection:** AWS GuardDuty, AWS Config, AWS Security Hub
- **Scanner:** Prowler (AWS security assessment tool)
- **Pipeline:** Python remediation and reporting pipeline

---

## Technologies Used

`AWS EC2` `AWS GuardDuty` `AWS Config` `AWS Security Hub` `Prowler` `Python` `IAM` `CloudTrail` `AWS CLI`

---

## What I Built

### Phase 1 — Vulnerable Environment
Configured an AWS EC2 instance with intentional misconfigurations for assessment purposes:

- SSH exposed to `0.0.0.0/0`
- Open inbound security group rules
- IMDSv1 enabled
- Publicly accessible test environment

### Phase 2 — Security Scanning
Performed cloud security assessments using:

- Prowler scans across:
  - EC2
  - IAM
  - S3
  - GuardDuty

Enabled and validated:
- AWS GuardDuty
- AWS Config
- Threat finding exports

### Phase 3 — Python Remediation Pipeline
Developed Python scripts to:

- Parse Prowler findings
- Parse GuardDuty findings
- Categorize findings by severity
- Map remediation SLA timelines
- Generate remediation tracking CSVs
- Produce executive summary reporting

### Phase 4 — Remediation & Validation
Implemented remediation actions including:

- Restricted SSH access
- Removed unnecessary inbound rules
- Improved EC2 metadata protections
- Re-ran scans to validate posture improvements

---

## Results

### Executive Summary
- Successfully deployed AWS security assessment environment
- Generated cloud security findings using Prowler and GuardDuty
- Built automated remediation reporting workflow
- Validated remediation effectiveness through rescanning

### Sample Findings
- Overly permissive security group rules
- IMDSv1 enabled on EC2
- Public exposure risks
- IAM security recommendations

---

## Project Files

| File | Description |
|------|-------------|
| `scripts/remediation_pipeline.py` | Main remediation workflow |
| `scripts/delta_report.py` | Before vs after comparison reporting |
| `results/guardduty_findings.json` | Exported GuardDuty findings |
| `results/` | Prowler scan outputs |
| `README.md` | Project documentation |

---

## Key Takeaways

- Hands-on AWS cloud security assessment experience
- Practical exposure to enterprise vulnerability management workflows
- Experience using GuardDuty, AWS Config, and Prowler
- Built Python automation for remediation tracking
- Demonstrated measurable security posture improvement

---

## Author

Abel Omambia  
GitHub: https://github.com/infosec9x
