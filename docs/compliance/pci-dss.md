# PCI DSS 4.0 Compliance

Automated compliance for Payment Card Industry Data Security Standard.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/compliance/pci-dss-automation){ .md-button .md-button--primary }

---

## Overview

Complete PCI DSS 4.0 implementation achieving **zero audit findings** for 3 consecutive years, protecting multi-PB cardholder data environment processing 1M+ daily transactions.

---

## Compliance Metrics

| Metric | Value |
|--------|-------|
| Audit Findings | Zero (3 years) |
| Automated Checks | 150+ |
| Control Coverage | 100% |
| Evidence Automation | 90% |
| Assessment Prep Time | Reduced 60% |

---

## Requirement Coverage

### Requirement 1: Network Security Controls

```yaml
# Automated firewall rule validation
checks:
  - name: "Deny all inbound by default"
    resource: aws_security_group
    condition: ingress_rules_explicit_allow_only

  - name: "No public database access"
    resource: aws_db_instance
    condition: publicly_accessible == false
```

### Requirement 3: Protect Stored Account Data

- Encryption at rest (AES-256 via KMS)
- PAN tokenization for scope reduction
- Key rotation every 90 days
- Access logging and monitoring

### Requirement 6: Secure Systems Development

```yaml
# CI/CD security gates
pipeline_gates:
  - sast: SonarQube (zero high/critical)
  - sca: Snyk (no known vulnerabilities)
  - secrets: GitLeaks (no secrets detected)
  - container: Trivy (no critical CVEs)
```

### Requirement 8: Access Control

- MFA enforcement (hardware tokens for CDE)
- Least privilege IAM policies
- Session timeout: 15 minutes
- Password complexity: 12+ chars, rotation

### Requirement 10: Logging and Monitoring

```yaml
# Log retention and monitoring
logging:
  retention: 1 year (hot: 90 days, cold: 275 days)
  sources:
    - CloudTrail (all regions)
    - VPC Flow Logs
    - Application logs
    - Database audit logs

  siem:
    platform: Wazuh
    rules: 280+ custom rules
    alerts: Real-time to SOC
```

### Requirement 11: Security Testing

| Test Type | Frequency | Coverage |
|-----------|-----------|----------|
| Vulnerability Scan | Weekly | 100% assets |
| Penetration Test | Annual | CDE + connected |
| ASV Scan | Quarterly | External |
| Segmentation Test | Annual | Network boundaries |

### Requirement 12: Security Policies

- Information Security Policy
- Incident Response Plan
- Vendor Management Program
- Security Awareness Training

---

## Automated Checks

### Infrastructure Validation

```python
# Example: PCI DSS automated check
def check_encryption_at_rest():
    """PCI DSS 3.4 - Render PAN unreadable"""
    violations = []

    for bucket in s3_client.list_buckets():
        encryption = get_bucket_encryption(bucket)
        if not encryption or encryption['Algorithm'] != 'aws:kms':
            violations.append({
                'resource': bucket,
                'requirement': '3.4',
                'finding': 'Missing KMS encryption'
            })

    return violations
```

### Compliance Dashboard

Real-time visibility into:

- Control effectiveness
- Failed checks with remediation
- Evidence collection status
- Upcoming assessment deadlines

---

## Evidence Collection

### Automated Screenshots

```bash
#!/bin/bash
# Capture compliance evidence
DATE=$(date +%Y-%m-%d)
EVIDENCE_DIR="evidence/${DATE}"

# Security group configs
aws ec2 describe-security-groups > "${EVIDENCE_DIR}/security-groups.json"

# IAM policies
aws iam get-account-authorization-details > "${EVIDENCE_DIR}/iam-policies.json"

# Encryption status
aws kms list-keys > "${EVIDENCE_DIR}/kms-keys.json"
```

### Evidence Organization

```
evidence/
├── requirement-01/
│   ├── firewall-rules/
│   ├── network-diagrams/
│   └── segmentation-tests/
├── requirement-03/
│   ├── encryption-configs/
│   ├── key-management/
│   └── tokenization/
├── requirement-10/
│   ├── log-configs/
│   ├── retention-policies/
│   └── siem-alerts/
└── quarterly-scans/
    ├── asv-reports/
    └── vulnerability-scans/
```

---

## Source Files

| File | Description |
|------|-------------|
| [pci-dss-automation/](https://github.com/gantmane/Portfolio/tree/main/compliance/pci-dss-automation) | Automated checks |
| [README.md](https://github.com/gantmane/Portfolio/blob/main/compliance/pci-dss-automation/README.md) | Implementation guide |
| [audit-reporting/](https://github.com/gantmane/Portfolio/tree/main/compliance/audit-reporting) | Evidence scripts |
