# Wazuh Detection Rules

280+ custom detection rules for enterprise security monitoring.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/siem-soc/custom-detection-rules){ .md-button .md-button--primary }

---

## Overview

Production Wazuh ruleset deployed across 200+ agents, providing host-based detection with <1% false positive rate.

## Rule Categories

### Authentication Security

| Rule ID Range | Category | Count |
|---------------|----------|-------|
| 100001-100099 | Brute force detection | 15 |
| 100100-100199 | Credential stuffing | 12 |
| 100200-100299 | Privilege escalation | 18 |
| 100300-100399 | Service account abuse | 10 |

### PCI DSS Compliance

| Requirement | Rules | Coverage |
|-------------|-------|----------|
| 10.2.1 | User access to cardholder data | 8 |
| 10.2.2 | Root/admin actions | 12 |
| 10.2.4 | Invalid access attempts | 15 |
| 10.2.5 | Authentication mechanisms | 10 |
| 10.2.6 | Audit log access | 6 |

### AWS CloudTrail

| Rule ID Range | Category | Count |
|---------------|----------|-------|
| 110001-110099 | IAM changes | 20 |
| 110100-110199 | Security group changes | 15 |
| 110200-110299 | S3 bucket changes | 12 |
| 110300-110399 | CloudTrail tampering | 8 |

### Kubernetes Security

| Rule ID Range | Category | Count |
|---------------|----------|-------|
| 120001-120099 | Pod security violations | 18 |
| 120100-120199 | RBAC abuse | 12 |
| 120200-120299 | Secret access | 10 |
| 120300-120399 | Container escapes | 8 |

---

## Rule Examples

### Brute Force Detection

```xml
<group name="authentication,brute_force,">
  <rule id="100001" level="10" frequency="5" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <description>Multiple authentication failures from same source</description>
    <group>pci_dss_10.2.4,authentication_failure,</group>
  </rule>
</group>
```

### AWS IAM Change

```xml
<group name="aws,iam,">
  <rule id="110001" level="8">
    <if_sid>80302</if_sid>
    <field name="eventName">CreateUser|DeleteUser|AttachUserPolicy</field>
    <description>AWS IAM user modification detected</description>
    <group>pci_dss_10.2.2,aws_iam,</group>
  </rule>
</group>
```

---

## Deployment

### Automated Validation

```bash
# Rule syntax validation
wazuh-logtest -v

# Coverage analysis
python3 analyze_coverage.py --mitre --pci-dss
```

### Rollback Procedure

1. Backup current rules
2. Deploy new rules
3. Monitor for 24 hours
4. Rollback if false positive rate > 2%

---

## Source Files

| File | Description |
|------|-------------|
| [custom-detection-rules/](https://github.com/gantmane/Portfolio/tree/main/siem-soc/custom-detection-rules) | All rule files |
| [README.md](https://github.com/gantmane/Portfolio/blob/main/siem-soc/custom-detection-rules/README.md) | Rule documentation |
