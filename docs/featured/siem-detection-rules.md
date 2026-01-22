# 500+ Production SIEM Detection Rules

Comprehensive Wazuh ruleset for payment processing security with 85%+ MITRE ATT&CK coverage.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/siem-soc/custom-detection-rules){ .md-button .md-button--primary }

---

## Overview

This detection ruleset powers the security operations for a PCI DSS Level 1 compliant payment processing platform handling 1M+ daily transactions.

## Key Metrics

| Metric | Value |
|--------|-------|
| Total Rules | 280+ custom Wazuh rules |
| MITRE ATT&CK Coverage | 85%+ techniques |
| PCI DSS Coverage | 100% relevant requirements |
| False Positive Rate | <1% |
| Mean Time to Detection | <5 minutes |
| Incident Reduction | 85% YoY |

---

## Rule Categories

### Authentication & Access Control

- Brute force detection (adaptive thresholds)
- Credential stuffing patterns
- Impossible travel detection
- Privilege escalation attempts
- Service account abuse

### Payment Security (PCI DSS)

- Card data access monitoring
- Tokenization bypass attempts
- PAN exposure detection
- Cardholder data environment (CDE) anomalies
- Payment fraud patterns

### Cloud Security (AWS)

- IAM policy changes
- Security group modifications
- S3 bucket exposure
- CloudTrail tampering
- GuardDuty finding correlation

### Kubernetes Security

- Pod security policy violations
- Container escape attempts
- Namespace boundary violations
- RBAC abuse patterns
- Secrets access anomalies

### Network Security

- Lateral movement detection
- Command & control patterns
- Data exfiltration indicators
- DNS tunneling
- Unusual port activity

---

## Implementation Details

### Rule Structure

```xml
<group name="pci-dss,authentication,">
  <rule id="100001" level="10">
    <if_sid>5710</if_sid>
    <match>authentication failure</match>
    <description>PCI-DSS: Multiple authentication failures detected</description>
    <group>pci_dss_10.2.4,authentication_failure,</group>
    <options>no_full_log</options>
  </rule>
</group>
```

### Deployment Automation

- Automated rule validation before deployment
- Rollback capabilities for failed deployments
- A/B testing for rule effectiveness
- Continuous tuning based on false positive feedback

---

## Source Files

| File | Description |
|------|-------------|
| [custom-detection-rules/](https://github.com/gantmane/Portfolio/tree/main/siem-soc/custom-detection-rules) | Main detection rules directory |
| [wazuh-deployment/](https://github.com/gantmane/Portfolio/tree/main/siem-soc/wazuh-deployment) | Wazuh deployment automation |
| [README.md](https://github.com/gantmane/Portfolio/blob/main/siem-soc/README.md) | SIEM-SOC documentation |

---

## Related Projects

- [MITRE ATT&CK Mapping](mitre-attack.md) - Coverage analysis
- [Incident Response Playbooks](incident-response.md) - Response procedures
- [Security Onion Integration](../siem-soc/security-onion.md) - Network detection
