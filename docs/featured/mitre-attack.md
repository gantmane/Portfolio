# MITRE ATT&CK Coverage Mapping

Quantified threat detection capabilities with 85%+ technique coverage and Purple Team validation.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/threat-detection/mitre-attack-mapping){ .md-button .md-button--primary }

---

## Overview

Comprehensive mapping of detection capabilities to MITRE ATT&CK framework, validated through continuous Purple Team exercises.

## Coverage Summary

| Category | Coverage |
|----------|----------|
| **Tactics** | 14/14 (100%) |
| **Techniques** | 120+ (85%+) |
| **Sub-techniques** | 200+ mapped |
| **Validation** | Purple Team tested |

---

## Tactic Coverage

| Tactic | Techniques Covered | Coverage |
|--------|-------------------|----------|
| Initial Access | 8/9 | 89% |
| Execution | 11/13 | 85% |
| Persistence | 15/19 | 79% |
| Privilege Escalation | 12/13 | 92% |
| Defense Evasion | 35/42 | 83% |
| Credential Access | 14/17 | 82% |
| Discovery | 25/31 | 81% |
| Lateral Movement | 8/9 | 89% |
| Collection | 15/17 | 88% |
| Command and Control | 14/16 | 88% |
| Exfiltration | 8/9 | 89% |
| Impact | 12/14 | 86% |

---

## Detection Methods

### Host-Based (Wazuh)

- File integrity monitoring
- Process execution logging
- Registry monitoring (Windows)
- Authentication events
- Privilege escalation detection

### Network-Based (Security Onion)

- Zeek protocol analysis
- Suricata IDS signatures
- DNS query logging
- Network flow analysis
- PCAP retention

### Cloud-Based (AWS)

- CloudTrail event analysis
- GuardDuty findings
- VPC Flow Logs
- S3 access logging
- IAM activity monitoring

---

## Purple Team Validation

### Exercise Scenarios

| Scenario | Techniques Tested | Detection Rate |
|----------|-------------------|----------------|
| AWS Account Takeover | T1078, T1098, T1136 | 100% |
| Kubernetes Container Escape | T1611, T1610, T1053 | 95% |
| Payment Data Exfiltration | T1048, T1567, T1041 | 100% |
| Lateral Movement | T1021, T1570, T1072 | 90% |

[:octicons-file-24: View Purple Team Scenarios](https://github.com/gantmane/Portfolio/tree/main/threat-detection/purple-team)

---

## Gap Analysis

### Identified Gaps

1. **Hardware-based attacks** - Limited visibility
2. **Firmware persistence** - Requires EDR
3. **Supply chain** - Partial coverage

### Remediation Plan

- EDR deployment for endpoint gaps
- Network segmentation for containment
- Supply chain security tooling

---

## Source Files

| File | Description |
|------|-------------|
| [mitre-attack-mapping/](https://github.com/gantmane/Portfolio/tree/main/threat-detection/mitre-attack-mapping) | ATT&CK mapping |
| [threat-hunting/](https://github.com/gantmane/Portfolio/tree/main/threat-detection/threat-hunting) | Hunting queries |
| [purple-team/](https://github.com/gantmane/Portfolio/tree/main/threat-detection/purple-team) | Validation scenarios |

---

## Related Projects

- [SIEM Detection Rules](siem-detection-rules.md) - Detection implementation
- [Threat Hunting Queries](../siem-soc/index.md) - Proactive hunting
