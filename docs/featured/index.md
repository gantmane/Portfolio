# Featured Projects

Production-grade security implementations from real-world deployments in PCI DSS Level 1 compliant fintech environments.

---

## SIEM & Detection

### [500+ Production SIEM Detection Rules](siem-detection-rules.md)

Comprehensive Wazuh ruleset for payment processing security.

- **Coverage**: 85%+ MITRE ATT&CK techniques, PCI DSS 100%, OWASP Top 10 100%
- **Quality**: <1% false positive rate, MTTD <5 minutes
- **Deployment**: Automated with validation and rollback
- **Impact**: 85% reduction in security incidents

[:octicons-code-24: View Source](https://github.com/gantmane/Portfolio/tree/main/siem-soc/custom-detection-rules){ .md-button }

---

### [Enterprise Incident Response Playbooks](incident-response.md)

NIST SP 800-61 aligned procedures for PCI DSS environments.

- **Data Breach Response**: Complete PCI DSS breach playbook (800+ lines)
- **AWS Account Compromise**: Cloud-specific incident procedures (700+ lines)
- **Automation**: Bash/Python scripts for forensics and containment
- **Compliance**: Regulatory notification templates included

[:octicons-code-24: View Source](https://github.com/gantmane/Portfolio/tree/main/siem-soc/incident-response){ .md-button }

---

## Threat Detection

### [MITRE ATT&CK Coverage Mapping](mitre-attack.md)

Quantified threat detection capabilities with Purple Team validation.

- **Technique Coverage**: 120+ techniques across 14 tactics (85%+ coverage)
- **Validation**: Purple Team tested with documented results
- **Gap Analysis**: Identified gaps with remediation recommendations

[:octicons-code-24: View Source](https://github.com/gantmane/Portfolio/tree/main/threat-detection/mitre-attack-mapping){ .md-button }

---

## Business Continuity

### [Multi-Region Disaster Recovery](disaster-recovery.md)

Pilot-light DR with 4-hour RTO, 15-minute RPO.

- **Automation**: Complete deployment script (600+ lines)
- **Coverage**: Database replication, S3 CRR, EKS clusters, Route 53 failover
- **Runbook**: Step-by-step recovery procedures with exact commands

[:octicons-code-24: View Source](https://github.com/gantmane/Portfolio/tree/main/disaster-recovery/multi-region-dr){ .md-button }

---

## API Security

### [API Security Framework](api-security.md)

AWS WAF + API Gateway protecting 120+ endpoints.

- **Attacks Blocked**: 50,000+ monthly (SQL injection, XSS, card testing)
- **Rate Limiting**: Tiered approach (Free/Standard/Premium)
- **Authentication**: JWT + API Keys + mTLS
- **Availability**: 99.98% with 2.5M requests/day

[:octicons-code-24: View Source](https://github.com/gantmane/Portfolio/tree/main/api-security/gateway-protection){ .md-button }
