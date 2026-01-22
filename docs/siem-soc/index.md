# SIEM & SOC

Security operations and threat detection with Wazuh and Security Onion.

[:octicons-code-24: View All Source Code](https://github.com/gantmane/Portfolio/tree/main/siem-soc){ .md-button .md-button--primary }

---

## Overview

Dual-SIEM architecture combining host-based (Wazuh) and network-based (Security Onion) detection for comprehensive security visibility.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Security Operations                   │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────────┐      ┌──────────────────┐         │
│  │     Wazuh        │      │  Security Onion  │         │
│  │  (Host-based)    │      │  (Network-based) │         │
│  ├──────────────────┤      ├──────────────────┤         │
│  │ • File Integrity │      │ • Zeek           │         │
│  │ • Log Analysis   │      │ • Suricata       │         │
│  │ • Vulnerability  │      │ • PCAP Capture   │         │
│  │ • Compliance     │      │ • DNS Logging    │         │
│  └────────┬─────────┘      └────────┬─────────┘         │
│           │                         │                    │
│           └───────────┬─────────────┘                    │
│                       ▼                                  │
│            ┌──────────────────┐                          │
│            │  Correlation &   │                          │
│            │  Alerting        │                          │
│            └──────────────────┘                          │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## Wazuh SIEM

### Detection Rules

280+ custom rules covering:

- Authentication anomalies
- PCI DSS compliance
- AWS CloudTrail events
- Kubernetes security
- File integrity monitoring

[:octicons-arrow-right-24: View Wazuh Rules](wazuh-rules.md)

### Key Metrics

| Metric | Value |
|--------|-------|
| Custom Rules | 280+ |
| False Positive Rate | <1% |
| MTTD | <5 minutes |
| Agents Deployed | 200+ |

---

## Security Onion

### Network Detection

| Component | Purpose |
|-----------|---------|
| Zeek | Protocol analysis, connection logging |
| Suricata | Signature-based IDS |
| Stenographer | Full packet capture |
| Elasticsearch | Log storage and search |

[:octicons-arrow-right-24: View Security Onion](security-onion.md)

---

## Incident Response

### Playbooks

- **Data Breach Response** - PCI DSS compliant procedures
- **AWS Account Compromise** - Cloud-specific response
- **Ransomware** - Containment and recovery

[:octicons-arrow-right-24: View IR Playbooks](https://github.com/gantmane/Portfolio/tree/main/siem-soc/incident-response)

---

## Source Files

| Directory | Description |
|-----------|-------------|
| [custom-detection-rules/](https://github.com/gantmane/Portfolio/tree/main/siem-soc/custom-detection-rules) | Wazuh rules |
| [incident-response/](https://github.com/gantmane/Portfolio/tree/main/siem-soc/incident-response) | IR playbooks |
| [security-onion/](https://github.com/gantmane/Portfolio/tree/main/siem-soc/security-onion) | Network detection |
| [wazuh-deployment/](https://github.com/gantmane/Portfolio/tree/main/siem-soc/wazuh-deployment) | Deployment automation |
