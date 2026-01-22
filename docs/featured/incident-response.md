# Enterprise Incident Response Playbooks

NIST SP 800-61 aligned procedures for PCI DSS environments with automation scripts.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/siem-soc/incident-response){ .md-button .md-button--primary }

---

## Overview

Production-tested incident response playbooks designed for payment processing environments, with complete automation for forensics and containment.

## Available Playbooks

### Data Breach Response

**800+ lines** - Complete PCI DSS breach response procedure

- Initial detection and triage
- Evidence preservation and chain of custody
- Containment procedures
- PCI DSS notification requirements
- Forensic analysis steps
- Recovery and lessons learned

[:octicons-file-24: View Playbook](https://github.com/gantmane/Portfolio/blob/main/siem-soc/incident-response/data-breach-response.md)

---

### AWS Account Compromise

**700+ lines** - Cloud-specific incident procedures

- Credential compromise detection
- IAM lockdown procedures
- CloudTrail analysis
- Resource isolation
- Evidence collection from AWS services
- Account recovery steps

[:octicons-file-24: View Playbook](https://github.com/gantmane/Portfolio/blob/main/siem-soc/incident-response/aws-account-compromise.md)

---

## Playbook Structure

All playbooks follow the NIST SP 800-61 framework:

```
1. Preparation
   └── Tools, contacts, documentation ready

2. Detection & Analysis
   └── Indicators, triage, severity classification

3. Containment
   └── Short-term and long-term containment

4. Eradication
   └── Root cause removal, system hardening

5. Recovery
   └── Service restoration, monitoring

6. Post-Incident
   └── Lessons learned, process improvements
```

---

## Automation Scripts

### Forensic Collection

```bash
#!/bin/bash
# Automated evidence collection
# - Memory dump
# - Disk imaging
# - Log preservation
# - Network captures
```

### Containment Actions

```bash
#!/bin/bash
# Automated containment
# - Network isolation
# - Account suspension
# - Service shutdown
# - Firewall rules
```

---

## Compliance Mapping

| Requirement | Coverage |
|-------------|----------|
| PCI DSS 12.10 | Incident response plan |
| PCI DSS 12.10.1 | Response procedures |
| PCI DSS 12.10.2 | Annual testing |
| PCI DSS 12.10.4 | Staff training |
| PCI DSS 12.10.5 | Alert monitoring |

---

## Source Files

| File | Description |
|------|-------------|
| [incident-response/](https://github.com/gantmane/Portfolio/tree/main/siem-soc/incident-response) | Playbooks directory |
| [data-breach-response.md](https://github.com/gantmane/Portfolio/blob/main/siem-soc/incident-response/data-breach-response.md) | Data breach playbook |
| [aws-account-compromise.md](https://github.com/gantmane/Portfolio/blob/main/siem-soc/incident-response/aws-account-compromise.md) | AWS compromise playbook |

---

## Related Projects

- [SIEM Detection Rules](siem-detection-rules.md) - Detection capabilities
- [MITRE ATT&CK Mapping](mitre-attack.md) - Threat coverage
