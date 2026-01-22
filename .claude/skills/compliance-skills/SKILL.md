---
name: compliance-skills
description: Regulatory compliance and audit expertise for PCI DSS, SOC 2, ISO 27001, HIPAA, GDPR, NIST frameworks. Use when performing compliance assessments, gap analysis, audit preparation, control mapping, or evidence collection.
allowed-tools: Read, Grep, Glob, Bash(aws:*), Bash(gcloud:*), Bash(az:*)
nist_csf_function: GOVERN
nist_csf_categories: [GV.OC-01, GV.OC-03, GV.PO-01, GV.PO-02, GV.RM-01, GV.RM-02, GV.OV-01, GV.OV-02, GV.SC-01]
mitre_attack_coverage: []
---

# Compliance & Audit Skills

> **NIST CSF 2.0 Alignment**: GOVERN Function - Organizational Context, Policy, and Oversight
> Supports regulatory compliance, control frameworks, and audit management

## Quick Reference

**Query MASTER_CONTENT_INDEX.json for:**
- "PCI DSS" → Payment card security requirements
- "SOC 2" → Trust services criteria & controls
- "ISO 27001" → ISMS & Annex A controls
- "HIPAA" → Healthcare security & privacy
- "GDPR" → Data protection & privacy compliance
- "NIST CSF" → Cybersecurity framework mapping

**ISP Documentation:**
- Policies: Compliance policies per framework
- Standards: Control baselines & evidence requirements

**Implementation:**
- Terraform: Compliance automation (AWS Config, Security Hub)
- GRC Tools: Drata, Vanta, ServiceNow GRC integration

## Core Capabilities ⇒ NIST CSF Categories

### Regulatory Frameworks ⇒ GV.OC-01

**PCI DSS v4.0:** 12 reqs (network/data/access/monitoring) | Encryption (Req 3-4) | Access (Req 7-8) | Logging (Req 10) | Testing (Req 11)

**SOC 2 Type II:** Security/Availability/Processing/Confidentiality/Privacy | 6-12mo observation | Control design & effectiveness

**ISO 27001:2022:** 10 clauses + 93 Annex A | Risk-based continuous improvement | Stage 1/2 audit + surveillance

**HIPAA:** Admin (§164.308) | Physical (§164.310) | Technical (§164.312) | Risk analysis | Training | Access | Encryption

**GDPR:** Art. 5 principles | Art. 6 lawful basis | Art. 15-22 data rights | Art. 25 privacy-by-design | Art. 32 security | Art. 33-34 breach 72h notification

**NIST:** CSF 2.0 (6 functions) | SP 800-53 (20 families, 1000+ controls)

### Control Mapping ⇒ GV.PO-01

**Map:** AC-2/A.5.15/CC6.1/7.1+8.1/PR.AA-05 | AU-2/A.8.15/CC7.2/10.1/DE.CM-09 | SC-8/A.8.24/CC6.7/4.1/PR.DS-02 | IA-2/A.8.5/CC6.1/8.3/PR.AA-01

**Themes:** Access control (RBAC/MFA/least priv) | Encryption (at-rest/in-transit) | Logging (audit trails, 1yr retention) | Incident response | Risk management

### Audit Methodology ⇒ GV.OV-01

**Evidence:** Policies | Configs | Logs | Reports | Interviews | Observations

**Testing:** Inquiry (ask) | Observation (watch) | Inspection (review) | Re-performance (test)

**Gap:** Control | Requirement | Current | Gap | Remediation | Priority (AC-2 account mgmt partial no SCIM→High | AU-2 audit 30d retention→extend 365d Medium)

### Compliance Automation ⇒ GV.OV-03

Posture: AWS Config/Security Hub/GCP SCC | Evidence collection (auto) | Validation scripts | GRC (Drata/Vanta/Secureframe)

**AWS:** `aws configservice get-compliance-summary-by-config-rule` | `aws configservice get-compliance-details-by-config-rule` | `aws securityhub get-findings`

**GCP:** `gcloud scc findings list organizations/ORG_ID --filter="state=ACTIVE"`

### Continuous Compliance Metrics ⇒ GV.OV-03

**Targets:** Effectiveness>95% | Findings↓ | MTTR<30d | Evidence 100% | Exceptions<5%

**Schedule:** Weekly auto-scans | Monthly self-assessments | Quarterly management reviews | Annual external audits

### Common Compliance Questions ⇒ GV.OC-01

**Q:** What data? | **Evidence:** Inventory/flows | **NIST:** ID.AM-07
**Q:** Who accesses? | **Evidence:** IAM/reviews | **NIST:** PR.AA-05
**Q:** Data protection? | **Evidence:** KMS/TLS | **NIST:** PR.DS-01/02
**Q:** Logging? | **Evidence:** SIEM/samples | **NIST:** DE.CM-09
**Q:** Incidents? | **Evidence:** Plan/runbooks | **NIST:** RS.MA-01
**Q:** Backups? | **Evidence:** Policies/tests | **NIST:** RC.RP-01

### PCI DSS Specific Guidance ⇒ GV.OC-01

**12 Reqs:** 1=Firewalls | 2=Secure configs | 3=Data protection (encrypt/tokenize) | 4=Transmit encrypt (TLS1.2+) | 5=Malware | 6=SDLC | 7=Access | 8=MFA | 9=Physical | 10=SIEM | 11=Testing (ASV/pentest) | 12=Policies

**Scope:** CDE isolation | Tokenization | P2PE encryption

### SOC 2 Specific Guidance ⇒ GV.OC-01

**Criteria:** CC (org/mgmt/risk/monitoring) | Security (access protection) | Availability (SLA uptime) | Processing (accuracy) | Confidentiality (info handling) | Privacy (personal data)

**Type I:** Point-in-time design | **Type II:** 6-12mo effectiveness

### ISO 27001 Specific Guidance ⇒ GV.PO-01

**Clauses:** 4=Context | 5=Leadership | 6=Planning/risk | 7=Support/resources | 8=Operation/risk treatment | 9=Performance | 10=Improvement

**Annex A (93):** Organizational (37) | People (8) | Physical (14) | Technological (34)

**Process:** Gap analysis→ISMS→Internal audit→Stage 1 (docs)→Stage 2 (implementation)→Cert (3yr+annual surveillance)

### HIPAA/GDPR Specific Guidance ⇒ GV.OC-01

**HIPAA:** Risk analysis | Workforce training | Access (unique IDs/logoff) | Audit logging | Transmit encrypt | BAA | Breach 60d HHS

**GDPR:** Art. 5 principles | Art. 6 lawful basis | Art. 13-14 notices | Art. 15-22 data rights | Art. 25 privacy-by-design | Art. 32 security | Art. 33-34 breach 72h

## MITRE ATT&CK Coverage

Defense-in-depth: Access control | Encryption | Logging | Monitoring | Incident response against all tactics

## Related Documentation

- PCI DSS v4.0: https://www.pcisecuritystandards.org/
- SOC 2: https://www.aicpa.org/soc-for-service-organizations
- ISO 27001:2022: https://www.iso.org/standard/27001
- HIPAA: https://www.hhs.gov/hipaa/
- GDPR: https://gdpr.eu/
- NIST CSF 2.0: https://www.nist.gov/cyberframework
- NIST SP 800-53: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
