---
name: cybersec-skills
description: Cybersecurity architecture expertise for threat modeling, zero trust, cloud security, defense-in-depth
allowed-tools: Read, Grep, Glob
nist_csf_function: IDENTIFY
nist_csf_categories: [ID.RA, ID.AM, ID.IM]
mitre_attack_coverage: [TA0043, TA0001, TA0002, TA0005, TA0006]
---

# Cybersecurity Skills

> **NIST CSF 2.0 Alignment**: IDENTIFY - Risk Assessment & Threat Modeling
> Supports threat modeling (STRIDE), zero trust architecture, cloud security, defense-in-depth

## Quick Reference
**Index:** "threat_model", "zero_trust", "cloud_security" | **Docs:** ISP/02-IDENTIFY/, ISP/03-PROTECT/, terragrunt/_modules/{aws,kubernetes}

## Core Capabilities

### Threat Modeling (STRIDE) ⇒ ID.RA-03
STRIDE with MITRE ATT&CK mapping: Spoofing (T1078), Tampering (T1565), Repudiation (T1070), Disclosure (T1005), DoS (T1498), Privilege (T1068).
**Reference:** ISP/02-IDENTIFY/

### Zero Trust Architecture ⇒ PR.AA
Identity (MFA, risk-based auth), Device (MDM/UEM), Network (microsegmentation), Application (API gateways), Data (encryption, DLP).
**Reference:** ISP/03-PROTECT/03.1-Identity-Access-Management/

### Cloud Security Architecture ⇒ PR.PS-01
IAM policies (T1078 mitigation), VPC design (T1021 mitigation), KMS encryption (T1552 mitigation), GuardDuty/Security Hub detection.
**Reference:** ISP/03-PROTECT/03.8-Cloud-Governance/

### Defense in Depth ⇒ PR (All)
Multi-layer security via attack path mapping, control gap analysis, and layered mitigations across all attack surfaces.

## MITRE ATT&CK Coverage
TA0043 (Recon), TA0001 (Initial Access), TA0002 (Execution), TA0005 (Evasion), TA0006 (Credentials), all other tactics via defense-in-depth
**Reference:** DevSecOps/docs/FRAMEWORK_REFERENCE.md
