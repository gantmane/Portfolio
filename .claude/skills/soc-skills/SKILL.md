---
name: soc-skills
description: SOC expertise for SIEM operations, alert triage, threat hunting, and log analysis
allowed-tools: Read, Grep, Glob, Bash(subset:*)
nist_csf_function: DETECT
nist_csf_categories: [DE.CM-01, DE.CM-02, DE.CM-03, DE.CM-06, DE.CM-09, DE.AE-02, DE.AE-03, DE.AE-06, DE.AE-07, DE.AE-08]
mitre_attack_coverage: [T1078, T1110, T1059, T1021, T1087, T1069, T1005, T1041, T1071, T1566, T1204, T1486]
---

# SOC Analyst Skills

> **NIST CSF 2.0 Alignment**: DETECT
> Supports continuous monitoring, alert triage, threat hunting, and incident response

## Quick Reference
**Index:** "siem-queries", "threat-hunts", "triage-procedures" | **Docs:** `/DevSecOps/detection-rules/`, SOC playbooks, triage workflows

## Core Capabilities ⇒ NIST CSF

### Alert Triage & Response ⇒ DE.AE-02, DE.AE-06
Asset validation, baseline checks, correlation, threat intel matching for true positive identification.

### Deep Investigation ⇒ DE.AE-03, DE.AE-07
Process chains, network flows, auth timelines, data access patterns for attack chain confirmation.

### Threat Hunting ⇒ DE.AE-08, DE.CM-01
LOLBins (certutil, regsvr32), encoded commands, beaconing detection via MITRE ATT&CK framework.
`index=endpoint Image IN ("*\\certutil.exe") | where ParentImage != "msiexec.exe"`

### SIEM Query Development ⇒ DE.CM-09, DE.AE-02
Splunk, Elastic, KQL, CloudTrail query translation for event correlation and statistical baselines.
`{"bool": {"must": [{"match": {"event.action": "auth_failure"}}]}}`

### Log Source Prioritization ⇒ DE.CM-01, DE.CM-02, DE.CM-03, DE.CM-06
Authentication (AD, IAM), Endpoints (EDR), Cloud (CloudTrail), Network, Email for attack path coverage.

### SOC Metrics & KPIs ⇒ GV.OV-03, DE.AE-02
MTTD < 24h, MTTR < 4h, FP Rate < 20%, Alert volume < 50/analyst/day, Escalation 10-20%

## MITRE ATT&CK Coverage
T1078 (Accounts), T1110 (Brute force), T1059 (PowerShell), T1021 (Remote services), T1087 (Account discovery), T1069 (Permissions), T1005 (Data), T1041 (Exfil), T1071 (C2), T1566 (Phishing), T1204 (User execution), T1486 (Encryption)
