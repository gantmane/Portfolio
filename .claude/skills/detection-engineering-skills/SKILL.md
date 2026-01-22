---
name: detection-engineering-skills
description: Detection engineering expertise for Sigma rules, SIEM queries, MITRE ATT&CK coverage, and adversary emulation testing for developing detection rules and building security monitoring capabilities.
allowed-tools: Read, Grep, Glob, Bash(subset:*)
nist_csf_function: DETECT
nist_csf_categories: [DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-03, DE.AE-06, DE.AE-08]
mitre_attack_coverage: [T1059, T1078, T1566, T1486, T1003, T1110, T1021, T1071, T1041, T1053, T1547]
---

# Detection Engineering Skills

> **NIST CSF 2.0 Alignment**: DETECT
> Supports detection rule development, MITRE ATT&CK coverage, and security monitoring

## Quick Reference
**Index:** "sigma-rules", "siem-queries", "mitre-attack", "detection-patterns" | **Docs:** `/DevSecOps/detection-rules/{policies,sigma,terragrunt}`

## Core Capabilities

### Sigma Rules Development ⇒ DE.AE-02
Standardized YAML detection rules with selection conditions, modifiers (contains, endswith, regex, base64offset), cross-platform conversion.
```bash
sigma convert -t splunk rule.yml
sigma check detections/sigma/
sigma convert -t elasticsearch rule.yml -o query.json
```
**Reference:** `/DevSecOps/detection-rules/sigma/`

### SIEM Query Languages ⇒ DE.CM-09
Splunk SPL, Elastic DSL, Sentinel KQL, CloudTrail/Athena for event correlation, statistical baselines, and time-window analysis.
```bash
index=auth EventCode=4625 | stats count by src_ip, user | where count > 10
DeviceProcessEvents | where ProcessCommandLine contains "-enc"
```
**Reference:** `/DevSecOps/detection-rules/queries/`

### MITRE ATT&CK Coverage ⇒ DE.AE-08
80+ techniques mapped across 11 tactics (execution, persistence, defense evasion) with 60-80% coverage via threat intelligence prioritization.
**Reference:** `/DevSecOps/detection-rules/coverage/mitre-attack-coverage.json`

### Behavior-Based Detection ⇒ DE.AE-02
Process chains (Office→Cmd→PowerShell), mass file modifications, C2 beaconing, and LOLBin abuse detection via behavioral indicators.
**Reference:** `/DevSecOps/detection-rules/patterns/behavior/`

### Anomaly-Based Detection ⇒ DE.AE-03
User behavior profiling, network traffic outliers, time-based anomalies (off-hours, impossible travel), and first-occurrence detection.
**Reference:** `/DevSecOps/detection-rules/patterns/anomaly/`

### Detection Testing & Validation ⇒ RS.AN-06, DE.AE-08
Atomic Red Team execution, CI/CD validation, multi-platform conversion testing, TPR/FPR/latency metrics tracking.
```bash
Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3
sigma check detections/sigma/ && pip install sigma-cli
```
**Reference:** `/DevSecOps/detection-rules/tests/`, `/DevSecOps/detection-rules/workflows/`

## MITRE ATT&CK Coverage
T1059 (Process creation), T1078 (Auth logs), T1566 (Email), T1486 (Encryption), T1003 (Credentials), T1110 (Brute force), T1021 (Remote services), T1071 (C2), T1041 (Exfil), T1053 (Tasks), T1547 (Autostart)

## References
Sigma: https://github.com/SigmaHQ/sigma | ATT&CK: https://attack.mitre.org/ | Atomic: https://github.com/redcanaryco/atomic-red-team | NIST: https://csrc.nist.gov/projects/cybersecurity-framework
