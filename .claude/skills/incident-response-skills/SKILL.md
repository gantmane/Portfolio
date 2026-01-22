---
name: incident-response-skills
description: Incident response expertise for security incident handling, forensic analysis, containment, eradication, and recovery. Use when responding to security incidents, performing forensics, or developing IR procedures.
allowed-tools: Read, Grep, Glob, Bash(subset:*)
nist_csf_function: RESPOND
nist_csf_categories: [RS.MA-01, RS.MA-02, RS.MA-03, RS.AN-03, RS.AN-06, RS.AN-07, RS.AN-08, RS.CO-02, RS.MI-01, RS.MI-02]
mitre_attack_coverage: [T1486, T1078, T1059, T1041, T1071, T1003, T1105, T1027]
---

# Incident Response Skills

> **NIST CSF 2.0 Alignment**: RESPOND Function
> Supports incident handling, forensic analysis, containment, eradication, and recovery operations

## Quick Reference

**Query MASTER_CONTENT_INDEX.json for:**
- "incident response" → Playbooks and procedures
- "forensics" → Evidence collection and analysis
- "containment" → Isolation strategies

**ISP Documentation:**
- Incident Response: `/DevSecOps/incident-response/`
- Detection Rules: `/DevSecOps/detection-rules/`

**Implementation:**
- Playbooks: `/DevSecOps/incident-response/playbooks/`
- Forensic Tools: `/DevSecOps/tools/forensics/`

## Core Capabilities ⇒ [NIST CSF Category]

### Incident Classification ⇒ RS.MA-01

Severity-based response prioritization with defined SLAs and escalation paths.

**Severity Levels:**
- **P1 Critical** (15 min): Active breach, ransomware, data exfil
- **P2 High** (1 hour): Confirmed compromise, malware
- **P3 Medium** (4 hours): Suspicious activity, policy violation
- **P4 Low** (24 hours): Failed attack attempts

**Key Techniques:**
- Triage assessment → Rapid impact analysis
- Stakeholder notification → RS.CO-02 communication
- Resource allocation → RS.MA-03 team coordination

**Reference:** `/DevSecOps/incident-response/classification.yaml`

### Incident Response Playbooks ⇒ RS.MA-01, RS.AN-03

Scenario-specific response procedures for common attack patterns.

**Key Playbooks:**
- **Ransomware** → T1486 response (isolate, preserve evidence, restore from backup)
- **Compromised Credentials** → T1078 response (disable accounts, rotate keys, audit activity)
- **Data Breach** → RS.CO-02 (contain exfiltration, assess impact, regulatory notification)

**Tools & Commands:**
```bash
# Isolate compromised instance
aws ec2 modify-instance-attribute --instance-id i-xxx --groups sg-quarantine

# Snapshot for forensics
aws ec2 create-snapshot --volume-id vol-xxx --description "IR-Evidence-$(date +%Y%m%d)"
```

**Reference:** `/DevSecOps/incident-response/playbooks/`

### Containment Strategies ⇒ RS.MI-01

Network, endpoint, and cloud isolation techniques to limit incident scope.

**Key Techniques:**
- Network isolation → Firewall rules, security group modifications
- Account disablement → Revoke sessions, rotate credentials
- C2 blocking → DNS firewall, Route53 resolver rules

**Tools & Commands:**
```bash
# Block C2 domain
aws route53resolver create-firewall-rule --action BLOCK --name "Block-C2-Domain"

# Deactivate access keys
aws iam update-access-key --access-key-id AKIA... --status Inactive
```

**Reference:** `/DevSecOps/incident-response/containment/`

### Digital Forensics ⇒ RS.AN-03

Evidence preservation and analysis following order of volatility.

**Key Techniques:**
- **Memory** → RAM dump, process analysis (most volatile)
- **Network** → Active connections, traffic capture
- **Disk** → Forensic imaging with hash verification
- **Logs** → CloudTrail, system logs, application logs

**Tools & Commands:**
```bash
# Memory acquisition
avml /evidence/memory.lime

# Disk imaging with verification
dc3dd if=/dev/sda of=/evidence/disk.img hash=sha256

# CloudTrail investigation
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user
```

**Reference:** `/DevSecOps/forensics/`

### Investigation Queries ⇒ RS.AN-06

SIEM and log analysis queries for threat hunting and root cause analysis.

**Key Techniques:**
- Failed auth spikes → T1110 brute force detection
- Lateral movement → T1021 detection (unusual authentication patterns)
- Data exfiltration → T1041 detection (abnormal outbound traffic)
- IAM changes → T1098 detection (privilege escalation)

**Tools & Commands:**
```sql
-- Suspicious IAM activity (Athena)
SELECT eventTime, userIdentity.arn, eventName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName IN ('CreateUser', 'CreateAccessKey', 'AttachUserPolicy')
AND eventTime > current_timestamp - interval '24' hour
```

**Reference:** `/DevSecOps/detection-rules/queries/`

### Post-Incident Activities ⇒ RS.IM-01, RS.IM-02

Lessons learned, root cause analysis, and continuous improvement.

**Key Techniques:**
- **Timeline reconstruction** → RS.AN-06 (complete incident chronology)
- **Root cause analysis** → RS.AN-07 (identify attack vector and failures)
- **Action items** → RS.IM-02 (detection improvements, control enhancements)
- **Playbook updates** → RS.IM-02 (incorporate lessons learned)

**Communication:**
- Internal updates → RS.CO-02 (stakeholder briefings)
- External notifications → GV.OC-01 (regulatory compliance)
- Post-mortem → RS.IM-01 (what worked, what didn't)

**Reference:** `/DevSecOps/incident-response/post-incident/`

## MITRE ATT&CK Coverage

This skill addresses response to:
- **T1486**: Data Encrypted for Impact (Ransomware)
- **T1078**: Valid Accounts
- **T1059**: Command and Scripting Interpreter
- **T1041**: Exfiltration Over C2 Channel
- **T1071**: Application Layer Protocol
- **T1003**: OS Credential Dumping
- **T1105**: Ingress Tool Transfer
- **T1027**: Obfuscated Files or Information

## Related Documentation

- NIST IR Framework: `/DevSecOps/frameworks/nist-ir/`
- SANS Incident Response: `/DevSecOps/frameworks/sans-ir/`
- Cloud Forensics: `/DevSecOps/forensics/cloud/`
