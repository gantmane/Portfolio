---
name: red-team-skills
description: Offensive security expertise for penetration testing, adversary emulation, MITRE ATT&CK techniques, and ethical hacking. Use when planning security assessments, understanding attack techniques, or reviewing defensive controls. For authorized testing only.
allowed-tools: Read, Grep, Glob, Bash(subset:*)
nist_csf_function: RESPOND
nist_csf_categories: [RS.AN-03, RS.AN-06, ID.RA-01, ID.RA-02, ID.RA-03, DE.AE-08]
mitre_attack_coverage: [T1595, T1592, T1589, T1590, T1591, T1566, T1190, T1133, T1078, T1195, T1059, T1203, T1204, T1547, T1053, T1136, T1505, T1068, T1548, T1003, T1110, T1558, T1557, T1021, T1550]
---

# Red Team & Offensive Security Skills

> **NIST CSF 2.0 Alignment**: RESPOND & IDENTIFY Functions
> Supports security validation through adversary emulation and vulnerability identification

**IMPORTANT**: All techniques are for authorized security testing, CTF competitions, and educational purposes only.

## Quick Reference

**Query MASTER_CONTENT_INDEX.json for:**
- "penetration testing" → Methodology, tools, reporting
- "MITRE ATT&CK" → Adversary tactics and techniques
- "adversary emulation" → Purple team exercises

**ISP Documentation:**
- Red Team Playbooks: `/DevSecOps/red-team/playbooks/`
- Detection Rules: `/DevSecOps/detection-rules/`

**Implementation:**
- Attack Scenarios: `/DevSecOps/red-team/scenarios/`
- Purple Team Exercises: `/DevSecOps/red-team/purple-team/`

## Core Capabilities ⇒ [NIST CSF Category]

### MITRE ATT&CK Techniques ⇒ ID.RA-01, ID.RA-03

Adversary tactics mapped to defensive controls for security validation.

**Initial Access (TA0001):**
- **T1566** Phishing → Defense: Email gateway, MFA (PR.AT-01)
- **T1190** Exploit Public App → Defense: WAF, patching (PR.PS-02)
- **T1078** Valid Accounts → Defense: MFA, monitoring (PR.AA-01, DE.CM-01)
- **T1195** Supply Chain → Defense: SCA, SBOM (ID.RA-01)

**Execution (TA0002):**
- **T1059** Command/Scripting → Defense: EDR, logging (DE.CM-01)
- **T1204** User Execution → Defense: Training, EDR (PR.AT-01)

**Persistence (TA0003):**
- **T1547** Boot/Logon → Defense: Registry monitoring (DE.CM-01)
- **T1053** Scheduled Task → Defense: Task auditing (DE.CM-01)
- **T1505** Web Shell → Defense: File integrity (DE.CM-03)

**Privilege Escalation (TA0004):**
- **T1068** Exploitation → Defense: Patching, EDR (PR.PS-02)
- **T1548** Sudo/SUID abuse → Defense: Config audit (PR.PS-01)

**Credential Access (TA0006):**
- **T1003** Credential Dumping → Defense: Credential Guard (PR.DS-01)
- **T1110** Brute Force → Defense: Rate limiting, lockout (PR.IR-01)
- **T1558** Kerberoasting → Defense: Honey accounts (DE.CM-01)

**Lateral Movement (TA0008):**
- **T1021** Remote Services → Defense: Network segmentation (PR.IR-01)
- **T1550** Pass-the-Hash → Defense: Credential hygiene (PR.AA-01)

**Reference:** `/DevSecOps/red-team/mitre-attack-mapping.yaml`

### Reconnaissance & Enumeration ⇒ T1595, T1592

Information gathering for attack surface identification.

**Key Techniques:**
- **Network scanning** → nmap, masscan (T1595)
- **Web enumeration** → gobuster, ffuf (T1595.002)
- **Subdomain discovery** → amass, subfinder (T1590)
- **OSINT** → theHarvester, LinkedIn, GitHub (T1589)

**Tools & Commands:**
```bash
# Network service discovery
nmap -sC -sV -oA scan target.com

# Web directory enumeration
gobuster dir -u https://target.com -w wordlist.txt

# Subdomain enumeration
amass enum -d target.com
```

**Reference:** `/DevSecOps/red-team/reconnaissance/`

### Exploitation ⇒ T1190, ID.RA-01

Vulnerability exploitation for security assessment.

**Key Techniques:**
- **Web application** → SQL injection (sqlmap), XSS, SSRF
- **API testing** → Authentication bypass, authorization flaws
- **Active Directory** → Kerberoasting, AS-REP roasting, BloodHound
- **Cloud misconfigurations** → Public S3 buckets, IAM overpermissions

**Tools & Commands:**
```bash
# SQL injection testing
sqlmap -u "https://target.com/page?id=1" --batch --dbs

# Active Directory enumeration
bloodhound-python -d domain.local -u user -p pass -c all

# Kerberoasting
GetUserSPNs.py domain.local/user:pass -request
```

**Reference:** `/DevSecOps/red-team/exploitation/`

### Cloud Attack Paths ⇒ ID.RA-03

AWS, Azure, GCP security assessment methodologies.

**AWS Attack Chain:**
1. Exposed S3 bucket → T1530 (Data from Cloud Storage)
2. Leaked credentials → T1552 (Unsecured Credentials)
3. IAM enumeration → T1087.004 (Cloud Account Discovery)
4. Privilege escalation → T1078.004 (Cloud Accounts)
5. EC2 IMDS access → T1552.005 (Cloud Instance Metadata)
6. Lateral movement → T1021 (Remote Services)

**Defense Mapping:**
- Step 1: PR.DS-05 (S3 bucket policies, block public access)
- Step 2: PR.DS-01 (Secrets Manager, no hardcoded keys)
- Step 3: PR.AA-05 (Least privilege IAM)
- Step 4: ID.RA-01 (IAM Access Analyzer)
- Step 5: PR.PS-01 (IMDSv2 required)
- Step 6: PR.IR-01 (Network segmentation, security groups)

**Tools & Commands:**
```bash
# AWS enumeration
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name user

# Cloud security assessment
prowler -c check11,check12,check13
ScoutSuite -p aws
```

**Reference:** `/DevSecOps/red-team/cloud-attacks/`

### Adversary Emulation ⇒ RS.AN-06, DE.AE-08

Purple team exercises for detection validation.

**Key Techniques:**
- **Attack simulation** → Atomic Red Team, Caldera, Metasploit
- **Detection validation** → Verify SIEM alerts trigger (DE.AE-08)
- **Purple team coordination** → Document expected detections
- **MTTD measurement** → Mean time to detect < 30 minutes (GV.OV-03)

**Purple Team Exercise Structure:**
1. **Scenario definition** → APT29 emulation, ransomware simulation
2. **Expected detections** → List all alerts that should fire
3. **Execution** → Controlled attack simulation
4. **Analysis** → Detection gaps, false positives/negatives
5. **Remediation** → Tune alerts, improve coverage

**Tools & Commands:**
```powershell
# Atomic Red Team execution
Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3

# List available tests
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# Cleanup
Invoke-AtomicTest T1059.001 -Cleanup
```

**Reference:** `/DevSecOps/red-team/purple-team/`

### Penetration Testing Methodology ⇒ ID.RA-01

Structured approach to security assessment.

**OWASP Testing Guide:**
1. Information Gathering → T1595
2. Configuration Testing → PR.PS-01
3. Authentication Testing → PR.AA-01
4. Authorization Testing → PR.AA-05
5. Input Validation → PR.DS-02
6. Cryptography Testing → PR.DS-01
7. Business Logic → PR.PS-01

**Network Penetration Testing:**
1. Reconnaissance (OSINT, scanning) → T1595
2. Enumeration (services, users) → T1087
3. Vulnerability Analysis → ID.RA-01
4. Exploitation → ID.RA-03
5. Post-Exploitation → RS.AN-03
6. Lateral Movement → T1021
7. Reporting → GV.OC-04

**Reference:** `/DevSecOps/red-team/methodology/`

### Security Assessment Reporting ⇒ RS.AN-03, GV.OC-04

Structured finding documentation with remediation guidance.

**Finding Template:**
- **CVSS Score** → Risk quantification
- **MITRE ATT&CK** → Attack technique mapping
- **NIST CSF Gap** → Control deficiency identification
- **Proof of Concept** → Demonstrate exploitability
- **Impact Analysis** → RS.AN-03 (business impact)
- **Remediation** → Specific, actionable recommendations with NIST CSF mapping

**Report Structure:**
- Executive Summary → GV.OC-04 (risk communication)
- Methodology → Tools, approach, limitations
- Findings → Critical/High/Medium/Low/Info
- Attack Narrative → RS.AN-03 (complete attack chain)
- NIST CSF Gap Analysis → ID.RA-06 (control recommendations)
- MITRE ATT&CK Coverage Matrix → Detection opportunities

**Reference:** `/DevSecOps/red-team/reporting/`

### Defensive Recommendations ⇒ ID.RA-06

Every attack technique must map to defensive control.

**Attack-to-Defense Mapping:**
- **Phishing** → Email filtering, user training, MFA (PR.AT-01, PR.AA-01)
- **Credential stuffing** → Rate limiting, MFA, monitoring (PR.IR-01, DE.CM-01)
- **SQL injection** → Parameterized queries, WAF (PR.DS-01, PR.IR-04)
- **Privilege escalation** → Least privilege, patching (PR.AA-05, PR.PS-02)
- **Lateral movement** → Segmentation, PAM (PR.IR-01, PR.AA-05)
- **Data exfiltration** → DLP, network monitoring (PR.DS-05, DE.CM-02)

**Reference:** `/DevSecOps/red-team/defensive-mapping.yaml`

## MITRE ATT&CK Coverage

This skill provides assessment capabilities for:
- **Reconnaissance**: T1595, T1592, T1589, T1590, T1591
- **Initial Access**: T1566, T1190, T1133, T1078, T1195
- **Execution**: T1059, T1203, T1204
- **Persistence**: T1547, T1053, T1136, T1505
- **Privilege Escalation**: T1068, T1548
- **Credential Access**: T1003, T1110, T1558, T1557
- **Lateral Movement**: T1021, T1550

## Related Documentation

- MITRE ATT&CK Framework: `/DevSecOps/frameworks/mitre-attack/`
- Penetration Testing Guide: `/DevSecOps/red-team/pentesting-guide.md`
- Purple Team Playbooks: `/DevSecOps/red-team/purple-team/`
