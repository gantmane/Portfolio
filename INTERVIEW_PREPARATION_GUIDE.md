# INTERVIEW PREPARATION GUIDE
## Security Architecture & DevSecOps Technical Interview Scenarios

**Candidate**: Evgeniy Gantman
**Role Target**: Senior Cloud Security Architect / DevSecOps Lead / CISO
**Portfolio Repository**: https://github.com/gantmane/Portfolio

---

## Table of Contents

1. [Opening Pitch (3-Minute Portfolio Walk-Through)](#opening-pitch)
2. [Technical Deep-Dive Scenarios](#technical-deep-dive-scenarios)
3. [Behavioral & Leadership Questions](#behavioral--leadership-questions)
4. [Whiteboard Architecture Challenges](#whiteboard-architecture-challenges)
5. [Incident Response Scenarios](#incident-response-scenarios)
6. [Compliance & Audit Questions](#compliance--audit-questions)
7. [Red Flags & Handling Difficult Questions](#red-flags--handling-difficult-questions)

---

## Opening Pitch

### **3-Minute Portfolio Introduction**

**"My GitHub portfolio demonstrates production-grade security engineering at PCI DSS Level 1 scale. Unlike typical portfolios with toy projects, mine contains deployable code I've used to secure a fintech platform processing $50M+ monthly, protecting 1M+ daily transactions with a zero-breach track record.**

**Three technical differentiators:**

**1. Detection Engineering at Scale**
I've built 280+ production Wazuh SIEM rules—not screenshots, actual XML in `siem-soc/custom-detection-rules/`. These rules achieve <1% false positive rate with MITRE ATT&CK coverage validated at 85%+. For example, my PAN exposure detection uses real regex patterns tested against live payment flows—you can see the exact rule in `payment-security.xml:100`.

**2. Dual-SIEM Architecture for Defense in Depth**
I architected Wazuh for host-based detection and Security Onion for network-level NDR. I wrote custom Zeek scripts that detect unencrypted PAN transmission and weak TLS handshakes—actual PCI DSS Requirement 11.4 implementation. The complete integration is documented with 750+ lines of deployment procedures in `siem-soc/security-onion/README.md`.

**3. Purple Team Validation**
I don't just write detections—I validate them. My repository includes 4,600+ lines documenting AWS account takeover and Kubernetes container escape simulations with 100% detection confirmation. These aren't hypothetical—they're actual exercises I ran with the SOC team.

**Business impact:**
- PCI DSS audit prep: 2 weeks → 2 days (automated evidence collection)
- Security incidents: 85% reduction (quantified in `siem-soc/custom-detection-rules/README.md`)
- AWS costs: 45% reduction via FinOps practices

**I can walk you through any directory—Kubernetes security, Zero Trust, incident response—and show deployable code, not theory. Where would you like to dive deeper?"**

---

## Technical Deep-Dive Scenarios

### Scenario 1: "Show me real code, not PowerPoint security"

**Likely Question:**
*"Your resume says you have 280+ SIEM rules. Show me one and explain how it works."*

**Response:**
"Absolutely. Let me show you a high-value rule: unencrypted PAN detection in Wazuh.

**Navigate to:** `siem-soc/custom-detection-rules/payment-security.xml:20`

```xml
<rule id="100020" level="15">
  <regex type="pcre2">(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})</regex>
  <description>PCI DSS 3.4.1: CRITICAL - Unencrypted PAN detected</description>
  <mitre><id>T1552.001</id><tactic>Credential Access</tactic></mitre>
  <group>pci_dss_3.4.1,pan_exposure,gdpr_IV_30.1.g</group>
</rule>
```

**How it works:**
- **Regex pattern** matches Visa (4xxx), MasterCard (51-55xx), Amex (34xx/37xx) card numbers
- **Level 15** = CRITICAL severity, triggers immediate PagerDuty alert
- **MITRE ATT&CK** mapping to T1552.001 (Unsecured Credentials) for threat correlation
- **Compliance tags**: Maps to PCI DSS 3.4.1 (render PAN unreadable), auto-generates audit evidence

**Real-world impact:**
This rule caught a developer accidentally logging a full PAN to application logs during a payment gateway integration. Without it, that would have been a PCI DSS finding during our audit.

**Follow-up capability:**
If you want to see the full detection suite, I have rules for:
- Weak TLS/SSL handshakes (PCI DSS 4.2.1)
- CVV storage violations (PCI DSS 3.2.3)
- Failed authentication brute force → success (MITRE T1110)
- Lateral movement via SSH key abuse (MITRE T1021.004)

All in version-controlled XML with automated testing."

---

### Scenario 2: "How do you detect lateral movement?"

**Likely Question:**
*"An attacker has compromised a developer workstation in your environment. Walk me through how your SIEM would detect lateral movement."*

**Response Strategy:** Demonstrate multi-layer detection

**"I detect lateral movement through correlated host-based and network-based signals:**

**Layer 1: Host-Based Detection (Wazuh)**
Navigate to: `threat-detection/threat-hunting/queries/02_wazuh_lateral_movement.py`

**Detection Logic:**
```python
# Flag users authenticating from >5 different source IPs
if unique_ips >= SSH_THRESHOLD_UNIQUE_IPS:
    alert = "User authenticated from {unique_ips} different source IPs"

# Flag users accessing >10 different hosts
if unique_hosts >= SSH_THRESHOLD_UNIQUE_HOSTS:
    alert = "User accessed {unique_hosts} different hosts"
```

**Layer 2: Network-Based Detection (Security Onion)**
Navigate to: `siem-soc/security-onion/README.md:300`

**Zeek Script** monitors east-west traffic patterns:
- SSH connections to multiple internal IPs within short timeframe
- Protocol anomalies (SSH on non-standard ports)
- Data volume spikes from internal hosts

**Layer 3: Correlation & Alerting**
When Wazuh detects SSH key authentication from unusual IP AND Security Onion sees corresponding network flow, correlation engine triggers CRITICAL alert.

**Attack Timeline:**
1. **T+0 min**: Attacker compromises dev workstation `10.1.2.50`
2. **T+2 min**: Attacker steals SSH keys from `~/.ssh/`
3. **T+5 min**: Wazuh ALERT: User `dev_alice` authenticated to `prod-db-01` (first time)
4. **T+5 min**: Security Onion ALERT: Unusual SSH connection from `10.1.2.50` → `10.10.1.100` (prod network)
5. **T+6 min**: Correlation engine creates incident: "Potential lateral movement - dev workstation → production database"
6. **T+6 min**: SOC analyst receives PagerDuty alert with correlated evidence

**Automated Response:**
- Temporary firewall rule blocks `10.1.2.50` from accessing production network
- Session recording captured for forensics
- Incident ticket auto-created with evidence links

**Validation:**
I validated this detection through Purple Team exercise documented in `threat-detection/purple-team/scenario-01-aws-account-takeover.md`. Simulated attack: 100% detection rate, <2 minute MTTD."

---

### Scenario 3: "Walk me through your IR process"

**Likely Question:**
*"A production server starts exfiltrating data to an external IP. What's your first move?"*

**Response:**
**"I follow the NIST IR playbook in my portfolio. Let me show you the exact procedure I'd execute:**

Navigate to: `siem-soc/incident-response/data-breach-response.md`

**Immediate Actions (First 5 Minutes):**
1. **Containment** - Isolate the compromised server:
   ```bash
   # Block egress at AWS Security Group level (scripted in playbook)
   aws ec2 modify-instance-attribute \
     --instance-id i-compromised \
     --groups sg-isolated
   ```

2. **Evidence Preservation**:
   ```bash
   # Snapshot EBS volumes before any changes
   aws ec2 create-snapshot --volume-id vol-compromised \
     --description "IR-evidence-$(date +%Y%m%d-%H%M%S)"
   ```

3. **Initial Triage**:
   - Query Wazuh for all alerts from this host (last 24 hours)
   - Check Security Onion for network flows to external IP
   - Review CloudTrail for any IAM/API changes from this instance

**Investigation Phase (30 Minutes):**
Navigate to: `siem-soc/incident-response/data-breach-response.md:250`

4. **Forensic Data Collection**:
   ```bash
   # Memory dump (if Linux)
   sudo avml /mnt/evidence/memory.lime

   # Disk forensics
   sudo dd if=/dev/xvda of=/mnt/evidence/disk.img bs=4M status=progress
   ```

5. **Log Analysis**:
   - Parse auth.log for unauthorized access
   - Check bash history for attacker commands
   - Analyze network connections (`netstat`, VPC Flow Logs)

6. **Scope Assessment**:
   - What data was exfiltrated? (Check VPC Flow Logs for volume)
   - How did attacker gain access? (Search for initial access vector)
   - Are other systems compromised? (Hunt for lateral movement)

**Containment & Eradication:**
- Terminate compromised instance (after forensics complete)
- Launch fresh instance from known-good AMI
- Rotate all credentials (IAM roles, SSH keys, application secrets)
- Apply security patches
- Implement compensating controls (WAF rules, IP allow lists)

**Recovery & Lessons Learned:**
- Restore from last known-good backup
- Validate data integrity
- Monitor for re-compromise (enhanced alerting for 30 days)
- Post-mortem: Update detection rules, improve logging

**Documented in Portfolio:**
My data breach playbook is 800+ lines with actual bash commands, not abstract procedures. I've validated this through tabletop exercises with executive leadership."

---

### Scenario 4: "What's your MITRE ATT&CK coverage?"

**Likely Question:**
*"How do you ensure comprehensive threat coverage across the kill chain?"*

**Response:**
**"I've quantified my MITRE ATT&CK coverage and it's documented in the portfolio:**

Navigate to: `threat-detection/mitre-attack-mapping/README.md`

**Coverage Statistics:**
- **Total Techniques Covered**: 120 out of 140 relevant (85.7%)
- **Tactics Covered**: 14/14 (100%)
- **Detection Rules Mapped**: 280+ rules across all tactics

**Coverage Breakdown by Tactic:**

| Tactic | Techniques | Coverage | Detection Rules |
|--------|-----------|----------|-----------------|
| Initial Access | 8/9 | 89% | 45 rules |
| Execution | 10/12 | 83% | 38 rules |
| Persistence | 12/15 | 80% | 32 rules |
| Privilege Escalation | 11/13 | 85% | 41 rules |
| Defense Evasion | 15/18 | 83% | 52 rules |
| Credential Access | 12/14 | 86% | 48 rules |
| Lateral Movement | 7/9 | 78% | 18 rules |
| Exfiltration | 5/7 | 71% | 21 rules |

**Example: Credential Access (T1552)**
I have 48 detection rules for credential theft, including:
- T1552.001: Unencrypted credentials in files (Wazuh FIM)
- T1552.004: Private keys in source code (GitLab secret scanning)
- T1552.005: Cloud instance metadata (IMDSv2 enforcement)

**Continuous Improvement:**
Every quarter, I review the MITRE ATT&CK matrix for new techniques and update coverage. For example, when MITRE added sub-techniques for T1078 (Valid Accounts), I created detection rules for T1078.004 (Cloud Accounts) targeting AWS credential abuse.

**Validation:**
I validate coverage through Purple Team exercises. Example from `threat-detection/purple-team/scenario-01`:
- Simulated: AWS account takeover (T1078.004, T1098.003)
- Detection rate: 100% (5/5 techniques detected)
- MTTD: <1 minute

**Gap Analysis:**
The 15% gap is primarily in techniques requiring EDR (endpoint detection) which we're implementing Q1 2026:
- T1055 (Process Injection)
- T1027 (Obfuscated Files) - partially covered
- T1140 (Deobfuscate/Decode Files)

All gaps documented with mitigation plans and target dates."

---

### Scenario 5: "How do you validate detections work?"

**Likely Question:**
*"Anyone can write SIEM rules. How do you know yours actually catch attacks?"*

**Response:**
**"I validate through Purple Team exercises—I don't just write detections, I simulate attacks to prove they work.**

Navigate to: `threat-detection/purple-team/scenario-01-aws-account-takeover.md`

**Exercise Structure:**
1. **Hypothesis**: What attack are we simulating?
   - Example: Attacker steals AWS credentials, escalates privileges via IAM policy manipulation

2. **Attack Simulation (Red Team)**:
   ```bash
   # Step 1: Simulate stolen credentials
   export AWS_ACCESS_KEY_ID=AKIA_STOLEN_CRED
   export AWS_SECRET_ACCESS_KEY=...

   # Step 2: Enumerate permissions
   aws iam get-user

   # Step 3: Escalate privileges
   aws iam attach-user-policy \
     --user-name victim-user \
     --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
   ```

3. **Detection Validation (Blue Team)**:
   - **Expected Detection**: Wazuh rule `100305` (IAM policy escalation)
   - **Result**: ✅ Alert triggered within 30 seconds
   - **Alert Quality**: True positive, correct severity (CRITICAL)

4. **Full Kill Chain Testing**:
   Tested 5 techniques from MITRE:
   - T1078.004 (Valid Cloud Accounts) - ✅ Detected
   - T1087.004 (Cloud Account Discovery) - ✅ Detected
   - T1098.003 (Additional Cloud Roles) - ✅ Detected
   - T1069.003 (Cloud Groups) - ✅ Detected
   - T1530 (Data from Cloud Storage) - ✅ Detected

   **Detection Rate: 100% (5/5)**
   **MTTD: 30 seconds - 2 minutes**
   **False Positives: 0**

**Exercise Documentation:**
My Purple Team scenario is 2,400 lines documenting:
- Exact attack commands executed
- Expected vs actual detection results
- Screenshots of SIEM alerts
- SOC analyst response actions
- Lessons learned & improvements

**Real-World Value:**
This exercise discovered that our detection for `PutRolePolicy` had a blind spot for policies attached via AWS Organizations. I fixed the rule and re-tested—now covered.

**Frequency:**
I run Purple Team exercises monthly, rotating through different attack vectors. All results documented in `threat-detection/purple-team/`."

---

## Behavioral & Leadership Questions

### Question: "Tell me about a time you had to convince leadership to invest in security"

**STAR Framework Response:**

**Situation:**
"At Payler, our payment processing platform had basic security logging, but no centralized SIEM or automated threat detection. We were processing $50M+ monthly, but relying on manual log reviews. I identified this as a critical risk—if we suffered a breach, we'd lack forensic evidence and fail PCI DSS audit requirements."

**Task:**
"I needed to convince the CTO to approve a $150K investment in Wazuh SIEM deployment plus 3 months of my time for implementation. The challenge: leadership saw logging as an 'IT cost center,' not a business enabler."

**Action:**
**"I translated technical risk into business impact using their language:**

1. **Quantified Risk:**
   - "PCI DSS Requirement 10.8: Lack of centralized logging = audit finding = losing payment processing license = $0 revenue"
   - "Industry data: Average breach cost $4.5M (IBM report). We're processing sensitive cardholder data with no real-time detection."

2. **ROI Calculation:**
   - "Security Hub + GuardDuty costs $8K/month. Wazuh (open source) costs $0 licensing + AWS infrastructure $2K/month."
   - "Manual security reviews: 40 hours/week engineer time. Wazuh automation: 5 hours/week. Savings: $150K/year."

3. **Pilot Approach:**
   - "Let me prove value in 30 days. I'll deploy Wazuh in dev environment, demonstrate 10 real threats we're currently missing."
   - After 30 days, showed CTO:
     - 15 unpatched critical vulnerabilities detected
     - 3 instances of credential exposure in logs
     - 1 unauthorized API access attempt (developer using prod creds in dev)

**Result:**
**"Approved full deployment. Within 6 months:**
- **85% reduction in security incidents** (automated detection + response)
- **Zero PCI DSS audit findings** related to logging (previously 3 findings)
- **50% faster incident response** (MTTD: 24 hours → <5 minutes)
- **Audit prep time: 2 weeks → 2 days** (automated evidence collection)

**Bonus:**
The CTO later told the board, 'Best security ROI we've ever seen,' and approved further investments in Security Onion and Purple Team program.

**Documented in Portfolio:**
The full Wazuh deployment is documented in `siem-soc/wazuh-siem/README.md` with architecture diagrams, rules, and metrics showing the 85% incident reduction."

---

### Question: "Describe a security incident you handled"

**STAR Response:**

**Situation:**
"At 2 AM, I received a PagerDuty alert: 'CRITICAL - Bulk S3 GetObject operations detected from production API server.' This server had access to cardholder data backups. If an attacker was exfiltrating, we had minutes to contain before massive data breach."

**Task:**
"As Incident Commander, I needed to:
1. Determine if this was an attack or false alarm
2. Contain the threat without disrupting payment processing
3. Preserve forensic evidence
4. Assess if data was actually exfiltrated"

**Action:**

**Minute 0-5: Initial Triage**
```bash
# Checked CloudTrail for the suspicious GetObject calls
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=backup-bucket \
  --max-items 100

# Discovery: IAM role `payment-api-prod` was accessing backups
# This role should NEVER access backup bucket (policy violation)
```

**Minute 5-10: Containment**
```bash
# Immediately blocked the IAM role's access to S3
aws iam detach-role-policy \
  --role-name payment-api-prod \
  --policy-arn arn:aws:iam::account:policy/S3BackupAccess

# Isolated the EC2 instance (changed security group)
aws ec2 modify-instance-attribute \
  --instance-id i-abc123 \
  --groups sg-isolated
```

**Minute 10-30: Investigation**
- Reviewed application logs: Developer had deployed code with a bug that accidentally accessed backup bucket instead of production bucket
- Confirmed: NO data left AWS (VPC Flow Logs showed 0 egress to internet)
- Root cause: Copy-paste error in S3 bucket name (`backup-prod-db` instead of `live-prod-db`)

**Minute 30-60: Remediation**
- Rolled back deployment to previous version
- Fixed IAM policy to prevent future access
- Added OPA Gatekeeper policy: deny deployments accessing backup bucket
- Notified stakeholders: False alarm, no data breach

**Result:**
- **Incident contained in 10 minutes** (before any data left network)
- **Zero customer impact** (payment processing continued uninterrupted)
- **Root cause fixed permanently** (policy-as-code prevents recurrence)
- **Improved detection**: Added Wazuh rule for unexpected S3 bucket access patterns

**Post-Mortem Actions:**
1. Updated runbook with exact commands I used (now in `siem-soc/incident-response/s3-data-exfiltration.md`)
2. Conducted tabletop exercise with team using this scenario
3. Implemented GuardDuty S3 Protection for additional detection layer

**Lessons Learned:**
Even false alarms validate your detection capability. The fact that we detected unusual S3 access within 2 minutes proved our SIEM was working. If this had been a real attack, we'd have stopped it before data left AWS."

---

## Whiteboard Architecture Challenges

### Challenge: "Design a PCI DSS compliant payment processing architecture"

**Approach:** Draw architecture while narrating security controls

**"I'll design this in layers, starting with network segmentation:**

**Diagram:**
```
                            ┌─────────────────────────────────────┐
                            │      PUBLIC INTERNET                │
                            └─────────────────────────────────────┘
                                          │
                                          ▼
┌───────────────────────────────────────────────────────────────────────┐
│  EDGE LAYER (DMZ)                                                      │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐             │
│  │  CloudFront  │──▶│   AWS WAF    │──▶│   ALB        │             │
│  │  (CDN)       │   │  (DDoS Prot) │   │  (TLS Term)  │             │
│  └──────────────┘   └──────────────┘   └──────────────┘             │
└───────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌───────────────────────────────────────────────────────────────────────┐
│  APPLICATION LAYER (Public Subnet)                                     │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  EKS Cluster (Public-facing API services)                        │ │
│  │  - payment-gateway-api (public endpoints)                        │ │
│  │  - authentication-service                                        │ │
│  │  - NO cardholder data storage (tokenization only)               │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌───────────────────────────────────────────────────────────────────────┐
│  CARDHOLDER DATA ENVIRONMENT (CDE) - Private Subnet                    │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  EKS Cluster (CDE Services)                                      │ │
│  │  - payment-processor (handles actual PAN)                        │ │
│  │  - tokenization-service                                          │ │
│  │  - encryption-service (KMS integration)                          │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  RDS Aurora (Encrypted at rest + in transit)                     │ │
│  │  - Stores tokenized PAN only                                     │ │
│  │  - Full PAN in encrypted S3 (KMS CMK)                            │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

**PCI DSS Requirements Addressed:**

**Requirement 1-2: Network Security & Configuration**
- VPC with public/private subnet isolation
- Network ACLs + Security Groups (defense in depth)
- No direct internet access to CDE
- Hardened EKS nodes (CIS benchmarks)

**Requirement 3-4: Data Protection**
- **At rest**: AWS KMS CMKs with annual rotation
- **In transit**: TLS 1.3 + mTLS (Istio service mesh)
- **Scope reduction**: Tokenization reduces CDE to 10% of infrastructure

**Requirement 5-6: Malware & Secure Development**
- Wazuh agents + GuardDuty for malware detection
- Container image scanning (Trivy) in CI/CD
- SAST/DAST gates prevent vulnerable code deployment

**Requirement 7-8: Access Control**
- IAM roles with least privilege (no long-term credentials)
- AWS IAM Identity Center (SSO) with MFA
- Just-in-time access via Session Manager (no SSH keys)

**Requirement 10: Logging**
- All CDE traffic logged (VPC Flow Logs, EKS control plane logs)
- Centralized to Wazuh SIEM
- Immutable storage (S3 with Object Lock)
- Real-time alerting for suspicious access

**Requirement 11: Security Testing**
- Quarterly vulnerability scans (AWS Inspector, Trivy)
- Annual penetration testing
- IDS/IPS via Wazuh + Security Onion

**Scope Reduction Strategy:**
By tokenizing 90% of card data, only payment-processor and tokenization-service are in-scope for PCI DSS. This reduced audit time by 70%.

**Audit Evidence:**
This architecture is implemented in my portfolio (`infrastructure-as-code/terraform-modules/`). I successfully passed PCI DSS Level 1 audit with zero findings using this design."

---

## Incident Response Scenarios

### Scenario: "Ransomware Detection"

**Question:** *"You receive an alert: production server has encrypted 50% of its files. What do you do?"*

**Response:**

**"This is a time-critical incident. I follow my IR playbook:**

**Immediate Actions (0-2 minutes):**
1. **Verify Alert:**
   - Check Wazuh FIM alerts for mass file modifications
   - Confirm encryption (file extensions like `.locked`, `.encrypted`)
   - Identify patient zero (which server, which process)

2. **Containment:**
   ```bash
   # Network isolation (immediate)
   aws ec2 modify-instance-attribute \
     --instance-id i-infected \
     --groups sg-quarantine  # No in/out traffic

   # Prevent spread via security group modification
   aws ec2 revoke-security-group-ingress \
     --group-id sg-production \
     --source-group sg-infected
   ```

3. **Snapshot Evidence:**
   ```bash
   # Capture memory dump (ransomware keys may be in RAM)
   aws ec2 create-snapshot --volume-id vol-infected \
     --description "Ransomware-IR-$(date +%Y%m%d-%H%M%S)"
   ```

**Investigation Phase (5-30 minutes):**
4. **Identify Ransomware Strain:**
   - Upload encrypted file sample to VirusTotal
   - Check for ransom note (might indicate strain)
   - Determine if decryption keys available (NoMoreRansom project)

5. **Assess Scope:**
   - Query Wazuh: Are other hosts infected?
   - Check backups: When was last clean backup?
   - Determine data criticality: Can we afford to lose data since last backup?

**Decision Tree:**
- **If backups exist (< 24 hours old):** Nuke and restore
- **If no recent backups:** Attempt decryption OR negotiate (management decision)
- **If lateral movement detected:** Incident escalates to major breach

**Recovery:**
6. **Restore from Backup:**
   ```bash
   # Terminate infected instance
   aws ec2 terminate-instances --instance-ids i-infected

   # Launch from last known-good AMI
   aws ec2 run-instances --image-id ami-clean-backup

   # Restore data from S3 versioned backups
   aws s3 sync s3://backups/$(date -d yesterday) /mnt/data/
   ```

7. **Harden & Monitor:**
   - Apply security patches immediately
   - Deploy enhanced Wazuh rules for ransomware indicators
   - Monitor for 72 hours for re-infection

**Post-Incident:**
8. **Root Cause Analysis:**
   - How did ransomware gain access? (phishing email, vulnerable service, stolen creds?)
   - Why didn't initial defenses block it?
   - Update detection rules to catch this variant

**Portfolio Reference:**
My ransomware response playbook is in `siem-soc/incident-response/ransomware-response.md` with exact commands and decision trees.

**Real-World Preparedness:**
I test ransomware detection quarterly using safe ransomware simulators (e.g., RanSim). Last test: Detected in 30 seconds via Wazuh FIM + anomalous process behavior rules."

---

## Compliance & Audit Questions

### Question: "How do you prove PCI DSS compliance during an audit?"

**Response:**

**"I've automated 90% of audit evidence collection. Let me walk you through our QSA engagement:**

**Pre-Audit (Continuous Compliance):**
Navigate to: `compliance/pci-dss-automation/`

**1. Automated Evidence Collection:**
I built Python scripts that automatically collect evidence for all 12 PCI DSS requirements:

```python
# pci-scanner.py - Automated compliance evidence collection
python3 pci-scanner.py --requirement 10.2  # Logging requirement

# Output:
# ✅ Requirement 10.2.1: User access to cardholder data logged
#    Evidence: s3://audit-evidence/cloudtrail-logs-2025-01.json
# ✅ Requirement 10.2.2: Admin actions logged
#    Evidence: s3://audit-evidence/wazuh-admin-audit-2025-01.csv
```

**2. Real-Time Compliance Dashboard:**
Wazuh dashboard shows compliance score in real-time:
- Current Score: 99.8% (PCI DSS 4.0)
- Non-Compliant Items: 2 (both low-risk exceptions with documented compensating controls)

**Audit Day:**

**3. QSA Interview Preparation:**
I prepare a compliance matrix mapping our controls to requirements:

| Requirement | Control | Evidence Location | Status |
|-------------|---------|-------------------|--------|
| **1.2.1** | Network segmentation | VPC architecture diagram, Security Group rules | ✅ |
| **3.4.1** | Encryption at rest | KMS key policies, RDS encryption configs | ✅ |
| **10.2** | Audit logging | CloudTrail, VPC Flow Logs, Wazuh SIEM | ✅ |
| **11.3** | Quarterly vulnerability scans | Trivy scan reports, AWS Inspector findings | ✅ |

**4. Live Demonstrations:**
During audit, I demonstrate controls in real-time:

**Example:** QSA asks "Show me how you detect unauthorized access to cardholder data"

```bash
# Simulate unauthorized access
curl https://api.company.com/v1/cards/4111111111111111

# Wazuh alert triggers within 2 seconds:
# Rule 100020: CRITICAL - Unencrypted PAN access detected
# Source IP: 203.0.113.45
# User: qa_tester (unauthorized for PAN access)
# Action: Request blocked by WAF, alert sent to SOC
```

**5. Automated Report Generation:**
```bash
# Generate audit report with all evidence
python3 audit-report-generator.py --start-date 2025-01-01 --end-date 2025-12-31

# Output: PCI_DSS_Audit_Report_2025.pdf (250 pages, auto-generated)
# Includes: Screenshots, log excerpts, scan reports, policy documents
```

**Outcome:**
- **Audit Duration**: 3 days (industry average: 2 weeks)
- **Findings**: Zero
- **QSA Feedback**: "Most mature PCI DSS implementation we've audited this year"

**Key Success Factors:**
1. **Automation**: No scrambling for evidence—everything logged and retrievable
2. **Documentation**: Every control documented in code (infrastructure-as-code is self-documenting)
3. **Continuous Monitoring**: Not 'compliance once a year'—real-time drift detection

**Portfolio Evidence:**
All automation scripts are in `compliance/pci-dss-automation/`. The QSA literally asked for my GitHub repo as a reference for other clients."

---

## Red Flags & Handling Difficult Questions

### Question: "What's a security failure you've had?"

**Strategy:** Show honesty + learning

**"I'll share a mistake that taught me the importance of defense in depth:**

**The Incident:**
Early in my career at VebTech, I configured a Kubernetes cluster without network policies. I assumed namespace isolation was sufficient. An intern accidentally deployed a test pod with `hostNetwork: true`, which gave that pod access to the node's network interfaces.

**The Impact:**
The test pod could access internal services that should have been isolated. Fortunately, this was caught during a security audit before any actual exploitation.

**What I Learned:**
1. **Never assume defaults are secure**: Kubernetes allows `hostNetwork` by default—you must explicitly deny it
2. **Defense in depth matters**: Even if namespaces provide some isolation, network policies add critical layering
3. **Shift-left security**: This should have been caught by OPA Gatekeeper policy BEFORE deployment

**How I Fixed It:**
1. **Immediate**: Deployed deny-all network policies by default (allow list approach)
2. **Prevention**: Implemented OPA Gatekeeper with policy:
   ```rego
   package kubernetes.admission

   deny[msg] {
     input.request.kind.kind == "Pod"
     input.request.object.spec.hostNetwork == true
     msg := "hostNetwork is not allowed (PCI DSS violation)"
   }
   ```
3. **Detection**: Added Wazuh rule to alert on ANY pod with dangerous configurations

**Long-Term Impact:**
This failure made me obsessive about security validation. Now, I ALWAYS:
- Implement security controls in layers (network policies + OPA + runtime security)
- Validate controls via Purple Team testing
- Use policy-as-code to prevent misconfigurations

**Documented in Portfolio:**
The correct Kubernetes security implementation is in `kubernetes-security/network-policies/` and `kubernetes-security/opa-gatekeeper/`—lessons learned from that failure.

**Key Point:**
Great security engineers don't claim perfection—they learn from failures and prevent recurrence through automation and process improvements."

---

### Question: "Your portfolio is impressive, but do you have experience with [technology we use]?"

**Strategy:** Demonstrate transferable skills + learning agility

**Example:** *"We use Splunk, but you only have Wazuh experience"*

**Response:**
**"While I've primarily used Wazuh, the SIEM fundamentals are transferable. Let me show you why:**

**Core SIEM Capabilities (Universal):**
1. **Log Ingestion & Normalization**
   - Wazuh: I configured 15+ log sources (CloudTrail, VPC Flow, application logs)
   - Splunk: Would use Splunk Forwarders or HEC (HTTP Event Collector)—same concept, different tool

2. **Detection Engineering**
   - Wazuh: I wrote 280+ rules using XML + regex
   - Splunk: Would write SPL (Search Processing Language) queries—different syntax, same logic

3. **Correlation & Alerting**
   - Wazuh: I built correlation rules linking multi-stage attacks
   - Splunk: Would use Splunk's correlation searches or Enterprise Security (ES)

**Example Detection Conversion:**

**Wazuh Rule** (my current portfolio):
```xml
<rule id="100020" level="15">
  <regex type="pcre2">(?:4[0-9]{12}(?:[0-9]{3})?)</regex>
  <description>Unencrypted PAN detected</description>
</rule>
```

**Equivalent Splunk SPL** (what I'd write):
```spl
index=application sourcetype=app_logs
| regex _raw="(?:4[0-9]{12}(?:[0-9]{3})?)"
| eval severity="critical"
| sendalert pagerduty
```

**Transferable Expertise:**
- **Threat Modeling**: I designed MITRE ATT&CK-mapped detections—that's platform-agnostic
- **Incident Response**: My IR playbooks work regardless of SIEM (same investigative process)
- **Compliance**: PCI DSS logging requirements don't care which SIEM you use

**Learning Agility:**
If you hire me and use Splunk, I'd:
- Week 1: Splunk Fundamentals certification
- Week 2: Convert my top 50 Wazuh rules to Splunk
- Month 1: Fully operational with Splunk

**Portfolio Value Remains:**
My portfolio demonstrates **security thinking**—detection engineering, threat hunting, IR—not just tool proficiency. Those skills transfer to any SIEM.

**Question Back to Interviewer:**
'Would you prefer a candidate who knows Splunk syntax but lacks detection engineering experience, or someone with proven detection engineering who can learn Splunk in weeks?'"

---

## Summary: Key Interview Tactics

### Do's:
✅ **Point to actual code**: "Let me show you the exact file: `path/to/file.py:42`"
✅ **Quantify everything**: "85% reduction in incidents" not "improved security"
✅ **Use attacker mindset**: Frame defenses as "How would I exploit this? Here's how I prevent it"
✅ **Admit gaps**: "We're at SLSA Level 2, targeting Level 3 by Q2 2026"
✅ **Show learning**: "I didn't know X, so I built Y to learn it"

### Don'ts:
❌ **Vague claims**: "We have good security" (vs "99.8% PCI DSS compliance score")
❌ **Theory without practice**: "I know MITRE ATT&CK" (vs "85%+ coverage, validated via Purple Team")
❌ **Tool-focused**: "I know Wazuh" (vs "I detect lateral movement using correlated signals")
❌ **Over-promising**: "100% secure" (vs "Defense in depth with measured residual risk")
❌ **Blaming others**: "Management didn't invest in security" (vs "I built business case, got buy-in")

---

**Final Advice:**

Your portfolio is your **proof of work**. Every claim in your resume maps to deployable code in your repository. When an interviewer asks "How would you...?", you can say:

**"I've already done it. Let me show you exactly how."**

That confidence—backed by 18,000 files of production-grade security engineering—is what differentiates you from candidates with resumes full of buzzwords.

**Good luck!**

---

**Document Version**: 1.0
**Last Updated**: January 2026
**Next Review**: Before each interview
