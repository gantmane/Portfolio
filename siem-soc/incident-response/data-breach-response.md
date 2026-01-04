# Data Breach Response Playbook

## Incident Overview

**Severity**: P0 - Critical
**Response Time**: Immediate (<15 minutes)
**Escalation**: CISO, CEO, Legal, PCI QSA

### Description
Unauthorized access to or disclosure of cardholder data (PAN, CVV, magnetic stripe data) or other sensitive payment information. This is the highest severity incident due to regulatory, financial, and reputational impact.

### Business Impact
- PCI DSS compliance violation - potential loss of card processing privileges
- Regulatory fines (GDPR: up to €20M or 4% of revenue)
- Legal liability and class-action lawsuits
- Reputational damage and customer trust loss
- Stock price impact for public companies

### MITRE ATT&CK Mapping
- **T1530** - Data from Cloud Storage Object
- **T1552.001** - Credentials from Files
- **T1041** - Exfiltration Over C2 Channel
- **T1048** - Exfiltration Over Alternative Protocol
- **T1567** - Exfiltration to Cloud Storage

### PCI DSS Requirements
- **Requirement 12.10.1** - Implement incident response plan
- **Requirement 12.10.6** - Incident analysis and documentation

## Detection Indicators

### Wazuh Rule IDs
- `100020` - Unencrypted PAN detected in logs (CRITICAL)
- `100021` - Encryption disabled on CDE S3 bucket
- `100334` - Bulk download from sensitive S3 bucket
- `100900` - Unmasked PAN in logs
- `100912` - Bulk detokenization (mass PAN exposure)
- `100962` - Bulk CDE access
- `100970` - Bulk payment database queries

### Log Sources
- **Wazuh SIEM** - Alert ID and correlation
- **AWS CloudTrail** - S3 access, IAM activity
- **Database Audit Logs** - Query history, data access
- **Application Logs** - API access, authentication
- **VPC Flow Logs** - Network egress to external IPs
- **WAF Logs** - Web attack patterns

### Common Indicators
```
- Unusual database query patterns (SELECT * FROM cards/payments)
- Large volume S3 GetObject API calls
- Data exfiltration to external IP/domain
- Bulk detokenization requests
- Unauthorized access to CDE systems
- PAN data appearing in non-CDE logs
- CVV data storage (explicitly prohibited)
- Export of cardholder data to unencrypted medium
```

## Phase 1: Initial Triage (0-15 Minutes)

### Step 1: Confirm and Classify (Minutes 0-5)

**Actions:**
1. **Validate Alert**
   ```bash
   # Review Wazuh alert details
   /var/ossec/bin/wazuh-control info

   # Check alert in OpenSearch Dashboard
   # Navigate to: Discover → Filter by Rule ID

   # Query CloudTrail for related events
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
     --start-time "2025-12-23T00:00:00Z" \
     --max-results 50
   ```

2. **Assess Data Type and Volume**
   - What type of data was accessed? (PAN, CVV, full magnetic stripe, CVV2)
   - How many records potentially compromised?
   - What is the time window of exposure?

3. **Determine Breach Classification**
   - **Confirmed Breach**: Evidence of unauthorized access AND data egress
   - **Suspected Breach**: Unauthorized access detected, exfiltration unclear
   - **Near Miss**: Attack detected and blocked before data access

**Decision Point**: If CONFIRMED or SUSPECTED breach → Proceed to Step 2

### Step 2: Immediate Notification (Minutes 5-10)

**Critical Communications:**

1. **Alert CISO/Security Manager**
   ```
   Via: PagerDuty P0 alert + Phone call
   Message: "P0 Data Breach - [Type] data accessed by [Actor] at [Time]
            Estimated records: [Count]. War room activating."
   ```

2. **Activate Incident Response Team**
   - Security Analyst (IR Lead)
   - Security Manager
   - CISO
   - DBA/Data Owner
   - Legal Counsel
   - PCI QSA (if PAN involved)

3. **Create War Room**
   - Slack channel: `#incident-breach-YYYY-MM-DD`
   - Jira ticket: `SEC-BREACH-XXXX`
   - Conference bridge: Activate dedicated IR line

### Step 3: Evidence Preservation (Minutes 10-15)

**Forensic Evidence Collection:**

```bash
#!/bin/bash
# Evidence preservation script
INCIDENT_ID="BREACH-$(date +%Y%m%d-%H%M%S)"
EVIDENCE_DIR="/var/forensics/$INCIDENT_ID"
mkdir -p "$EVIDENCE_DIR"

# 1. Capture logs immediately
aws s3 sync s3://audit-logs-bucket/ "$EVIDENCE_DIR/cloudtrail/" \
  --exclude "*" --include "*$(date -d '1 hour ago' +%Y/%m/%d)*"

# 2. Database query history
psql -h payment-db.internal -U forensics -d payment_prod -c \
  "COPY (SELECT * FROM pg_stat_statements WHERE query_start > NOW() - INTERVAL '1 hour')
   TO '$EVIDENCE_DIR/db_queries.csv' CSV HEADER;"

# 3. Application logs
kubectl logs -n production --all-containers --since=1h > "$EVIDENCE_DIR/app_logs.txt"

# 4. Network flow logs
aws ec2 describe-flow-logs --filter "Name=creation-time,Values=$(date -u +%Y-%m-%dT%H:%M:%S)" \
  > "$EVIDENCE_DIR/vpc_flow.json"

# 5. Take EBS snapshots of affected instances
aws ec2 create-snapshot --volume-id vol-XXXXXXX \
  --description "Forensic snapshot - $INCIDENT_ID"

# 6. Enable S3 object versioning and MFA delete
aws s3api put-bucket-versioning --bucket cardholder-data \
  --versioning-configuration Status=Enabled,MFADelete=Enabled
```

**Chain of Custody:**
- Document all evidence collected (what, when, who, where)
- Calculate SHA256 hashes of all artifacts
- Store evidence in write-once S3 bucket with legal hold
- Log all access to evidence

## Phase 2: Containment (15-60 Minutes)

### Objective
Stop ongoing data exfiltration, prevent further unauthorized access, isolate compromised systems.

### Containment Decision Matrix

| Scenario | Action | Trade-off |
|----------|--------|-----------|
| Active exfiltration | Block egress immediately | May alert attacker, lose forensic visibility |
| Compromised credentials | Rotate credentials + revoke sessions | May disrupt legitimate access |
| Compromised EC2 instance | Isolate with security group | Preserves state for forensics |
| Database compromise | Revoke database user permissions | May impact application availability |
| S3 bucket exposure | Remove public access + add bucket policy | Immediate protection, audit later |

### Step 4: Network-Level Containment

**Block Outbound Exfiltration:**

```bash
# 1. Identify exfiltration destination
MALICIOUS_IP="203.0.113.50"  # Replace with actual IOC

# 2. Block at AWS Network Firewall
aws networkfirewall create-rule \
  --rule-group-arn arn:aws:network-firewall:region:account:stateful-rulegroup/block-malicious \
  --rule "deny $MALICIOUS_IP any -> any any (msg:\"Block data exfiltration\";)"

# 3. Update security group (deny all egress)
COMPROMISED_SG="sg-0abcd1234"
aws ec2 revoke-security-group-egress \
  --group-id $COMPROMISED_SG \
  --ip-permissions IpProtocol=-1,FromPort=0,ToPort=65535,IpRanges='[{CidrIp=0.0.0.0/0}]'

# 4. Update NACL for subnet-level blocking
aws ec2 create-network-acl-entry \
  --network-acl-id acl-xyz123 \
  --rule-number 1 --protocol -1 --egress \
  --cidr-block $MALICIOUS_IP/32 --rule-action deny
```

### Step 5: Identity and Access Containment

**Revoke Compromised Credentials:**

```bash
# 1. Disable compromised IAM user
COMPROMISED_USER="john.doe@example.com"
aws iam update-login-profile --user-name $COMPROMISED_USER \
  --password-reset-required --no-password

# 2. Deactivate access keys
aws iam list-access-keys --user-name $COMPROMISED_USER --query 'AccessKeyMetadata[*].AccessKeyId' \
  | xargs -I {} aws iam update-access-key --user-name $COMPROMISED_USER --access-key-id {} --status Inactive

# 3. Terminate active sessions
aws sts get-session-token --serial-number arn:aws:iam::account:mfa/user --token-code revoke-all

# 4. Force re-authentication for all users in affected group
aws iam put-user-policy --user-name $COMPROMISED_USER \
  --policy-name ForceReauth \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
```

### Step 6: Data Source Containment

**Database Isolation:**

```sql
-- 1. Revoke database permissions for compromised accounts
REVOKE ALL PRIVILEGES ON DATABASE payment_prod FROM app_user;
REVOKE SELECT ON ALL TABLES IN SCHEMA public FROM app_user;

-- 2. Terminate active sessions from compromised IP
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE client_addr = '10.0.50.75'
  AND pid <> pg_backend_pid();

-- 3. Enable row-level security
ALTER TABLE cards ENABLE ROW LEVEL SECURITY;
CREATE POLICY cards_policy ON cards
  USING (current_user IN ('forensics_ro'));

-- 4. Take point-in-time snapshot
aws rds create-db-snapshot \
  --db-instance-identifier payment-prod-db \
  --db-snapshot-identifier forensic-snap-$(date +%Y%m%d-%H%M%S)
```

**S3 Bucket Lockdown:**

```bash
# 1. Remove public access
aws s3api put-public-access-block \
  --bucket cardholder-data-bucket \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 2. Apply restrictive bucket policy
aws s3api put-bucket-policy --bucket cardholder-data-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyAllExceptForensics",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::cardholder-data-bucket","arn:aws:s3:::cardholder-data-bucket/*"],
    "Condition": {
      "StringNotEquals": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/ForensicsRole"}
    }
  }]
}'

# 3. Enable MFA Delete
aws s3api put-bucket-versioning --bucket cardholder-data-bucket \
  --versioning-configuration Status=Enabled,MFADelete=Enabled \
  --mfa "arn:aws:iam::123456789012:mfa/security-admin 123456"
```

## Phase 3: Investigation (1-4 Hours)

### Step 7: Scope Determination

**Forensic Analysis Questions:**
1. **What** data was accessed/exfiltrated?
2. **When** did unauthorized access begin and end?
3. **Who** is the threat actor (external attacker, insider, compromised account)?
4. **Where** did the access originate (IP, geolocation)?
5. **How** did the attacker gain access (vulnerability, credential theft, misconfiguration)?
6. **Why** was the attack successful (what controls failed)?

**Timeline Reconstruction:**

```bash
# Build attack timeline from CloudTrail
aws athena start-query-execution \
  --query-string "
    SELECT eventTime, userIdentity.principalId, eventName, sourceIPAddress, requestParameters
    FROM cloudtrail_logs
    WHERE eventTime BETWEEN timestamp '2025-12-23 00:00:00' AND timestamp '2025-12-23 23:59:59'
      AND (eventName LIKE '%GetObject%' OR eventName LIKE '%DescribeDB%')
      AND resources LIKE '%cardholder%'
    ORDER BY eventTime ASC
  " \
  --result-configuration OutputLocation=s3://forensics/timeline-$(date +%Y%m%d)/
```

**Volume Assessment:**

```sql
-- Count affected records in database
SELECT
  COUNT(*) as total_records,
  MIN(last_accessed) as first_access,
  MAX(last_accessed) as last_access,
  COUNT(DISTINCT user_id) as unique_users
FROM audit_log
WHERE table_name = 'cards'
  AND action = 'SELECT'
  AND timestamp > (NOW() - INTERVAL '24 hours')
  AND user_id IN (SELECT user_id FROM compromised_accounts);

-- Identify specific affected card numbers (for notification)
SELECT card_id, customer_id, card_bin, last_four
FROM cards
WHERE card_id IN (
  SELECT DISTINCT resource_id
  FROM audit_log
  WHERE action='SELECT'
    AND user_id IN (SELECT user_id FROM compromised_accounts)
);
```

### Step 8: Root Cause Analysis

**Common Attack Vectors:**

| Attack Vector | Investigation Steps | Remediation |
|---------------|---------------------|-------------|
| **SQL Injection** | Review WAF logs, application logs for SQLi patterns | Patch application, deploy WAF rules |
| **Compromised Credentials** | Check for credential stuffing, brute force in auth logs | Force password reset, enable MFA |
| **Misconfigured S3 Bucket** | Review bucket ACLs, policies; check AWS Config history | Remove public access, apply SCPs |
| **Insider Threat** | Review user access patterns, correlate with HR records | Revoke access, legal action |
| **Supply Chain Attack** | Analyze third-party integrations, review vendor access | Revoke API keys, audit all vendors |
| **Vulnerability Exploitation** | Match GuardDuty findings with CVE databases | Apply patches, deploy IPS rules |

## Phase 4: Eradication (4-8 Hours)

### Step 9: Threat Removal

```bash
# 1. Patch exploited vulnerability
ansible-playbook -i production remediate-cve-XXXX.yml

# 2. Remove backdoors and persistence mechanisms
# Check cron jobs
crontab -l -u www-data

# Check systemd timers
systemctl list-timers --all

# Check for suspicious processes
ps auxf | grep -E "(nc|ncat|socat|cryptominer)"

# 3. Rebuild compromised systems from known-good images
kubectl delete pod compromised-pod-xyz --force --grace-period=0
kubectl apply -f deployment-v2-secure.yaml

# 4. Rotate ALL credentials (assume full compromise)
./rotate-all-credentials.sh
```

### Step 10: Hardening and Re-architecture

**Immediate Security Enhancements:**

```hcl
# Enhanced S3 bucket security (Terraform)
resource "aws_s3_bucket" "cardholder_data" {
  bucket = "cardholder-data-${var.environment}"

  # Block all public access
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  # Enable versioning and MFA delete
  versioning {
    enabled    = true
    mfa_delete = true
  }

  # Server-side encryption required
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.cardholder_data.arn
      }
      bucket_key_enabled = true
    }
  }

  # Object lock for compliance
  object_lock_configuration {
    object_lock_enabled = "Enabled"
    rule {
      default_retention {
        mode = "GOVERNANCE"
        days = 2555  # 7 years for PCI DSS
      }
    }
  }

  # Logging to separate bucket
  logging {
    target_bucket = aws_s3_bucket.audit_logs.id
    target_prefix = "s3-access-logs/"
  }
}
```

## Phase 5: Recovery (8-24 Hours)

### Step 11: Service Restoration

**Validation Checklist:**
- [ ] All vulnerabilities patched
- [ ] Backdoors and persistence mechanisms removed
- [ ] All credentials rotated
- [ ] Security controls validated (SIEM, FIM, AV)
- [ ] Monitoring enhanced for this attack pattern
- [ ] Backup integrity verified
- [ ] Test transactions successful

**Gradual Restoration:**

```bash
# 1. Start with isolated test environment
terraform apply -target=module.test_environment

# 2. Run security validation
./security-validation-suite.sh --comprehensive

# 3. Gradual production rollout (canary deployment)
kubectl set image deployment/payment-api payment-api=v2.0-secure --record
kubectl rollout status deployment/payment-api
kubectl rollout undo deployment/payment-api  # If issues detected

# 4. Monitor for 24 hours before full restoration
watch -n 60 'kubectl top pods && curl -s http://healthcheck/api/status'
```

## Phase 6: Post-Incident Activities (1-7 Days)

### Step 12: Regulatory Notification

**PCI DSS Requirement 12.10.6: Notify Acquirer and Card Brands**

Timeline:
- **Immediately**: Notify acquiring bank
- **Within 24 hours**: Notify PCI QSA
- **Within 72 hours**: Formal written notification to card brands

**Notification Template:**

```
To: PCI QSA <qsa@example.com>
Subject: PCI DSS Security Incident Notification - [Company Name]

Dear [QSA Name],

This is formal notification of a security incident that may have compromised cardholder data,
per PCI DSS Requirement 12.10.6.

Incident Summary:
- Date/Time Detected: [YYYY-MM-DD HH:MM UTC]
- Date/Time Contained: [YYYY-MM-DD HH:MM UTC]
- Affected Systems: [List CDE systems]
- Data Types Compromised: [PAN / CVV / Track Data / etc.]
- Estimated Records Affected: [Number]
- Attack Vector: [SQLi / Credential Theft / etc.]

Current Status:
- Containment: [Complete/In Progress]
- Forensic Investigation: [In Progress]
- Law Enforcement Notified: [Yes/No]

We are conducting a full forensic investigation and will provide a comprehensive report within 7 days.

Contact: [CISO Name, Phone, Email]
```

**GDPR Notification (if EU data subjects affected):**

```
To: Supervisory Authority
Subject: Personal Data Breach Notification under GDPR Article 33

Notification within 72 hours of breach discovery, including:
1. Nature of the breach
2. Categories and approximate number of data subjects
3. Likely consequences
4. Measures taken or proposed
```

### Step 13: Lessons Learned Meeting

**Participants**: IR Team, Engineering, Management, QSA (optional)

**Agenda:**
1. **Timeline Review** (30 min)
   - Attack reconstruction
   - Detection timeline
   - Response timeline

2. **What Went Well** (15 min)
   - Effective controls
   - Quick detection
   - Good coordination

3. **What Went Wrong** (30 min)
   - Security control failures
   - Detection gaps
   - Response delays

4. **Action Items** (30 min)
   - Technical remediations
   - Process improvements
   - Training needs

5. **Final Report Assignment** (15 min)

### Step 14: Corrective Action Plan

**Template:**

| Finding | Root Cause | Corrective Action | Owner | Due Date | Status |
|---------|------------|-------------------|-------|----------|--------|
| S3 bucket misconfiguration | Manual configuration, no IaC | Enforce Terraform SCPs, AWS Config rules | Cloud Architect | 2025-01-15 | In Progress |
| Failed to detect SQLi | WAF rules outdated | Update OWASP Core Rule Set, add custom rules | Security Engineer | 2025-01-10 | Complete |
| Excessive DB permissions | Over-privileged app account | Implement least privilege, database role separation | DBA | 2025-01-20 | Not Started |

## Appendix A: Breach Severity Calculator

```python
def calculate_breach_severity(records_compromised, data_types, pci_scope):
    """
    Calculate breach severity for prioritization and notification
    """
    severity_score = 0

    # Record count scoring
    if records_compromised > 1000000:
        severity_score += 50
    elif records_compromised > 100000:
        severity_score += 40
    elif records_compromised > 10000:
        severity_score += 30
    elif records_compromised > 1000:
        severity_score += 20
    else:
        severity_score += 10

    # Data sensitivity scoring
    data_weights = {
        'PAN': 30,
        'CVV': 20,
        'Full_Track_Data': 25,
        'PIN': 25,
        'SSN': 15,
        'DOB': 5
    }
    severity_score += sum(data_weights.get(dt, 0) for dt in data_types)

    # PCI scope impact
    if pci_scope:
        severity_score += 20

    # Final classification
    if severity_score >= 80:
        return "CATASTROPHIC - Immediate executive escalation, legal involvement"
    elif severity_score >= 60:
        return "CRITICAL - CISO escalation, prepare for regulatory notification"
    elif severity_score >= 40:
        return "HIGH - Immediate containment required"
    else:
        return "MEDIUM - Standard IR procedures"

# Usage
severity = calculate_breach_severity(
    records_compromised=50000,
    data_types=['PAN', 'CVV'],
    pci_scope=True
)
print(f"Breach Severity: {severity}")
```

## Appendix B: Evidence Collection Checklist

- [ ] CloudTrail logs (48 hours before and after)
- [ ] VPC Flow Logs (24 hours window)
- [ ] Database audit logs
- [ ] Application logs
- [ ] WAF logs
- [ ] SIEM alerts and correlation
- [ ] EBS snapshots of affected instances
- [ ] Memory dumps (if malware suspected)
- [ ] Network packet captures (Security Onion)
- [ ] User account activity logs
- [ ] Authentication logs (successful and failed)
- [ ] S3 access logs
- [ ] DNS query logs
- [ ] Email logs (if phishing involved)

## Appendix C: Communication Templates

**CEO Briefing (P0 Breach):**
```
Subject: URGENT - Data Breach Notification

Executive Summary:
We detected unauthorized access to [X] cardholder records at [Time] on [Date].

Status: [Contained / Ongoing]
Impact: [Customer Count], [Financial Estimate], [Regulatory Risk]

Immediate Actions Taken:
1. Threat contained and isolated
2. Forensic investigation initiated
3. PCI QSA notified
4. Legal counsel engaged

Next Steps:
- Complete forensic analysis (24 hours)
- Regulatory notification (72 hours)
- Customer notification (per legal guidance)

Recommendation: Convene executive crisis management team immediately.
```

---

**Document Version**: 2.0
**Last Updated**: December 2025
**Owner**: CISO
**Review Cycle**: Quarterly or post-incident
