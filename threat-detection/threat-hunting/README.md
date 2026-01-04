# Threat Hunting Queries

## Overview

Proactive threat hunting queries for detecting sophisticated threats that evade automated detection. These queries implement hypothesis-driven hunting based on MITRE ATT&CK framework and threat intelligence.

## Hunting Methodology

### Hunt Process

```
1. HYPOTHESIS → Formulate based on threat intelligence, MITRE technique
2. QUERY → Design searches across logs, SIEM, EDR
3. INVESTIGATE → Analyze results, identify anomalies
4. VALIDATE → Confirm true positive vs false positive
5. DETECT → Create automated rule for confirmed TTP
6. DOCUMENT → Record findings, improve detection
```

### Hunt Frequency

| Hunt Type | Frequency | Duration | Tools |
|-----------|-----------|----------|-------|
| **Scheduled Hunts** | Weekly | 2-4 hours | Athena, Wazuh, Security Onion |
| **Threat Intel Driven** | As intel arrives | 1-2 hours | STIX/TAXII feeds |
| **Incident-Based** | Post-incident | 4-8 hours | Forensic tools |
| **Continuous** | Automated | Real-time | ML anomaly detection |

## AWS CloudTrail Hunting (Athena)

### Hunt 1: AWS Account Takeover Indicators

**Hypothesis**: Attacker gains initial access via compromised IAM credentials

```sql
-- Hunt: Unusual AWS API calls from new geolocations
-- MITRE: T1078.004 - Valid Accounts: Cloud Accounts

WITH user_baselines AS (
  SELECT
    useridentity.principalid,
    sourceipaddress,
    awsregion,
    COUNT(*) as call_count,
    MIN(eventtime) as first_seen,
    MAX(eventtime) as last_seen
  FROM cloudtrail_logs
  WHERE eventtime > DATE_SUB(NOW(), INTERVAL 30 DAY)
  GROUP BY 1, 2, 3
),
recent_activity AS (
  SELECT
    useridentity.principalid,
    sourceipaddress,
    awsregion,
    eventname,
    eventtime,
    useridentity.principalid || sourceipaddress AS user_ip_combo
  FROM cloudtrail_logs
  WHERE eventtime > DATE_SUB(NOW(), INTERVAL 24 HOUR)
)
SELECT
  r.eventtime,
  r.principalid,
  r.sourceipaddress,
  r.awsregion,
  r.eventname,
  CASE
    WHEN b.principalid IS NULL THEN 'NEW_USER_IP_COMBINATION'
    WHEN DATEDIFF(hour, b.first_seen, r.eventtime) < 1 THEN 'FIRST_HOUR_ACTIVITY'
    ELSE 'KNOWN_COMBINATION'
  END AS anomaly_type
FROM recent_activity r
LEFT JOIN user_baselines b
  ON r.user_ip_combo = b.useridentity.principalid || b.sourceipaddress
WHERE b.principalid IS NULL  -- New IP for this user
  OR r.awsregion != b.awsregion  -- Different region than usual
ORDER BY r.eventtime DESC
LIMIT 100;
```

**Expected Results**:
- Legitimate: New VPN endpoint, user traveling
- Suspicious: Attacker using compromised credentials from new location

**Follow-up Actions**:
1. Check MFA status for flagged logins
2. Review all API calls from suspicious IPs
3. Compare user agent strings to known baselines
4. Contact user to confirm legitimate activity

---

### Hunt 2: Privilege Escalation via IAM Policy Manipulation

**Hypothesis**: Attacker modifies IAM policies to elevate privileges

```sql
-- Hunt: IAM policy changes granting broad permissions
-- MITRE: T1098.003 - Account Manipulation: Additional Cloud Roles

SELECT
  eventtime,
  useridentity.principalid AS actor,
  eventname,
  JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') AS policy_document,
  JSON_EXTRACT_SCALAR(requestparameters, '$.userName') AS target_user,
  JSON_EXTRACT_SCALAR(requestparameters, '$.roleName') AS target_role,
  sourceipaddress,
  useragent
FROM cloudtrail_logs
WHERE eventtime > DATE_SUB(NOW(), INTERVAL 7 DAY)
  AND eventname IN (
    'PutUserPolicy',
    'PutRolePolicy',
    'PutGroupPolicy',
    'AttachUserPolicy',
    'AttachRolePolicy',
    'AttachGroupPolicy'
  )
  AND (
    -- Detect wildcard permissions
    JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%"Action":"*"%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%"Resource":"*"%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%AdministratorAccess%'
    -- Detect sensitive actions
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%iam:CreateAccessKey%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%iam:PassRole%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.policyDocument') LIKE '%sts:AssumeRole%'
  )
ORDER BY eventtime DESC;
```

**Hunting Tips**:
- Review policies created outside business hours
- Check if actor has legitimate reason to modify IAM
- Look for rapid succession of permission changes (privilege escalation chain)

---

### Hunt 3: Data Exfiltration from S3

**Hypothesis**: Attacker uses compromised credentials to bulk download S3 data

```sql
-- Hunt: Bulk S3 GetObject operations indicating data exfiltration
-- MITRE: T1530 - Data from Cloud Storage Object

WITH s3_access_baseline AS (
  SELECT
    useridentity.principalid,
    AVG(COUNT(*)) OVER (PARTITION BY useridentity.principalid) AS avg_daily_gets
  FROM cloudtrail_logs
  WHERE eventname = 'GetObject'
    AND eventtime > DATE_SUB(NOW(), INTERVAL 30 DAY)
  GROUP BY useridentity.principalid, DATE(eventtime)
),
recent_s3_activity AS (
  SELECT
    DATE(eventtime) AS event_date,
    useridentity.principalid,
    requestparameters.bucketName AS bucket,
    COUNT(*) AS get_count,
    COUNT(DISTINCT requestparameters.key) AS unique_objects,
    sourceipaddress,
    MIN(eventtime) AS first_access,
    MAX(eventtime) AS last_access
  FROM cloudtrail_logs
  WHERE eventname = 'GetObject'
    AND eventtime > DATE_SUB(NOW(), INTERVAL 7 DAY)
  GROUP BY 1, 2, 3, 6
)
SELECT
  r.event_date,
  r.principalid,
  r.bucket,
  r.get_count,
  r.unique_objects,
  r.sourceipaddress,
  r.first_access,
  r.last_access,
  DATEDIFF(minute, r.first_access, r.last_access) AS duration_minutes,
  b.avg_daily_gets,
  ROUND(r.get_count / NULLIF(b.avg_daily_gets, 0), 2) AS deviation_ratio
FROM recent_s3_activity r
LEFT JOIN s3_access_baseline b ON r.principalid = b.principalid
WHERE r.get_count > 100  -- Threshold for bulk access
  AND (
    r.get_count > b.avg_daily_gets * 3  -- 3x normal activity
    OR b.avg_daily_gets IS NULL  -- New user accessing S3
  )
ORDER BY r.get_count DESC;
```

**Investigation Checklist**:
- [ ] Is the bucket sensitive (cardholder data, PII)?
- [ ] Is the source IP known/expected?
- [ ] Were files actually downloaded (check VPC Flow Logs for egress)?
- [ ] Was data encrypted in transit?
- [ ] Contact user to verify legitimate business need

---

### Hunt 4: Persistence via Lambda Backdoors

**Hypothesis**: Attacker deploys malicious Lambda functions for persistence

```sql
-- Hunt: Lambda functions created with suspicious characteristics
-- MITRE: T1543 - Create or Modify System Process

SELECT
  eventtime,
  useridentity.principalid AS creator,
  JSON_EXTRACT_SCALAR(requestparameters, '$.functionName') AS function_name,
  JSON_EXTRACT_SCALAR(requestparameters, '$.runtime') AS runtime,
  JSON_EXTRACT_SCALAR(requestparameters, '$.role') AS execution_role,
  JSON_EXTRACT_SCALAR(requestparameters, '$.environment.variables') AS env_vars,
  sourceipaddress,
  useragent
FROM cloudtrail_logs
WHERE eventtime > DATE_SUB(NOW(), INTERVAL 30 DAY)
  AND (eventname = 'CreateFunction' OR eventname = 'UpdateFunctionCode')
  AND (
    -- Suspicious runtimes (deprecated or uncommon)
    JSON_EXTRACT_SCALAR(requestparameters, '$.runtime') IN ('python2.7', 'nodejs10.x')
    -- Environment variables with suspicious names
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.environment.variables') LIKE '%password%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.environment.variables') LIKE '%secret%'
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.environment.variables') LIKE '%api_key%'
    -- Functions with overly broad IAM roles
    OR JSON_EXTRACT_SCALAR(requestparameters, '$.role') LIKE '%AdministratorAccess%'
    -- Created outside business hours
    OR EXTRACT(HOUR FROM eventtime) NOT BETWEEN 8 AND 18
  )
ORDER BY eventtime DESC;
```

**Further Investigation**:
```bash
# Download Lambda function code for analysis
aws lambda get-function --function-name <suspicious_function> --query 'Code.Location' --output text | \
  xargs wget -O /tmp/lambda_code.zip

# Extract and scan for malicious code
unzip /tmp/lambda_code.zip -d /tmp/lambda_code/
grep -r "eval\|exec\|import os\|subprocess" /tmp/lambda_code/
```

---

## Wazuh SIEM Hunting (OpenSearch)

### Hunt 5: Lateral Movement via SSH Key Abuse

**Hypothesis**: Attacker uses stolen SSH keys to move laterally

```json
// OpenSearch Query (Wazuh indices)
// MITRE: T1021.004 - Remote Services: SSH

GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-7d"}}},
        {"match": {"data.sshd.event": "Accepted publickey"}}
      ]
    }
  },
  "aggs": {
    "ssh_keys_by_user": {
      "terms": {
        "field": "data.srcuser.keyword",
        "size": 100
      },
      "aggs": {
        "unique_source_ips": {
          "cardinality": {
            "field": "data.srcip"
          }
        },
        "unique_dest_hosts": {
          "cardinality": {
            "field": "agent.name.keyword"
          }
        },
        "source_ips": {
          "terms": {
            "field": "data.srcip",
            "size": 10
          }
        }
      }
    }
  }
}
```

**Analysis**:
- Users authenticating from >5 different source IPs (suspicious)
- Users accessing >10 different hosts (lateral movement)
- Non-service accounts with high SSH key usage

**Follow-up**:
```bash
# Check SSH key fingerprints on compromised hosts
ssh-keygen -lf /home/user/.ssh/authorized_keys

# Review recent commands by suspicious user
sudo ausearch -ua <username> -ts recent | aureport -f -i
```

---

### Hunt 6: Fileless Malware via Memory-Only Execution

**Hypothesis**: Attacker uses in-memory payloads to evade file-based detection

```json
// Hunt: Suspicious process execution patterns
// MITRE: T1027 - Obfuscated Files or Information

GET wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        {"match": {"rule.groups": "syscheck"}}
      ],
      "should": [
        {"wildcard": {"data.command": "*base64*"}},
        {"wildcard": {"data.command": "*powershell -enc*"}},
        {"wildcard": {"data.command": "*eval(*"}},
        {"wildcard": {"data.command": "*exec(*"}},
        {"wildcard": {"data.command": "*curl * | bash*"}},
        {"wildcard": {"data.command": "*wget * | sh*"}},
        {"match": {"data.process.name": "bash"}},
        {"match": {"data.process.ppid": "1"}}
      ],
      "minimum_should_match": 2
    }
  },
  "sort": [{"@timestamp": "desc"}]
}
```

**Indicators to Investigate**:
- Base64 encoded commands (obfuscation)
- Process spawned without parent (orphaned process)
- Network connections from scripting interpreters (bash, python, perl)
- Unusual child processes of web servers

---

## Kubernetes Threat Hunting

### Hunt 7: Container Escape Attempts

**Hypothesis**: Attacker attempts to escape container to access host

```bash
#!/bin/bash
# Hunt: Kubernetes pod security violations and escape attempts
# MITRE: T1611 - Escape to Host

kubectl get events --all-namespaces -o json | \
jq -r '.items[] |
  select(.reason == "FailedCreate" or .reason == "FailedScheduling") |
  select(.message | contains("hostNetwork") or contains("hostPID") or contains("privileged")) |
  "\(.lastTimestamp) | \(.involvedObject.namespace)/\(.involvedObject.name) | \(.message)"'

# Hunt for running pods with dangerous configurations
kubectl get pods --all-namespaces -o json | \
jq -r '.items[] |
  select(
    .spec.hostNetwork == true or
    .spec.hostPID == true or
    .spec.hostIPC == true or
    (.spec.containers[].securityContext.privileged == true)
  ) |
  "\(.metadata.namespace)/\(.metadata.name) | hostNetwork:\(.spec.hostNetwork) | hostPID:\(.spec.hostPID) | privileged:\(.spec.containers[0].securityContext.privileged)"'

# Check for mounts of sensitive host paths
kubectl get pods --all-namespaces -o json | \
jq -r '.items[] |
  select(.spec.volumes[]?.hostPath.path |
    contains("/") or contains("/var/run/docker.sock") or contains("/proc") or contains("/sys")
  ) |
  "\(.metadata.namespace)/\(.metadata.name) | Mounted: \(.spec.volumes[].hostPath.path)"'
```

**Investigation Steps**:
1. Review pod security policies (PSP) or Pod Security Standards (PSS)
2. Check who created the pod (kubectl describe pod)
3. Inspect container image for malware (Trivy scan)
4. Review audit logs for privilege escalation attempts

---

### Hunt 8: Kubernetes Service Account Token Theft

**Hypothesis**: Attacker steals service account tokens to access K8s API

```bash
#!/bin/bash
# Hunt: Unusual Kubernetes API access patterns
# MITRE: T1528 - Steal Application Access Token

# Query K8s audit logs for service account token usage
kubectl logs -n kube-system kube-apiserver-* | \
grep '"verb":"get","objectRef":{"resource":"secrets"' | \
jq -r 'select(.user.username | startswith("system:serviceaccount")) |
  "\(.timestamp) | User: \(.user.username) | Source: \(.sourceIPs[0]) | Resource: \(.objectRef.namespace)/\(.objectRef.name)"'

# Find pods with automountServiceAccountToken enabled
kubectl get pods --all-namespaces -o json | \
jq -r '.items[] |
  select(.spec.automountServiceAccountToken == true or .spec.automountServiceAccountToken == null) |
  "\(.metadata.namespace)/\(.metadata.name) | SA: \(.spec.serviceAccountName // "default")"'

# Check for service accounts with cluster-admin privileges
kubectl get clusterrolebindings -o json | \
jq -r '.items[] |
  select(.roleRef.name == "cluster-admin") |
  select(.subjects[]?.kind == "ServiceAccount") |
  "\(.metadata.name) | SA: \(.subjects[].namespace)/\(.subjects[].name)"'
```

---

## Network Traffic Hunting (Zeek/Security Onion)

### Hunt 9: DNS Tunneling for C2 Communication

**Hypothesis**: Attacker uses DNS tunneling to exfiltrate data or receive commands

```bash
#!/bin/bash
# Hunt: Anomalous DNS queries indicating tunneling
# MITRE: T1071.004 - Application Layer Protocol: DNS

# Query Zeek DNS logs for suspicious patterns
cat /nsm/zeek/logs/current/dns.log | \
zeek-cut query qtype_name answers | \
awk '
  length($1) > 50 {  # Unusually long domain names
    print "LONG_QUERY:", $0
  }
  $1 ~ /[0-9]{10,}/ {  # Domains with long numeric sequences
    print "NUMERIC_DOMAIN:", $0
  }
  $1 ~ /[A-Za-z0-9]{20,}\./ {  # Random-looking subdomains
    print "RANDOM_SUBDOMAIN:", $0
  }
  $2 == "TXT" && length($3) > 100 {  # Large TXT records
    print "LARGE_TXT:", $0
  }
' | sort | uniq -c | sort -rn

# Statistical analysis - find domains with unusual query frequency
cat /nsm/zeek/logs/current/dns.log | \
zeek-cut query | \
awk -F'.' '{print $(NF-1)"."$NF}' | \  # Extract TLD
sort | uniq -c | sort -rn | head -20
```

**Indicators**:
- Domain names with entropy >4.5 (random-looking)
- High query volume to single domain (>100 queries/minute)
- TXT record queries with base64 encoded data
- Consistent query intervals (beaconing)

**Validation**:
```python
#!/usr/bin/env python3
import math
from collections import Counter

def calculate_entropy(string):
    """Calculate Shannon entropy of a string"""
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

# Check suspicious domain
domain = "a8f3kd9s2lmx4n7q.malicious-c2.com"
subdomain = domain.split('.')[0]

entropy = calculate_entropy(subdomain)
print(f"Entropy: {entropy:.2f}")  # > 4.5 is suspicious

if entropy > 4.5:
    print(f"ALERT: High entropy domain detected - possible DGA or tunneling")
```

---

### Hunt 10: TLS/SSL Certificate Anomalies

**Hypothesis**: Attacker uses self-signed or suspicious SSL certificates

```bash
# Hunt: SSL certificate anomalies
# MITRE: T1573 - Encrypted Channel

# Extract certificate details from Zeek
cat /nsm/zeek/logs/current/x509.log | \
zeek-cut certificate.subject certificate.issuer certificate.not_valid_after | \
awk '
  {
    # Self-signed certificates (subject == issuer)
    if ($1 == $2) {
      print "SELF_SIGNED:", $0
    }

    # Expired certificates
    expiry_timestamp = mktime(substr($3, 1, 19))
    current_timestamp = systime()
    if (expiry_timestamp < current_timestamp) {
      print "EXPIRED:", $0
    }

    # Certificates expiring soon (< 30 days)
    days_until_expiry = (expiry_timestamp - current_timestamp) / 86400
    if (days_until_expiry < 30 && days_until_expiry > 0) {
      print "EXPIRING_SOON:", $0, "Days:", int(days_until_expiry)
    }
  }
'

# Find certificates from untrusted CAs
cat /nsm/zeek/logs/current/ssl.log | \
zeek-cut server_name validation_status | \
grep -E "(self signed|unable to get local issuer|certificate has expired)" | \
sort | uniq -c | sort -rn
```

---

## Payment Fraud Hunting

### Hunt 11: Card Testing Attacks

**Hypothesis**: Attacker tests stolen credit cards with small transactions

```sql
-- Hunt: Card testing patterns in payment transactions
-- Business Logic: Fraudulent payment validation attempts

SELECT
  DATE(transaction_time) AS transaction_date,
  HOUR(transaction_time) AS transaction_hour,
  customer_ip,
  COUNT(DISTINCT card_bin) AS unique_card_bins,
  COUNT(*) AS transaction_count,
  SUM(CASE WHEN amount < 1.00 THEN 1 ELSE 0 END) AS micro_transactions,
  SUM(CASE WHEN status = 'declined' THEN 1 ELSE 0 END) AS declined_count,
  ROUND(AVG(amount), 2) AS avg_amount,
  COUNT(DISTINCT customer_email) AS unique_emails
FROM payment_transactions
WHERE transaction_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)
GROUP BY 1, 2, 3
HAVING unique_card_bins > 10  -- Testing multiple cards
   AND transaction_count > 20  -- High volume
   AND micro_transactions / transaction_count > 0.5  -- Mostly small amounts
   AND declined_count / transaction_count > 0.3  -- High decline rate
ORDER BY unique_card_bins DESC, transaction_count DESC;
```

**Red Flags**:
- Single IP testing >10 different cards
- >50% of transactions < $1.00
- >30% decline rate (invalid cards being tested)
- Multiple email addresses from same IP

**Response Actions**:
```bash
# Block IP at WAF
aws wafv2 update-ip-set \
  --name CardTestingBlockList \
  --addresses <MALICIOUS_IP>/32

# Notify fraud team
echo "Card testing detected from IP: $MALICIOUS_IP" | \
  mail -s "FRAUD ALERT" fraud-team@company.com
```

---

## Hunt Documentation Template

```markdown
# Hunt Report: [Hunt Name]

**Date**: YYYY-MM-DD
**Hunter**: [Your Name]
**Duration**: [Hours spent]

## Hypothesis
[What threat are you looking for?]
**MITRE Technique**: [T1XXX - Technique Name]

## Data Sources
- [ ] AWS CloudTrail
- [ ] Wazuh SIEM
- [ ] Security Onion / Zeek
- [ ] Kubernetes Audit Logs
- [ ] Application Logs
- [ ] Other: ___________

## Query/Procedure
```
[Paste your hunting query or procedure here]
```

## Results Summary
- **Total Events Analyzed**: [Number]
- **Suspicious Events**: [Number]
- **True Positives**: [Number]
- **False Positives**: [Number]

## Findings
1. **Finding #1**:
   - Description: [What was found]
   - Severity: [Critical/High/Medium/Low]
   - Evidence: [Log excerpt, screenshot, etc.]

## Actions Taken
- [ ] Created automated detection rule (Rule ID: _____)
- [ ] Escalated to incident response (Ticket: _____)
- [ ] Updated threat intel feed
- [ ] No action required

## Lessons Learned
[What did you learn? How can detection be improved?]

## Recommendations
1. [Recommendation #1]
2. [Recommendation #2]
```

---

**Document Version**: 1.0
**Last Updated**: December 2025
**Owner**: Threat Hunting Team
**Review Cycle**: Monthly
