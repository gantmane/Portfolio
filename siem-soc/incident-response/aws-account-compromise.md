# AWS Account Compromise Response Playbook

## Incident Overview

**Severity**: P0 - Critical
**Response Time**: Immediate (<15 minutes)
**Escalation**: CISO, Cloud Architect, AWS TAM

### Description
Unauthorized access to AWS account through compromised credentials, IAM keys, or console access. Can lead to data exfiltration, resource hijacking (cryptomining), service disruption, and financial loss.

### Business Impact
- Unauthorized resource provisioning (financial loss)
- Data exfiltration from S3, RDS, or other data stores
- Service disruption and downtime
- Cryptomining resource abuse
- Lateral movement to connected accounts (AWS Organizations)
- Compliance violations (PCI DSS, SOC 2)

### MITRE ATT&CK Mapping
- **T1078.004** - Valid Accounts: Cloud Accounts
- **T1136.003** - Create Account: Cloud Account
- **T1098** - Account Manipulation
- **T1537** - Transfer Data to Cloud Account
- **T1496** - Resource Hijacking

### PCI DSS Requirements
- **Requirement 7.2** - Implement access control systems
- **Requirement 8** - Identify and authenticate access
- **Requirement 10.2** - Implement automated audit trails

## Detection Indicators

### Wazuh Rule IDs
- `100211` - Failed root account login
- `100212` - Root account console login successful (CRITICAL)
- `100300` - Overly permissive IAM policy created
- `100301` - AdministratorAccess policy attached
- `100302` - New IAM access key created
- `100390` - CloudTrail logging stopped
- `100420` - Bulk resource deletion
- `100430` - Multiple access denied errors (privilege enumeration)
- `100440` - Cross-account role assumption

### GuardDuty Findings
```
- UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
- UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom
- Persistence:IAMUser/UserPermissions
- PrivilegeEscalation:IAMUser/AdministrativePermissions
- Stealth:IAMUser/CloudTrailLoggingDisabled
- CryptoCurrency:EC2/BitcoinTool.B!DNS
```

### Common Indicators
```
- Console login from unfamiliar IP/geolocation
- API calls from Tor exit nodes or known VPN services
- Root account usage (should never be used)
- Creation of new IAM users outside normal change window
- Launch of large EC2 instances (cryptomining)
- S3 bucket policy changes (public exposure)
- CloudTrail disabled or logging suspended
- Unusual cross-region API activity
- Snapshot sharing with external accounts
- AccessDenied errors followed by permission changes
```

## Phase 1: Initial Triage (0-15 Minutes)

### Step 1: Confirm and Classify

**Validate Compromise:**

```bash
# Check recent CloudTrail events for anomalies
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --max-results 20 \
  --output table

# Review GuardDuty findings (last 24 hours)
aws guardduty list-findings \
  --detector-id <detector-id> \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7},"updatedAt":{"Gte":'$(date -d '1 day ago' +%s)'}}}' \
  --query 'FindingIds' --output text | \
  xargs -I {} aws guardduty get-findings --detector-id <detector-id> --finding-ids {}

# Check for suspicious IAM changes
aws iam get-credential-report
aws iam list-users --output table
```

**Compromise Indicators:**
- ✅ **Root Account Access**: Any root usage is suspicious
- ✅ **Impossible Geography**: Login from two distant locations within minutes
- ✅ **New IAM Users**: Created outside change management process
- ✅ **Permission Escalation**: New admin policies or roles
- ✅ **Resource Anomalies**: Unexpected EC2 instances, Lambda functions
- ✅ **Data Access**: Unusual S3 API activity, RDS snapshots shared

### Step 2: Immediate Notification

**Alert Key Stakeholders:**
1. **CISO / Security Manager** - PagerDuty P0 + Phone
2. **Cloud Architect / DevOps Lead** - War room activation
3. **AWS TAM (Technical Account Manager)** - Enterprise support case
4. **Finance** - Potential billing impact monitoring

**Create Incident Ticket:**
```
Priority: P0 - Critical
Type: Security Incident - Cloud Compromise
Title: AWS Account [Account-ID] Compromise - [Date/Time]
Description: Unauthorized access detected via [Root/IAM/Keys]
             Source IP: [IP], Geolocation: [Country]
             Actions taken: [Initial containment steps]
War Room: #incident-aws-YYYYMMDD
```

### Step 3: Evidence Preservation

```bash
#!/bin/bash
# AWS Compromise Evidence Collection Script
INCIDENT_ID="AWS-COMPROMISE-$(date +%Y%m%d-%H%M%S)"
EVIDENCE_S3="s3://forensics-evidence-bucket/$INCIDENT_ID"
LOOKBACK_HOURS=24

echo "[+] Starting evidence collection for $INCIDENT_ID"

# 1. CloudTrail logs (last 24-48 hours)
aws s3 sync s3://aws-cloudtrail-logs-ACCOUNT-ID/ /tmp/cloudtrail-evidence/ \
  --exclude "*" \
  --include "*$(date -d '2 days ago' +%Y/%m/%d)*" \
  --include "*$(date -d '1 day ago' +%Y/%m/%d)*" \
  --include "*$(date +%Y/%m/%d)*"

# 2. IAM credential report
aws iam generate-credential-report
sleep 5
aws iam get-credential-report --output text | base64 -d > /tmp/iam-credentials-$INCIDENT_ID.csv

# 3. Current IAM state (users, roles, policies)
aws iam list-users > /tmp/iam-users-$INCIDENT_ID.json
aws iam list-roles > /tmp/iam-roles-$INCIDENT_ID.json
aws iam list-policies --scope Local > /tmp/iam-policies-$INCIDENT_ID.json

# 4. EC2 instance inventory (check for cryptominers)
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name,LaunchTime,PublicIpAddress]' \
  --output table > /tmp/ec2-inventory-$INCIDENT_ID.txt

# 5. VPC Flow Logs (if enabled)
aws ec2 describe-flow-logs > /tmp/vpc-flow-logs-$INCIDENT_ID.json

# 6. GuardDuty findings
aws guardduty list-detectors --query 'DetectorIds[0]' --output text | \
  xargs -I {} aws guardduty get-findings --detector-id {} \
  --finding-ids $(aws guardduty list-findings --detector-id {} --output text) \
  > /tmp/guardduty-findings-$INCIDENT_ID.json

# 7. S3 bucket policies and ACLs
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  echo "Bucket: $bucket" >> /tmp/s3-policies-$INCIDENT_ID.txt
  aws s3api get-bucket-policy --bucket $bucket 2>/dev/null >> /tmp/s3-policies-$INCIDENT_ID.txt || echo "No policy"
  aws s3api get-bucket-acl --bucket $bucket >> /tmp/s3-policies-$INCIDENT_ID.txt
done

# 8. Upload to forensics bucket
aws s3 sync /tmp/ $EVIDENCE_S3/ --include "*$INCIDENT_ID*"

echo "[+] Evidence collection complete: $EVIDENCE_S3"
```

## Phase 2: Containment (15-60 Minutes)

### Step 4: Emergency Root Account Actions

**If Root Account Compromised:**

```bash
# 1. IMMEDIATELY rotate root password (via console only)
# Navigate to: AWS Console → Account → Security Credentials
# → Root user → Manage Password → Change Password

# 2. Invalidate all root account sessions
# (Requires AWS Support - open critical ticket)

# 3. Enable MFA on root account if not already enabled
# Console → Security Credentials → Multi-Factor Authentication (MFA) → Activate MFA

# 4. Delete any access keys for root account
aws iam list-access-keys --user-name root  # Should return empty
# If keys exist, delete immediately via console
```

**AWS Support Escalation for Root Compromise:**
```
Phone: +1-XXX-XXX-XXXX (24/7 Security Hotline)
Ticket Priority: Critical
Issue: "Root account compromise - require immediate session invalidation"
```

### Step 5: IAM User/Role Containment

**Identify Compromised Principal:**

```bash
# Find principal from suspicious CloudTrail events
COMPROMISED_USER="attacker-created-user"
COMPROMISED_IP="203.0.113.50"

# Get all actions by this principal
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=$COMPROMISED_USER \
  --max-results 50

# Check what permissions this user has
aws iam list-attached-user-policies --user-name $COMPROMISED_USER
aws iam list-user-policies --user-name $COMPROMISED_USER
```

**Immediate Containment Actions:**

```bash
# 1. Attach explicit DENY policy (immediate effect)
aws iam put-user-policy --user-name $COMPROMISED_USER \
  --policy-name EmergencyDenyAll \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'

# 2. Deactivate all access keys
aws iam list-access-keys --user-name $COMPROMISED_USER \
  --query 'AccessKeyMetadata[*].AccessKeyId' --output text | \
  xargs -I {} aws iam update-access-key --user-name $COMPROMISED_USER \
    --access-key-id {} --status Inactive

# 3. Delete console password (if exists)
aws iam delete-login-profile --user-name $COMPROMISED_USER 2>/dev/null

# 4. Remove from all groups
aws iam list-groups-for-user --user-name $COMPROMISED_USER \
  --query 'Groups[*].GroupName' --output text | \
  xargs -I {} aws iam remove-user-from-group --user-name $COMPROMISED_USER --group-name {}

# 5. Detach all policies
aws iam list-attached-user-policies --user-name $COMPROMISED_USER \
  --query 'AttachedPolicies[*].PolicyArn' --output text | \
  xargs -I {} aws iam detach-user-policy --user-name $COMPROMISED_USER --policy-arn {}

# 6. Revoke active sessions (requires STS service)
# Note: This affects ALL users in the account
aws iam put-user-policy --user-name $COMPROMISED_USER \
  --policy-name RevokeOldSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {"aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}
      }
    }]
  }'
```

### Step 6: Network-Level Containment

**Block Malicious IPs at Multiple Layers:**

```bash
MALICIOUS_IPS=("203.0.113.50" "198.51.100.75")

# 1. AWS WAF (if applicable)
for ip in "${MALICIOUS_IPS[@]}"; do
  aws wafv2 update-ip-set \
    --scope REGIONAL \
    --id IPSET-ID \
    --lock-token $(aws wafv2 get-ip-set --scope REGIONAL --id IPSET-ID --query 'LockToken' --output text) \
    --addresses $ip/32
done

# 2. Security Groups (deny inbound from malicious IPs)
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName]' --output text | \
  while read sg_id sg_name; do
    aws ec2 revoke-security-group-ingress \
      --group-id $sg_id \
      --ip-permissions IpProtocol=-1,FromPort=0,ToPort=65535,IpRanges="[{CidrIp=$MALICIOUS_IP/32}]" \
      2>/dev/null
  done

# 3. Network ACLs (subnet-level blocking)
aws ec2 create-network-acl-entry \
  --network-acl-id acl-xyz123 \
  --rule-number 1 \
  --protocol -1 \
  --ingress \
  --cidr-block $MALICIOUS_IP/32 \
  --rule-action deny
```

### Step 7: Resource-Level Containment

**Stop Cryptomining Instances:**

```bash
# Identify suspicious instances (large instance types, recent launches)
SUSPICIOUS_INSTANCES=$(aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[?InstanceType==`c5.24xlarge` || InstanceType==`p3.16xlarge`].[InstanceId,LaunchTime]' \
  --output text | \
  awk -v cutoff="$(date -d '24 hours ago' +%Y-%m-%dT%H:%M:%S)" '$2 > cutoff {print $1}')

# Isolate instances (don't terminate yet - preserve for forensics)
for instance in $SUSPICIOUS_INSTANCES; do
  echo "Isolating instance: $instance"

  # Create forensic snapshot
  VOLUME_ID=$(aws ec2 describe-instances --instance-ids $instance \
    --query 'Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId' --output text)
  aws ec2 create-snapshot --volume-id $VOLUME_ID \
    --description "Forensic snapshot - $INCIDENT_ID - $instance"

  # Change security group to isolated group (no ingress/egress)
  aws ec2 modify-instance-attribute --instance-id $instance \
    --groups sg-isolated-forensics

  # Stop instance (preserve state)
  aws ec2 stop-instances --instance-ids $instance
done
```

**Protect Data Stores:**

```bash
# 1. S3 - Remove any public access added by attacker
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  aws s3api put-public-access-block --bucket $bucket \
    --public-access-block-configuration \
      "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
done

# 2. RDS - Check for snapshots shared with external accounts
aws rds describe-db-snapshots --snapshot-type manual \
  --query 'DBSnapshots[*].[DBSnapshotIdentifier,DBSnapshotArn]' --output text | \
  while read snapshot_id snapshot_arn; do
    # Check if snapshot is public
    SHARED=$(aws rds describe-db-snapshot-attributes --db-snapshot-identifier $snapshot_id \
      --query 'DBSnapshotAttributesResult.DBSnapshotAttributes[?AttributeName==`restore`].AttributeValues' --output text)
    if [[ "$SHARED" == "all" ]]; then
      echo "PUBLIC SNAPSHOT FOUND: $snapshot_id - REMOVING PUBLIC ACCESS"
      aws rds modify-db-snapshot-attribute \
        --db-snapshot-identifier $snapshot_id \
        --attribute-name restore \
        --values-to-remove all
    fi
  done
```

## Phase 3: Investigation (1-4 Hours)

### Step 8: Attack Timeline Reconstruction

**CloudTrail Analysis with Athena:**

```sql
-- Query 1: Get all actions by compromised principal
SELECT
  eventTime,
  eventName,
  awsRegion,
  sourceIPAddress,
  userAgent,
  requestParameters,
  responseElements,
  errorCode
FROM cloudtrail_logs
WHERE userIdentity.principalid = 'AIDAI***EXAMPLE'
  AND eventTime BETWEEN '2025-12-23T00:00:00Z' AND '2025-12-23T23:59:59Z'
ORDER BY eventTime ASC;

-- Query 2: Identify privilege escalation attempts
SELECT
  eventTime,
  eventName,
  userIdentity.principalid,
  requestParameters
FROM cloudtrail_logs
WHERE eventName IN (
  'PutUserPolicy', 'PutRolePolicy', 'AttachUserPolicy', 'AttachRolePolicy',
  'CreateAccessKey', 'UpdateAssumeRolePolicy'
)
  AND eventTime > DATE_SUB(NOW(), INTERVAL 48 HOUR)
ORDER BY eventTime;

-- Query 3: Find data exfiltration attempts
SELECT
  eventTime,
  eventName,
  sourceIPAddress,
  requestParameters
FROM cloudtrail_logs
WHERE (
  eventName LIKE '%GetObject%' OR
  eventName LIKE '%CreateSnapshot%' OR
  eventName LIKE '%CopySnapshot%' OR
  eventName LIKE '%ModifySnapshotAttribute%'
)
  AND eventTime > DATE_SUB(NOW(), INTERVAL 24 HOUR)
ORDER BY eventTime;

-- Query 4: Resource creation for cryptomining
SELECT
  eventTime,
  eventName,
  awsRegion,
  requestParameters
FROM cloudtrail_logs
WHERE eventName IN ('RunInstances', 'CreateFunction', 'CreateContainer')
  AND eventTime > DATE_SUB(NOW(), INTERVAL 24 HOUR)
ORDER BY eventTime;
```

### Step 9: Lateral Movement Assessment

**Check Multi-Account Impact (AWS Organizations):**

```bash
# List all accounts in the organization
aws organizations list-accounts

# Check if compromised role was used for cross-account access
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --max-results 100 | \
  jq '.Events[] | select(.CloudTrailEvent | fromjson | .requestParameters.roleArn | contains("arn:aws:iam::ANOTHER-ACCOUNT"))'

# For each child account, check for suspicious activity
for account_id in $(aws organizations list-accounts --query 'Accounts[*].Id' --output text); do
  echo "Checking account: $account_id"
  aws cloudtrail lookup-events --max-results 20 # Requires cross-account role
done
```

## Phase 4: Eradication (4-8 Hours)

### Step 10: Complete Credential Rotation

**Rotate ALL Potentially Compromised Credentials:**

```bash
#!/bin/bash
# Full credential rotation script
echo "[+] Starting full AWS credential rotation"

# 1. Rotate all IAM user access keys
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  echo "Rotating keys for user: $user"

  # Get current access keys
  KEYS=$(aws iam list-access-keys --user-name $user --query 'AccessKeyMetadata[*].AccessKeyId' --output text)

  for key in $KEYS; do
    # Create new key
    NEW_KEY=$(aws iam create-access-key --user-name $user)
    echo "New key created for $user"

    # Deactivate old key (don't delete yet - 30 day grace period)
    aws iam update-access-key --user-name $user --access-key-id $key --status Inactive

    # Send notification to user with new keys (via Secrets Manager or email)
    aws secretsmanager create-secret --name "rotation/$user/access-key-$(date +%Y%m%d)" \
      --secret-string "$NEW_KEY"
  done
done

# 2. Rotate database passwords
for db_instance in $(aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier' --output text); do
  echo "Rotating password for RDS instance: $db_instance"
  NEW_PASS=$(openssl rand -base64 32)

  aws rds modify-db-instance \
    --db-instance-identifier $db_instance \
    --master-user-password $NEW_PASS \
    --apply-immediately

  # Store new password in Secrets Manager
  aws secretsmanager update-secret \
    --secret-id "rds/$db_instance/master-password" \
    --secret-string $NEW_PASS
done

# 3. Rotate EC2 Key Pairs (requires reprovisioning instances)
# This is more complex - typically done during recovery phase

echo "[+] Credential rotation complete"
```

### Step 11: Remove Attacker Persistence

**Delete Malicious Resources:**

```bash
# 1. Delete unauthorized IAM users
aws iam delete-user --user-name attacker-created-user

# 2. Delete backdoor Lambda functions
aws lambda list-functions --query 'Functions[?Runtime==`python2.7` || contains(FunctionName, `backdoor`)].[FunctionName]' --output text | \
  xargs -I {} aws lambda delete-function --function-name {}

# 3. Delete unauthorized security groups
aws ec2 describe-security-groups --filters "Name=group-name,Values=*backdoor*,*attacker*" \
  --query 'SecurityGroups[*].GroupId' --output text | \
  xargs -I {} aws ec2 delete-security-group --group-id {}

# 4. Remove snapshot sharing with external accounts
aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[*].SnapshotId' --output text | \
  while read snapshot_id; do
    aws ec2 reset-snapshot-attribute --snapshot-id $snapshot_id --attribute createVolumePermission
  done
```

## Phase 5: Recovery (8-24 Hours)

### Step 12: Restore Normal Operations

**Security Validation Before Restoration:**

```bash
#!/bin/bash
# Pre-restoration security checklist
echo "=== AWS Account Security Validation ==="

# 1. Verify CloudTrail is enabled in all regions
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  echo "Checking CloudTrail in $region..."
  TRAIL_STATUS=$(aws cloudtrail get-trail-status --name primary-trail --region $region \
    --query 'IsLogging' --output text 2>/dev/null)
  [[ "$TRAIL_STATUS" == "True" ]] && echo "✓ CloudTrail active" || echo "✗ CloudTrail INACTIVE"
done

# 2. Verify GuardDuty is enabled
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  DETECTOR=$(aws guardduty list-detectors --region $region --query 'DetectorIds[0]' --output text)
  [[ -n "$DETECTOR" ]] && echo "✓ GuardDuty enabled in $region" || echo "✗ GuardDuty missing in $region"
done

# 3. Verify MFA on all users
aws iam get-credential-report | grep -v "root_account" | \
  awk -F',' '{if ($4 == "true" && $8 == "false") print "✗ MFA missing for user:", $1}'

# 4. Check for unused access keys (>90 days)
aws iam get-credential-report | \
  awk -F',' -v cutoff="$(date -d '90 days ago' +%Y-%m-%d)" '$11 < cutoff {print "✗ Old access key for", $1}'

# 5. Verify S3 public access blocks
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  PUBLIC_BLOCK=$(aws s3api get-public-access-block --bucket $bucket 2>/dev/null | grep -c "true")
  [[ $PUBLIC_BLOCK -eq 4 ]] && echo "✓ $bucket protected" || echo "✗ $bucket NOT fully protected"
done

echo "=== Validation Complete ==="
```

### Step 13: Enhanced Monitoring

**Deploy Additional Detections:**

```python
# AWS Lambda function for real-time CloudTrail monitoring
import boto3
import json

def lambda_handler(event, context):
    """
    Enhanced CloudTrail monitoring for post-incident vigilance
    Triggers on high-risk API calls
    """
    sns = boto3.client('sns')

    # High-risk API calls to monitor
    HIGH_RISK_EVENTS = [
        'PutUserPolicy', 'PutRolePolicy', 'AttachUserPolicy',
        'CreateAccessKey', 'DeleteTrail', 'StopLogging',
        'PutBucketPolicy', 'ModifySnapshotAttribute',
        'AuthorizeSecurityGroupIngress'
    ]

    for record in event['Records']:
        cloudtrail_event = json.loads(record['Sns']['Message'])
        event_name = cloudtrail_event['eventName']

        if event_name in HIGH_RISK_EVENTS:
            # Send immediate alert
            sns.publish(
                TopicArn='arn:aws:sns:region:account:security-alerts',
                Subject=f'HIGH RISK: {event_name} detected',
                Message=json.dumps(cloudtrail_event, indent=2)
            )

            # Enhanced logging
            print(f"ALERT: {event_name} by {cloudtrail_event['userIdentity']} from {cloudtrail_event['sourceIPAddress']}")

    return {'statusCode': 200}
```

## Phase 6: Post-Incident (1-7 Days)

### Step 14: Cost Assessment

**Calculate Financial Impact:**

```bash
# Get total cost for incident timeframe
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '7 days ago' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity DAILY \
  --metrics "UnblendedCost" \
  --group-by Type=SERVICE

# Identify unusual spikes
# Typical indicators: EC2 costs increased 10x, Lambda invocations spike, data transfer surge

# Request cost forgiveness from AWS (if cryptomining)
# Submit case: "Fraudulent usage due to account compromise - request cost adjustment"
```

### Step 15: Hardening Recommendations

**AWS Account Hardening Checklist:**

- [ ] Enable MFA on root account and all IAM users
- [ ] Delete root account access keys
- [ ] Implement SCPs (Service Control Policies) to prevent CloudTrail disable
- [ ] Enable GuardDuty in all regions
- [ ] Configure AWS Config rules for compliance
- [ ] Implement least-privilege IAM policies (no AdministratorAccess)
- [ ] Use IAM Identity Center (SSO) instead of long-lived IAM keys
- [ ] Enable S3 Block Public Access at account level
- [ ] Require MFA for sensitive API calls (SCP condition)
- [ ] Implement session duration limits (1-hour max)
- [ ] Enable VPC Flow Logs in all VPCs
- [ ] Deploy Security Hub for centralized findings
- [ ] Configure EventBridge rules for real-time alerts
- [ ] Implement AWS Backup for critical resources
- [ ] Use AWS Organizations for multi-account strategy
- [ ] Enable EBS encryption by default
- [ ] Review and minimize cross-account trust relationships

---

**Document Version**: 2.0
**Last Updated**: December 2025
**Owner**: Cloud Security Architect
**Review Cycle**: Quarterly or post-incident
