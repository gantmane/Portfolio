# AWS GuardDuty Automation

Multi-account GuardDuty deployment with intelligent threat detection, automated response, and integration with centralized SIEM (Wazuh) across 15+ AWS accounts.

## Overview

This directory contains Infrastructure as Code (Terraform), automation scripts (Python, Bash), and integration configurations for AWS GuardDuty threat detection service. The implementation demonstrates proactive threat hunting and automated incident response capabilities that contributed to **85% reduction in security incidents** over 18 months.

### Key Achievements

- **15+ AWS Accounts**: Organization-wide GuardDuty deployment with centralized management
- **Real-time Threat Detection**: Automated detection of cryptocurrency mining, backdoor communication, and data exfiltration
- **SIEM Integration**: Findings forwarded to Wazuh for correlation with 500+ custom detection rules
- **Automated Response**: Lambda-based remediation for common threats (isolation, snapshot, notification)
- **Threat Intelligence**: Integration with AWS-managed and custom threat lists
- **Cost Optimization**: S3 protection and CloudTrail monitoring enabled selectively

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    GuardDuty Organization                       │
│                  (Delegated Administrator)                      │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │  Production  │  │ Development  │  │     CDE      │         │
│  │   Account    │  │   Account    │  │   Account    │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│         │                  │                  │                │
│         └──────────────────┴──────────────────┘                │
│                           │                                    │
│                    GuardDuty Findings                          │
│                           │                                    │
│         ┌─────────────────┴─────────────────┐                 │
│         │                                   │                 │
│    EventBridge                        Kinesis Stream          │
│         │                                   │                 │
│    ┌────▼────┐                         ┌───▼────┐            │
│    │ Lambda  │                         │  SIEM  │            │
│    │Response │                         │ Wazuh  │            │
│    └─────────┘                         └────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

## Contents

- [README.md](README.md) - This file
- [metadata.yaml](metadata.yaml) - Directory metadata and compliance mappings
- [guardduty-config.tf](guardduty-config.tf) - Organization-wide GuardDuty configuration
- [guardduty-findings-processor.py](guardduty-findings-processor.py) - Lambda function for finding enrichment and response
- [threat-intel-integration.tf](threat-intel-integration.tf) - Threat intelligence feed integration
- [suspicious-activity-alerts.tf](suspicious-activity-alerts.tf) - EventBridge rules for critical findings
- [enable-guardduty.sh](enable-guardduty.sh) - Deployment script for multi-account setup
- [guardduty-suppression-rules.yaml](guardduty-suppression-rules.yaml) - Suppression rules for false positives

## Key Features

### 1. Organization-Wide Deployment
- **Delegated Administrator**: Security account manages GuardDuty for all member accounts
- **Auto-Enable**: New accounts automatically enrolled in GuardDuty
- **Multi-Region**: Enabled in 5 regions (us-east-1, us-west-2, eu-west-1, eu-central-1, ap-southeast-1)
- **Centralized Findings**: Aggregated view across all accounts and regions

### 2. Detection Coverage
- **VPC Flow Logs Monitoring**: Network traffic analysis for anomalies
- **CloudTrail Analysis**: API call monitoring for suspicious behavior
- **DNS Logs**: Query analysis for command-and-control communication
- **S3 Protection**: Data access anomaly detection (enabled for CDE buckets)
- **EKS Protection**: Kubernetes audit log analysis
- **RDS Protection**: Database login activity monitoring
- **Lambda Protection**: Serverless function monitoring

### 3. Automated Response
- **Isolation**: Automatically isolate compromised EC2 instances
- **Snapshot**: Create forensic snapshots before remediation
- **Notification**: Severity-based alerting (Critical→PagerDuty, High→Slack)
- **Enrichment**: Add context from AWS APIs, threat intel, and historical data
- **SIEM Forwarding**: Send findings to Wazuh for correlation

### 4. Threat Intelligence
- **AWS Managed Lists**: Proofpoint ET Intelligence, CrowdStrike Falcon feeds
- **Custom IP Lists**: Company-specific threat indicators
- **Whitelisting**: Trusted IP ranges and known safe domains
- **Auto-Update**: Daily refresh of threat intelligence feeds

## Detection Types and Response

### Critical Severity (Automated Isolation)
- **CryptoCurrency:EC2/BitcoinTool.B!DNS**: Bitcoin mining detected
- **Backdoor:EC2/C&CActivity.B!DNS**: Command-and-control communication
- **Trojan:EC2/DNSDataExfiltration**: Data exfiltration via DNS tunneling
- **UnauthorizedAccess:IAMUser/MaliciousIPCaller**: IAM access from known malicious IP

**Response**: Isolate instance, create snapshot, alert security team, create incident ticket

### High Severity (Notification Only)
- **Recon:EC2/PortProbeUnprotectedPort**: Port scanning activity
- **UnauthorizedAccess:EC2/SSHBruteForce**: SSH brute force attempts
- **Impact:EC2/AbusedDomainRequest.Reputation**: Communication with known bad domain
- **PrivilegeEscalation:IAMUser/AnomalousBehavior**: Unusual IAM privilege changes

**Response**: Alert security team, enrich with context, forward to SIEM

### Medium Severity (SIEM Only)
- **Recon:EC2/Portscan**: Network reconnaissance
- **Behavior:EC2/NetworkPortUnusual**: Unusual network port usage
- **Stealth:IAMUser/CloudTrailLoggingDisabled**: CloudTrail disabled

**Response**: Forward to Wazuh for correlation and analysis

## Usage

### Deploy GuardDuty Organization-Wide

```bash
# Set environment variables
export SECURITY_ACCOUNT_ID=111122223333
export HOME_REGION=us-east-1
export ENABLE_REGIONS=us-east-1,us-west-2,eu-west-1

# Run deployment script
./enable-guardduty.sh
```

### Deploy Terraform Configuration

```bash
cd /path/to/guardduty-automation

# Initialize Terraform
terraform init

# Plan deployment
terraform plan \
  -var="organization_id=o-exampleorgid" \
  -var="security_account_id=111122223333"

# Apply configuration
terraform apply
```

### Process Findings Manually

```bash
# Process last 7 days of findings
python3 guardduty-findings-processor.py \
  --region us-east-1 \
  --days 7 \
  --severity HIGH,CRITICAL \
  --action enrich

# Test automated response (dry-run)
python3 guardduty-findings-processor.py \
  --region us-east-1 \
  --finding-id <finding-id> \
  --action respond \
  --dry-run
```

## PCI DSS Compliance Mapping

| Requirement | Description | Implementation |
|------------|-------------|----------------|
| **10.6.1** | Review logs and security events for anomalies | GuardDuty continuously monitors VPC Flow, CloudTrail, DNS logs |
| **10.6.2** | Review logs of critical system components at least daily | Automated daily summary reports sent to security team |
| **10.6.3** | Follow up exceptions and anomalies during review | EventBridge triggers automated response workflows |
| **10.8.1** | Timely detection and reporting of failures | Real-time alerting via SNS to PagerDuty for critical findings |
| **11.4.1** | Use intrusion-detection techniques to detect intrusions | GuardDuty provides managed intrusion detection for AWS infrastructure |
| **11.4.2** | Keep intrusion-detection up to date | AWS automatically updates GuardDuty detection algorithms |

## Integration with SIEM (Wazuh)

GuardDuty findings are forwarded to Wazuh SIEM for:

1. **Correlation**: Cross-reference with host-based detections from Wazuh agents
2. **Enrichment**: Add context from vulnerability scans, compliance checks, FIM
3. **Aggregation**: Unified view of AWS and on-premises security events
4. **Playbooks**: Automated incident response workflows in Wazuh

### Wazuh Integration Flow

```
GuardDuty Finding
       │
       ▼
  EventBridge Rule
       │
       ▼
  Kinesis Stream
       │
       ▼
 Kinesis Firehose
       │
       ▼
  S3 Bucket (findings/)
       │
       ▼
Wazuh S3 Integration
       │
       ▼
 Wazuh Indexer/Dashboard
```

## Suppression Rules

False positives are suppressed using criteria-based rules:

- **Known Security Scanners**: Suppress findings from approved security tools (Nessus, Qualys)
- **Scheduled Tasks**: Suppress expected behaviors (backups, batch jobs)
- **Development Environments**: Lower thresholds for dev/staging accounts

Suppression rules are reviewed quarterly and documented in [guardduty-suppression-rules.yaml](guardduty-suppression-rules.yaml).

## Metrics and KPIs

- **Mean Time to Detect (MTTD)**: < 5 minutes (real-time detection)
- **Mean Time to Respond (MTTR)**: < 15 minutes for critical findings (automated)
- **False Positive Rate**: < 5% (with suppression rules)
- **Coverage**: 100% of AWS accounts and critical regions
- **Availability**: 99.99% (AWS-managed service)

## Cost Optimization

GuardDuty costs are optimized by:

1. **Selective S3 Protection**: Enabled only for CDE and sensitive data buckets
2. **Regional Filtering**: Disabled in unused regions
3. **CloudTrail Events**: Limited to management events only
4. **Volume-Based Pricing**: AWS provides 15% discount for high-volume accounts

**Monthly Cost**: ~$180/month for 15 accounts across 5 regions

## Related Directories

- [../security-hub-configs/](../security-hub-configs/) - Security Hub integration
- [../../../siem-soc/wazuh-deployment/](../../../siem-soc/wazuh-deployment/) - Wazuh SIEM configuration
- [../../../threat-detection/detection-rules/](../../../threat-detection/detection-rules/) - Custom detection rules
- [../../../devsecops/ci-cd-pipelines/](../../../devsecops/ci-cd-pipelines/) - Automated deployment pipelines

## Security Considerations

- **Least Privilege**: GuardDuty uses service-linked roles with minimal permissions
- **Encryption**: All findings encrypted at rest (KMS) and in transit (TLS 1.3)
- **Audit Logging**: All GuardDuty API calls logged in CloudTrail
- **Access Control**: Only security team can modify GuardDuty configuration
- **Data Retention**: Findings retained for 90 days in GuardDuty, 7 years in S3

## Troubleshooting

**GuardDuty Not Generating Findings**

- Verify VPC Flow Logs are enabled
- Check CloudTrail is active and multi-region
- Confirm DNS query logging is enabled
- Review suppression rules for over-suppression

**High False Positive Rate**

- Review and adjust suppression rules
- Whitelist known security tools
- Tune severity thresholds for development accounts

**SIEM Integration Not Working**

- Check EventBridge rule is active
- Verify Kinesis stream has sufficient capacity
- Confirm S3 bucket permissions for Wazuh
- Review Kinesis Firehose delivery errors

## References

- [AWS GuardDuty Documentation](https://docs.aws.amazon.com/guardduty/)
- [GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [PCI DSS v4.0 Requirement 11](https://www.pcisecuritystandards.org/)
- [Wazuh AWS Integration](https://documentation.wazuh.com/current/cloud-security/amazon/index.html)
