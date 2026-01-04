# Cloud Security Posture Management (CSPM)

**Author**: Evgeniy Gantman
**Cloud Accounts Monitored**: 25 AWS accounts
**Misconfigurations Detected**: 1,800+ annually
**Auto-Remediation Rate**: 85%

## Overview
Cloud Security Posture Management using AWS Security Hub, Config, and custom automation to detect and remediate 1,800+ cloud misconfigurations annually across 25 AWS accounts with 85% auto-remediation rate.

## Key Metrics
- **AWS Accounts Monitored**: 25
- **Misconfigurations Detected/Year**: 1,800+
- **Auto-Remediation Rate**: 85%
- **Manual Review Required**: 15%
- **Compliance Frameworks**: CIS, PCI DSS, NIST
- **Security Score**: 95/100
- **Mean Time to Remediate**: 15 minutes

## Common Misconfigurations Detected

### Critical (Auto-Remediated)
1. **S3 Buckets Public**: 120/year → Block public access
2. **Security Groups 0.0.0.0/0**: 85/year → Restrict to specific IPs
3. **Unencrypted EBS**: 65/year → Enable encryption
4. **Root Account Usage**: 12/year → Alert + MFA enforcement
5. **Exposed RDS**: 8/year → Move to private subnet

### High (Auto-Remediated)
1. **MFA Not Enabled**: 250/year → Enforce MFA
2. **Old Access Keys**: 180/year → Rotate credentials
3. **Overly Permissive IAM**: 320/year → Apply least privilege
4. **CloudTrail Disabled**: 15/year → Re-enable logging
5. **VPC Flow Logs Missing**: 45/year → Enable flow logs

## Technology Stack
- AWS Security Hub
- AWS Config Rules
- AWS Systems Manager
- Lambda (auto-remediation)
- CloudWatch Events

## Resume Achievements
- **"1,800+ misconfigurations detected annually"**: Comprehensive CSPM across 25 accounts
- **"85% auto-remediation rate"**: Automated fixes for common issues
- **"95/100 security score"**: Continuous posture improvement
- **"15-minute MTTR"**: Rapid remediation via automation
