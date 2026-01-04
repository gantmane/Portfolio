# IAM Automation & Access Management

**Author**: Evgeniy Gantman
**Users Managed**: 1,200+
**Automated Provisioning**: 100%
**Access Reviews**: Monthly (automated)

## Overview
Comprehensive IAM automation using AWS IAM, Okta SSO, and automated provisioning/deprovisioning workflows managing 1,200+ users with 100% automation and monthly access reviews.

## Key Metrics
- **Users Managed**: 1,200+ across all systems
- **Automated Provisioning**: 100% (zero manual user creation)
- **Deprovisioning Time**: <1 hour from termination
- **Access Reviews**: Monthly automated reconciliation
- **MFA Enforcement**: 100% coverage
- **Orphaned Accounts**: 0 (automated cleanup)
- **Policy Violations**: 45/month detected and auto-remediated

## IAM Automation

### User Lifecycle Management
1. **Onboarding** (Automated)
   - New hire in Workday → Webhook to Lambda
   - Create Okta account with appropriate groups
   - Provision AWS IAM via SAML federation
   - Generate temporary credentials
   - Send welcome email with setup instructions
   - **Time**: <5 minutes (vs 2 hours manual)

2. **Role Changes** (Automated)
   - Job change in Workday → Update Okta groups
   - AWS IAM roles updated via group mappings
   - Access recertification triggered
   - Manager approval required for elevated access

3. **Offboarding** (Automated)
   - Termination in Workday → Immediate trigger
   - Disable Okta account (SSO blocked)
   - Revoke all AWS sessions
   - Rotate credentials they had access to
   - Archive user data to compliance storage
   - **Time**: <1 hour (PCI DSS requirement: same day)

### Least Privilege Enforcement
- **IAM Access Analyzer**: Continuous monitoring for overly permissive policies
- **Policy Validation**: CloudFormation hooks prevent privilege escalation
- **Permission Boundaries**: Applied to all roles automatically
- **Unused Access**: Removed after 90 days of inactivity

### Access Reviews
**Monthly Automated Process**:
1. Generate access report from AWS IAM Access Analyzer
2. Send to managers via email with approval links
3. Managers review and certify team access
4. Auto-revoke if not certified within 7 days
5. **Compliance**: SOC 2, PCI DSS quarterly access reviews

## Technology Stack
- **Okta**: SSO and identity provider
- **AWS IAM**: Cloud access management
- **Workday**: HR system (source of truth)
- **Lambda**: Automation workflows
- **DynamoDB**: Access review tracking
- **Slack**: Manager notifications

## Resume Achievements
- **"1,200+ users managed via IAM automation"**: 100% automated provisioning/deprovisioning
- **"<1 hour deprovisioning time"**: Immediate access revocation on termination
- **"100% MFA enforcement"**: Zero exceptions across all users
- **"Monthly access reviews"**: Automated certification reducing audit prep by 90%

## Files in This Directory
- `README.md`: This documentation
- `metadata.yaml`: Project metadata
- `user-provisioning.py`: Automated user lifecycle
- `access-review.py`: Monthly access certification
