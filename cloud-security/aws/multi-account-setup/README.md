# AWS Multi-Account Setup

AWS Organizations and Control Tower landing zone configuration for secure, scalable multi-account architecture.

## Overview

This directory contains Infrastructure as Code (IaC) for deploying an enterprise-grade AWS multi-account setup using AWS Organizations and Control Tower. The architecture follows AWS Well-Architected Framework principles and implements security best practices with 15+ accounts organized across multiple Organizational Units (OUs).

**Resume Achievement:** Architected AWS multi-account landing zone with 15+ accounts, implementing centralized governance, security, and compliance controls achieving PCI DSS Level 1 compliance with zero audit findings.

The implementation provides:
- Centralized identity management with IAM Identity Center
- Automated account provisioning and baseline configuration
- Service Control Policies (SCPs) for guardrails
- Centralized logging and security monitoring
- Cross-account role automation for secure access

## Contents

- **README.md** - This file
- **metadata.yaml** - Directory metadata and dependencies
- **organizations-structure.tf** - AWS Organizations with 15+ accounts and OUs
- **control-tower-baseline.tf** - Control Tower configuration with security baseline
- **scp-policies.json** - 10+ Service Control Policies for security guardrails
- **account-factory.py** - Python script for automated account provisioning
- **cross-account-roles.tf** - IAM roles for cross-account access patterns
- **deploy-landing-zone.sh** - Automated deployment and validation script

## Key Features

- **15+ AWS accounts** organized across Security, Production, Development, CDE, and Sandbox OUs
- **Zero audit findings** - PCI DSS Level 1 compliant multi-account structure
- **Automated provisioning** with Control Tower Account Factory
- **10+ SCPs** enforcing encryption, MFA, region restrictions, and preventing security control disablement
- **Centralized logging** with automatic CloudTrail, Config, and GuardDuty enablement
- **Least-privilege access** with cross-account roles and IAM Identity Center integration

## Organizational Structure

```
Root
├── Security OU (111122223333)
│   ├── Log Archive Account
│   ├── Security Audit Account
│   └── Security Tooling Account
├── Production OU (222233334444)
│   ├── Prod Application Account
│   ├── Prod Data Account
│   └── CDE Account (444455556666) - Cardholder Data Environment
├── Development OU (333344445555)
│   ├── Dev Application Account
│   ├── Dev Data Account
│   └── Staging Account
└── Sandbox OU
    ├── Sandbox 1
    └── Sandbox 2
```

## Usage

### Initial Deployment

```bash
# Deploy landing zone
./deploy-landing-zone.sh

# Provision new account
python account-factory.py --name "prod-app-01" --email prod-app@example.com --ou Production
```

### Terraform Deployment

```bash
# Initialize and deploy organizations structure
cd terraform/
terraform init
terraform plan
terraform apply

# Deploy Control Tower baseline
terraform apply -target=module.control_tower
```

## PCI DSS Compliance Mapping

| Requirement | Control | Implementation |
|------------|---------|----------------|
| Req 1 - Network Security | Network segmentation | Dedicated CDE account with isolated VPC |
| Req 2 - Secure Configuration | Configuration standards | Control Tower baseline with AWS Config rules |
| Req 7 - Access Control | Least-privilege access | Cross-account roles with conditions, IAM Identity Center |
| Req 10 - Logging | Centralized logging | Automatic CloudTrail to Log Archive account |
| Req 12 - Security Policy | Preventive controls | SCPs enforcing security guardrails |

## Service Control Policies

The following SCPs are automatically applied:

1. **DenyLeaveOrganization** - Prevent accounts from leaving organization
2. **RequireMFA** - Enforce MFA for console access
3. **EnforceEncryption** - Require encryption for S3, EBS, RDS
4. **RestrictRegions** - Limit operations to approved regions
5. **DenyPublicS3** - Prevent public S3 bucket access
6. **ProtectSecurityServices** - Prevent disabling CloudTrail, Config, GuardDuty
7. **DenyRootUser** - Restrict root user actions
8. **EnforceTagging** - Require specific tags on resources
9. **PreventSecurityGroupChanges** - Restrict security group modifications in CDE
10. **LimitInstanceTypes** - Restrict to approved EC2 instance types

## Cross-Account Access Patterns

Implemented cross-account roles:
- **SecurityAuditRole** - Read-only access for security team
- **NetworkAdminRole** - Network management across accounts
- **DeploymentRole** - CI/CD pipeline deployment access
- **BreakGlassRole** - Emergency access (requires MFA, logged to SIEM)

## Automation Features

- **Automatic baseline** - New accounts automatically configured with:
  - CloudTrail enabled (all regions)
  - AWS Config enabled with recording
  - GuardDuty enabled with S3 protection
  - Security Hub enabled with PCI DSS standard
  - Default encryption enabled
  - VPC Flow Logs to centralized logging

## Related Directories

- [../iam-policies/](../iam-policies/) - IAM policies for cross-account access
- [../security-hub-configs/](../security-hub-configs/) - Centralized security monitoring
- [../../infrastructure-as-code/terraform-modules/](../../infrastructure-as-code/terraform-modules/) - Reusable Terraform modules

## References

- [AWS Organizations Best Practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices.html)
- [AWS Control Tower](https://aws.amazon.com/controltower/)
- [AWS Multi-Account Strategy](https://aws.amazon.com/organizations/getting-started/best-practices/)
