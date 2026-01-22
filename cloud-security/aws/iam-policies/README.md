# AWS IAM Policies

Least-privilege IAM policies and Identity Center configurations for secure cross-account access.

## Overview

This directory contains production-ready IAM policies implementing the principle of least-privilege for various roles and use cases. All policies follow AWS security best practices and include conditional access controls for MFA, source IP restrictions, and time-based access.

**Resume Achievement:** Implemented least-privilege IAM policies with IAM Identity Center (SSO) for centralized identity management across 15+ AWS accounts, achieving zero unauthorized access incidents and PCI DSS Requirement 7 & 8 compliance.

The policies are designed for a multi-account environment with strict security requirements, including PCI DSS compliant Cardholder Data Environment (CDE) access controls.

## Contents

- **README.md** - This file
- **metadata.yaml** - Directory metadata and compliance mappings
- **developer-policy.json** - Developer least-privilege policy (read + deploy)
- **devops-policy.json** - DevOps engineer policy with deployment and infrastructure permissions
- **readonly-policy.json** - Read-only auditor policy for compliance teams
- **cde-admin-policy.json** - CDE administrator policy with strict conditions
- **irsa-policies/** - Directory containing EKS IRSA policies for pods
- **permission-boundaries.json** - Permission boundary templates to prevent privilege escalation
- **identity-center-config.tf** - IAM Identity Center (SSO) Terraform configuration
- **validate-policies.py** - Python script to validate IAM policies

## Key Features

- **Least-privilege by default** - All policies grant minimum required permissions
- **Conditional access** - MFA required, source IP restrictions, time-based access
- **Permission boundaries** - Prevent privilege escalation
- **IRSA for EKS** - Service-specific policies for Kubernetes pods
- **Centralized SSO** - IAM Identity Center integration for 15+ accounts
- **PCI DSS compliant** - Strict CDE access controls with audit logging

## Policy Highlights

### Developer Policy
- Read access to most services
- Deploy permissions for non-production accounts only
- No access to CDE account (444455556666)
- MFA required for console access

### DevOps Policy
- Infrastructure management (EC2, EKS, RDS)
- Deployment permissions with region restrictions
- Read access to CloudWatch, logs
- Denied: CDE modifications, security service changes

### CDE Admin Policy
- Restricted to CDE account only
- Requires MFA + source IP from corporate network
- Session duration limited to 4 hours
- All actions logged to SIEM

### IRSA Policies
Kubernetes pod-level policies for:
- ALB Ingress Controller
- EBS CSI Driver
- External Secrets Operator
- Cert Manager
- Cluster Autoscaler

## Usage

### Validate Policies

```bash
# Validate all IAM policies
python3 validate-policies.py

# Check specific policy
python3 validate-policies.py --policy developer-policy.json
```

### Apply with Terraform

```bash
terraform init
terraform plan
terraform apply
```

### Test Policy Simulation

```bash
# Simulate policy for specific actions
aws iam simulate-custom-policy \
    --policy-input-list file://developer-policy.json \
    --action-names ec2:DescribeInstances s3:PutObject \
    --resource-arns arn:aws:s3:::example-bucket/*
```

## PCI DSS Compliance Mapping

| Requirement | Control | Implementation |
|------------|---------|----------------|
| Req 7 - Access Control | Least-privilege access | Role-based policies with minimum permissions |
| Req 7.1 | Need-to-know access | Policies scoped to specific resources and actions |
| Req 7.2 | Access control system | IAM Identity Center with SAML integration |
| Req 8 - Authentication | Unique user IDs | IAM Identity Center enforces unique identities |
| Req 8.2 | Strong authentication | MFA required via conditional policies |
| Req 8.3 | Multi-factor authentication | MFA enforced for all console and CDE access |
| Req 8.4 | Password requirements | Enforced via IAM password policy |

## Security Best Practices Implemented

1. **Explicit Deny for Sensitive Actions**
   - Root user actions denied
   - Security service modifications denied
   - CDE access restricted to authorized roles only

2. **Conditional Access Controls**
   ```json
   "Condition": {
     "Bool": {"aws:MultiFactorAuthPresent": "true"},
     "IpAddress": {"aws:SourceIp": ["10.0.0.0/8"]},
     "DateGreaterThan": {"aws:CurrentTime": "2024-01-01T00:00:00Z"}
   }
   ```

3. **Permission Boundaries**
   - Prevent users from escalating their own privileges
   - Block creation of users/roles with more permissions
   - Enforce tagging requirements

4. **Session Controls**
   - Maximum session duration enforced
   - Session tags for attribution
   - Automatic session expiration

## Related Directories

- [../multi-account-setup/](../multi-account-setup/) - AWS Organizations structure
- [../security-hub-configs/](../security-hub-configs/) - Centralized security monitoring
- [../../../compliance/pci-dss-4.0/](../../../compliance/pci-dss-4.0/) - PCI DSS Req 7 & 8 implementation

## References

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [IAM Policy Simulator](https://policysim.aws.amazon.com/)
- [PCI DSS v4.0 Requirement 7](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf)
