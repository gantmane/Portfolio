# AWS Security

Enterprise AWS security configurations for PCI DSS Level 1 compliance.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/cloud-security/aws){ .md-button .md-button--primary }

---

## Multi-Account Setup

### Account Structure

```
AWS Organizations
├── Management Account
│   └── Billing, Organizations, SSO
├── Security OU
│   ├── Security Account (GuardDuty, Security Hub)
│   └── Log Archive Account (CloudTrail, Config)
├── Infrastructure OU
│   ├── Network Account (Transit Gateway, VPN)
│   └── Shared Services (ECR, Artifacts)
├── Workloads OU
│   ├── Production Account
│   ├── Staging Account
│   └── Development Account
└── Sandbox OU
    └── Developer Sandbox Accounts
```

### Service Control Policies

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDisableCloudTrail",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## IAM Security

### Policies

- Least privilege enforcement
- Permission boundaries
- Service control policies
- Role-based access

### Best Practices

| Practice | Implementation |
|----------|----------------|
| No root usage | CloudWatch alarm on root login |
| MFA required | IAM policy condition |
| Credential rotation | 90-day maximum age |
| Access review | IAM Access Analyzer |

---

## GuardDuty

### Configuration

- All regions enabled
- S3 protection enabled
- Kubernetes protection enabled
- Malware protection enabled

### Finding Categories

| Category | Action |
|----------|--------|
| High severity | Immediate alert + auto-remediation |
| Medium severity | SOC review within 4 hours |
| Low severity | Weekly review |

---

## Security Hub

### Standards Enabled

- CIS AWS Foundations Benchmark
- PCI DSS v3.2.1
- AWS Foundational Security Best Practices

### Compliance Score

| Standard | Score |
|----------|-------|
| CIS | 95% |
| PCI DSS | 100% |
| AWS FSBP | 92% |

---

## Source Files

| File | Description |
|------|-------------|
| [multi-account-setup/](https://github.com/gantmane/Portfolio/tree/main/cloud-security/aws/multi-account-setup) | Organizations config |
| [iam-policies/](https://github.com/gantmane/Portfolio/tree/main/cloud-security/aws/iam-policies) | IAM examples |
| [security-hub/](https://github.com/gantmane/Portfolio/tree/main/cloud-security/aws/security-hub) | Security Hub config |
| [guardduty/](https://github.com/gantmane/Portfolio/tree/main/cloud-security/aws/guardduty) | GuardDuty config |
| [waf-shield/](https://github.com/gantmane/Portfolio/tree/main/cloud-security/aws/waf-shield) | WAF rules |
