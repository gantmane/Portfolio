# Cloud Security

AWS, GCP, and multi-cloud security implementations for enterprise environments.

[:octicons-code-24: View All Source Code](https://github.com/gantmane/Portfolio/tree/main/cloud-security){ .md-button .md-button--primary }

---

## Overview

Production cloud security configurations from PCI DSS Level 1 compliant payment processing environments, covering multi-account architectures, IAM, networking, and security services.

---

## AWS Security

### Multi-Account Architecture

15+ account structure using AWS Organizations and Control Tower:

- **Management Account** - Organizations, billing, SSO
- **Security Account** - GuardDuty, Security Hub, CloudTrail
- **Log Archive** - Centralized logging with immutable storage
- **Network Account** - Transit Gateway, VPN, Direct Connect
- **Production Accounts** - Workload isolation
- **Development Accounts** - Non-production environments

[:octicons-arrow-right-24: View AWS Security](aws.md)

---

### Security Services

| Service | Purpose | Configuration |
|---------|---------|---------------|
| GuardDuty | Threat detection | Multi-region, S3 protection |
| Security Hub | Posture management | CIS, PCI DSS standards |
| CloudTrail | Audit logging | Organization trail, S3 + CloudWatch |
| Config | Compliance | 150+ rules, auto-remediation |
| IAM Access Analyzer | Permissions | External access detection |

---

## Zero Trust Architecture

### Implementation Components

- **Identity**: AWS SSO + MFA enforcement
- **Device**: Certificate-based authentication
- **Network**: Micro-segmentation via Security Groups
- **Application**: Service mesh (Istio) with mTLS
- **Data**: Encryption at rest and in transit

[:octicons-arrow-right-24: View Zero Trust](zero-trust.md)

---

## Network Security

### VPC Design

```
┌─────────────────────────────────────────────┐
│              Transit Gateway                │
├─────────────────────────────────────────────┤
│                                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐     │
│  │ Prod    │  │ Dev     │  │ Shared  │     │
│  │ VPC     │  │ VPC     │  │ Services│     │
│  └─────────┘  └─────────┘  └─────────┘     │
│                                             │
└─────────────────────────────────────────────┘
```

### Security Controls

- VPC Flow Logs to S3 + CloudWatch
- Network Firewall for egress filtering
- PrivateLink for AWS service access
- WAF + Shield for DDoS protection

---

## Source Files

| Directory | Description |
|-----------|-------------|
| [aws/](https://github.com/gantmane/Portfolio/tree/main/cloud-security/aws) | AWS security configurations |
| [gcp/](https://github.com/gantmane/Portfolio/tree/main/cloud-security/gcp) | GCP security configurations |
| [azure/](https://github.com/gantmane/Portfolio/tree/main/cloud-security/azure) | Azure security configurations |
| [zero-trust-architecture/](https://github.com/gantmane/Portfolio/tree/main/cloud-security/zero-trust-architecture) | Zero Trust implementation |
| [cspm-automation/](https://github.com/gantmane/Portfolio/tree/main/cloud-security/cspm-automation) | Cloud security posture |
