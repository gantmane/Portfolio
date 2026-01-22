# Infrastructure as Code

**Author**: Evgeniy Gantman
**Last Updated**: December 2025
**Purpose**: Secure, reusable IaC templates and automation

## Overview

This directory contains security-hardened Infrastructure as Code templates, including Terraform modules, Ansible playbooks, and CloudFormation templates with integrated compliance validation.

## Contents

### [Terraform Modules](terraform-modules/)
30+ reusable, security-hardened Terraform modules.
- AWS VPC with security group management
- EKS clusters with pod security
- RDS with encryption and backup
- S3 with versioning and encryption
- IAM roles with least-privilege policies

### [Ansible Playbooks](ansible-playbooks/)
CIS benchmark hardening and configuration management.
- Linux server hardening (CIS Level 1 & 2)
- Docker security configuration
- Kubernetes node hardening
- Compliance validation scripts

### [CloudFormation](cloudformation/)
AWS-native infrastructure templates.
- Security Hub enablement
- GuardDuty configuration
- Config rules deployment

### [Security Scanning](security-scanning/)
IaC security scanning integration.
- Checkov policies
- tfsec rules
- Terrascan configurations

### [Compliance Checks](compliance-checks/)
Automated CIS and PCI DSS validation.

## Key Features

| Feature | Description |
|---------|-------------|
| **Security by Default** | All modules include encryption, logging, least-privilege |
| **CIS Benchmark** | Ansible playbooks for CIS Level 1 & 2 |
| **Pre-commit Hooks** | Automated security scanning before commits |
| **Compliance Validation** | PCI DSS and CIS checks integrated |

## Security Scanning Integration

```bash
# Pre-commit security scanning
checkov -d terraform-modules/
tfsec terraform-modules/
terrascan scan -d terraform-modules/
```

## Related Sections

- [Cloud Security](../cloud-security/) - AWS security configurations
- [Kubernetes Security](../kubernetes-security/) - EKS infrastructure
- [Compliance](../compliance/) - Compliance automation
- [DevSecOps](../devsecops/) - CI/CD integration
