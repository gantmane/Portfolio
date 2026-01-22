# Infrastructure as Code

Secure IaC templates with Terraform and Ansible.

[:octicons-code-24: View Source Code](https://github.com/gantmane/Portfolio/tree/main/infrastructure-as-code){ .md-button .md-button--primary }

---

## Overview

30+ security-hardened Terraform modules and Ansible playbooks enabling 90% infrastructure automation with built-in compliance validation.

---

## Module Inventory

### Terraform Modules

| Module | Purpose | Security Features |
|--------|---------|-------------------|
| VPC | Network foundation | Flow logs, NACLs, private subnets |
| EKS | Kubernetes cluster | Encryption, OIDC, private API |
| RDS | Database | Encryption, IAM auth, backups |
| S3 | Object storage | Encryption, versioning, policies |
| KMS | Key management | Key rotation, policies |
| IAM | Identity | Least privilege, boundaries |

[:octicons-arrow-right-24: View Terraform Modules](terraform.md)

---

### Ansible Playbooks

| Playbook | Purpose | Compliance |
|----------|---------|------------|
| CIS Hardening | OS security | CIS Benchmark Level 2 |
| Wazuh Agent | SIEM deployment | PCI DSS 10.x |
| Log Forwarding | Centralized logging | PCI DSS 10.x |
| Patch Management | Security updates | PCI DSS 6.x |

---

## Security Scanning

### Pre-commit Checks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    hooks:
      - id: terraform_fmt
      - id: terraform_validate
      - id: terraform_tflint
      - id: terraform_tfsec
      - id: checkov
```

### Pipeline Integration

| Tool | Purpose | Blocking |
|------|---------|----------|
| tfsec | Security scanning | High/Critical |
| Checkov | Policy compliance | Failed checks |
| Terrascan | Compliance | PCI DSS violations |
| OPA/Conftest | Custom policies | Policy failures |

---

## Automation Metrics

| Metric | Value |
|--------|-------|
| Infrastructure Automation | 90% |
| Deployment Time | 15 min (was 4 hours) |
| Configuration Drift | <1% |
| Compliance Pass Rate | 99%+ |

---

## Source Files

| Directory | Description |
|-----------|-------------|
| [terraform-modules/](https://github.com/gantmane/Portfolio/tree/main/infrastructure-as-code/terraform-modules) | Terraform modules |
| [ansible-playbooks/](https://github.com/gantmane/Portfolio/tree/main/infrastructure-as-code/ansible-playbooks) | Ansible automation |
| [cloudformation/](https://github.com/gantmane/Portfolio/tree/main/infrastructure-as-code/cloudformation) | CloudFormation templates |
