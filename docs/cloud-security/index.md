# Cloud Security

Multi-cloud security configurations for AWS, Azure, and GCP.

74 files | 37 Terraform modules | CIS Benchmarks | NIST SP 800-53

## AWS

| File | Purpose |
|------|---------|
| kms-encryption/kms-keys.tf | KMS key definitions with automatic rotation |
| kms-encryption/key-rotation-policy.tf | 365-day rotation, CloudWatch alerting |
| kms-encryption/cross-account-sharing.tf | Cross-account key policies |
| kms-encryption/cloudhsm-integration.tf | CloudHSM cluster for FIPS 140-2 Level 3 |
| security-hub-configs/security-hub-config.tf | Security Hub aggregation region |
| security-hub-configs/security-standards.tf | CIS, PCI DSS, NIST standards enablement |
| security-hub-configs/automated-remediation.tf | Lambda-based auto-remediation |
| security-hub-configs/custom-insights.tf | Custom security findings dashboard |

## Azure

| File | Purpose |
|------|---------|
| azure-security-center.tf | Defender for Cloud configuration |
| azure-key-vault.tf | Key Vault with soft delete, purge protection |
| azure-network-security.tf | NSG, DDoS Protection, Private Link |
| azure-rbac-policies.tf | PIM, conditional access, role assignments |
| azure-management-groups.tf | Management group hierarchy, policy inheritance |

## GCP

| File | Purpose |
|------|---------|
| gcp-organization.tf | Organization policies, folder structure |
| gcp-iam-policies.tf | Workload Identity, service account constraints |
| gcp-vpc-security.tf | VPC Service Controls, Private Google Access |
| gcp-kms-encryption.tf | Cloud KMS, HSM-backed keys |
| gcp-security-command-center.tf | SCC Premium, threat detection |
