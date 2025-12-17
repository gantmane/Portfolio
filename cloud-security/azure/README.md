# Azure Security Configuration

Multi-cloud security architecture evaluation with Azure as tertiary cloud provider for workload flexibility and vendor comparison.

## Overview

This directory contains Infrastructure as Code (Terraform), automation scripts, and security configurations for Microsoft Azure. The implementation demonstrates comprehensive multi-cloud security expertise across AWS (primary), GCP (secondary), and Azure (evaluation) environments.

### Key Achievements

- **Multi-Cloud Expertise**: Security architecture across AWS, GCP, and Azure
- **2 Azure Subscriptions**: Production and Development for evaluation
- **Azure Security Center**: Secure Score 95%+ with zero critical findings
- **Unified Identity**: Azure AD integration with corporate SSO
- **Hub-Spoke Network**: Secure network topology with Azure Firewall
- **Comparison Framework**: Side-by-side evaluation of AWS, GCP, and Azure services

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Azure Management Group                         │
│                (ExamplePay)                                 │
│                                                             │
│  ┌───────────────┐              ┌───────────────┐          │
│  │  Production   │              │ Development   │          │
│  │ Subscription  │              │ Subscription  │          │
│  │               │              │               │          │
│  │  - AKS        │              │  - AKS        │          │
│  │  - SQL DB     │              │  - SQL DB     │          │
│  │  - Storage    │              │  - Storage    │          │
│  └───────────────┘              └───────────────┘          │
│         │                              │                   │
│         └──────────────┬───────────────┘                   │
│                        │                                   │
│                 Hub Virtual Network                        │
│              (Shared Services + Firewall)                  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                   Azure ExpressRoute
                    (AWS ↔ Azure)
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    AWS Organization                         │
│                  (Primary Cloud)                            │
└─────────────────────────────────────────────────────────────┘
```

## Contents

- [README.md](README.md) - This file
- [metadata.yaml](metadata.yaml) - Directory metadata and compliance mappings
- [azure-management-groups.tf](azure-management-groups.tf) - Management groups and subscriptions
- [azure-rbac-policies.tf](azure-rbac-policies.tf) - RBAC roles and assignments
- [azure-network-security.tf](azure-network-security.tf) - VNet security and NSGs
- [azure-security-center.tf](azure-security-center.tf) - Azure Security Center configuration
- [azure-key-vault.tf](azure-key-vault.tf) - Key Vault encryption management
- [deploy-azure-security.sh](deploy-azure-security.sh) - Deployment automation script

## Key Features

### 1. Management Groups & Subscriptions
- **Management Group Hierarchy**: ExamplePay → Production, Development
- **Azure Policy**: Centralized policy enforcement
- **Subscription Governance**: Separate billing and RBAC per subscription
- **Resource Tags**: Consistent tagging for cost tracking and compliance

### 2. Identity and Access Management
- **Azure Active Directory**: Corporate SSO integration
- **Managed Identities**: No service principal credentials in code
- **Privileged Identity Management (PIM)**: Just-in-time admin access
- **Conditional Access**: Context-aware authentication policies
- **RBAC**: Role-based access control with custom roles

### 3. Network Security
- **Hub-Spoke Topology**: Centralized shared services with spoke VNets
- **Azure Firewall**: Centralized network filtering
- **Network Security Groups (NSGs)**: Subnet-level security rules
- **Application Security Groups (ASGs)**: Workload-based security
- **DDoS Protection**: Standard tier for all public IPs

### 4. Azure Security Center
- **Secure Score**: 95%+ security posture
- **Defender for Cloud**: Threat protection for workloads
- **Security Policies**: Built-in and custom policies
- **Recommendations**: Automated security improvements
- **Regulatory Compliance**: PCI DSS, CIS Azure Foundations

### 5. Key Vault Encryption
- **Centralized Secrets**: Secure storage for keys, secrets, certificates
- **Hardware Security Module (HSM)**: Premium tier for PCI DSS
- **Soft Delete**: 90-day retention for deleted secrets
- **Purge Protection**: Prevent permanent deletion
- **Private Link**: Private endpoint access to Key Vault

### 6. Monitoring and Logging
- **Azure Monitor**: Centralized monitoring platform
- **Log Analytics**: 7-year log retention for compliance
- **Microsoft Sentinel**: Cloud-native SIEM
- **Activity Logs**: All subscription operations logged
- **Diagnostic Settings**: Resource-level logging

## Usage

### Deploy Azure Security Infrastructure

```bash
# Set environment variables
export AZURE_TENANT_ID=12345678-1234-1234-1234-123456789012
export AZURE_SUBSCRIPTION_ID=87654321-4321-4321-4321-210987654321
export AZURE_REGION=eastus

# Run deployment script
./deploy-azure-security.sh
```

### Deploy Terraform Configuration

```bash
cd /path/to/azure

# Initialize Terraform
terraform init

# Plan deployment
terraform plan \
  -var="tenant_id=$AZURE_TENANT_ID" \
  -var="subscription_id=$AZURE_SUBSCRIPTION_ID"

# Apply configuration
terraform apply
```

### Verify Security Posture

```bash
# Check Azure Security Center secure score
az security secure-scores list \
  --subscription $AZURE_SUBSCRIPTION_ID

# Review security recommendations
az security assessment list \
  --subscription $AZURE_SUBSCRIPTION_ID

# Check Azure Policy compliance
az policy state summarize \
  --subscription $AZURE_SUBSCRIPTION_ID
```

## Multi-Cloud Comparison

| Feature | AWS | GCP | Azure | Primary Choice |
|---------|-----|-----|-------|----------------|
| **Compute** | EC2 | Compute Engine | Virtual Machines | AWS |
| **Containers** | EKS | GKE | AKS | AWS (EKS) |
| **Database** | RDS | Cloud SQL | Azure SQL | AWS (RDS) |
| **Object Storage** | S3 | Cloud Storage | Blob Storage | AWS (S3) |
| **IAM** | AWS IAM | Cloud IAM | Azure AD + RBAC | Azure AD (SSO) |
| **Network** | VPC | VPC | VNet | AWS (VPC) |
| **Encryption** | KMS | Cloud KMS | Key Vault | AWS (KMS) |
| **SIEM** | GuardDuty | SCC | Sentinel | Wazuh (unified) |
| **Cost** | Lowest | Medium | Highest | AWS |
| **Maturity** | Highest | Medium | Medium | AWS |

## Azure vs AWS/GCP

### Advantages of Azure
- **Azure AD Integration**: Best-in-class identity management
- **Microsoft Ecosystem**: Office 365, SharePoint, Teams integration
- **Hybrid Cloud**: Azure Arc for on-premises management
- **Enterprise Support**: Strong support for enterprise customers

### Disadvantages of Azure
- **Cost**: 20-30% more expensive than AWS for equivalent services
- **Complexity**: More complex networking model (VNet vs VPC)
- **Maturity**: Some services less mature than AWS equivalents
- **Learning Curve**: Different terminology and concepts

### Why AWS Remains Primary
1. **Cost Efficiency**: 20-30% lower costs than Azure
2. **Service Maturity**: More mature services (e.g., RDS, S3, Lambda)
3. **Ecosystem**: Larger partner ecosystem and community
4. **Existing Investment**: 15+ AWS accounts, established workflows

## Use Cases for Azure

### 1. Active Directory Integration
- **Use Case**: Enterprise SSO for all cloud services
- **Implementation**: Azure AD as identity provider
- **Integration**: SAML federation with AWS and GCP

### 2. Microsoft Workloads
- **Use Case**: SQL Server databases, Windows VMs
- **Implementation**: Azure SQL Database, Windows Server VMs
- **Cost Benefit**: Licensing included in Azure

### 3. Hybrid Cloud
- **Use Case**: On-premises integration via Azure Arc
- **Implementation**: Monitor on-prem servers in Azure Monitor
- **Benefit**: Unified management plane

### 4. Development/Testing
- **Use Case**: Compare Azure services against AWS/GCP
- **Implementation**: POCs and evaluations in Development subscription
- **Decision**: Choose best service for each workload

## PCI DSS Compliance Mapping

| Requirement | Description | Azure Implementation |
|------------|-------------|---------------------|
| **1.3** | Network segmentation | Hub-spoke VNets with NSGs |
| **2.2** | Configuration standards | Azure Policy enforces baselines |
| **7.1** | Limit access to cardholder data | RBAC + PIM for least privilege |
| **8.3** | Multi-factor authentication | Azure AD enforces MFA |
| **10.2** | Audit logs | Activity logs + Log Analytics (7 years) |
| **11.4** | Intrusion detection | Azure Defender for Cloud |
| **12.8** | Third-party service providers | Managed identities (no credentials) |

## Cost Breakdown

### Monthly Azure Costs
- **Compute (AKS)**: $100/month (2 small clusters)
- **Networking (VNet, Firewall)**: $70/month
- **Key Vault**: $5/month
- **Log Analytics**: $40/month (500GB/month)
- **Azure Security Center**: Free (Standard tier)
- **ExpressRoute**: $150/month (50 Mbps)

**Total Monthly**: ~$365/month (~$4,380/year)

**Note**: Azure is 54% more expensive than GCP ($236/month) for equivalent services, which is why AWS remains the primary cloud provider.

## Multi-Cloud Connectivity

### ExpressRoute to AWS
```
Azure VNet (10.1.0.0/16) ←→ ExpressRoute ←→ AWS VPC (10.0.0.0/16)
```

### Unified Logging
```
Azure Activity Logs → Log Analytics → Event Hub → AWS Kinesis → Wazuh SIEM
```

### Shared Identity
- **Primary**: Azure AD (corporate identity provider)
- **Federation**: SAML to AWS IAM Identity Center and Google Workspace
- **MFA**: Enforced at Azure AD level for all clouds

## Security Considerations

- **Least Privilege**: RBAC with custom roles following least privilege
- **Encryption**: All data encrypted at rest (Key Vault) and in transit (TLS 1.3)
- **Audit Logging**: All admin actions logged to Log Analytics (7-year retention)
- **Network Isolation**: Hub-spoke topology with Azure Firewall
- **Data Residency**: Resources deployed only in US East region
- **Backup**: Daily snapshots, 30-day retention

## Troubleshooting

### ExpressRoute Connection Down

**Symptoms**: No connectivity between Azure and AWS

**Solutions**:
1. Check ExpressRoute circuit status in Azure Portal
2. Verify AWS Direct Connect virtual interface status
3. Check route propagation in VNet route tables
4. Validate BGP peering session
5. Contact Azure support for circuit issues

### High Secure Score Alerts

**Symptoms**: Secure score drops below 90%

**Solutions**:
1. Review Security Center recommendations
2. Prioritize critical and high-severity items
3. Enable Defender for Cloud if not active
4. Update NSG rules to follow best practices
5. Enable diagnostic settings for all resources

### RBAC Permission Errors

**Symptoms**: Users cannot access resources

**Solutions**:
1. Review RBAC role assignments
2. Check Azure Policy denials
3. Verify conditional access policies
4. Use Azure AD PIM for just-in-time access
5. Check subscription-level restrictions

## Related Directories

- [../aws/](../aws/) - AWS security configurations (primary cloud)
- [../gcp/](../gcp/) - GCP security configurations (secondary cloud)
- [../../siem-soc/wazuh-deployment/](../../siem-soc/wazuh-deployment/) - Unified SIEM for all clouds
- [../../kubernetes-security/](../../kubernetes-security/) - AKS security hardening

## Decision Log

### Why Azure is Tertiary (Not Primary or Secondary)

**Date**: 2024-Q3

**Decision**: Use AWS as primary, GCP as secondary, Azure as tertiary

**Rationale**:
1. **Cost**: Azure is 20-30% more expensive than AWS
2. **Maturity**: AWS services more mature and feature-complete
3. **Team Expertise**: Team has more AWS experience
4. **Existing Investment**: 15+ AWS accounts already in production
5. **Use Azure for**: Active Directory, Microsoft workloads, evaluation

**Trade-offs**:
- Miss out on native Microsoft integration benefits
- More complex multi-cloud management
- Higher operational overhead

**Status**: Approved by CISO and CTO

## References

- [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/)
- [Azure Security Center](https://docs.microsoft.com/en-us/azure/security-center/)
- [Azure Policy](https://docs.microsoft.com/en-us/azure/governance/policy/)
- [Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/)
- [Azure PCI DSS Compliance](https://docs.microsoft.com/en-us/azure/compliance/offerings/offering-pci-dss)
- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
