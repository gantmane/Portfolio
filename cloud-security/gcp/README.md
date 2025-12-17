# GCP Security Configuration

Multi-cloud security architecture extending security controls to Google Cloud Platform, supporting hybrid cloud operations across AWS and GCP.

## Overview

This directory contains Infrastructure as Code (Terraform), automation scripts, and security configurations for Google Cloud Platform. The implementation demonstrates multi-cloud security expertise and hybrid infrastructure management across AWS (primary) and GCP (secondary) environments.

### Key Achievements

- **Multi-Cloud Architecture**: Consistent security controls across AWS and GCP
- **3 GCP Projects**: Production, Development, and Shared Services
- **Zero GCP Security Findings**: Clean security posture via Security Command Center
- **Unified IAM**: Integration with corporate identity provider (Google Workspace)
- **VPC Service Controls**: Data exfiltration prevention for sensitive workloads
- **Hybrid Connectivity**: Secure VPN tunnels between AWS and GCP

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GCP Organization                         │
│                  (examplepay.com)                          │
│                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  │
│  │  Production   │  │ Development   │  │    Shared     │  │
│  │    Project    │  │    Project    │  │   Services    │  │
│  │               │  │               │  │               │  │
│  │  - GKE        │  │  - GKE        │  │  - CI/CD      │  │
│  │  - Cloud SQL  │  │  - Cloud SQL  │  │  - Artifacts  │  │
│  │  - Cloud      │  │  - Cloud      │  │  - Logging    │  │
│  │    Storage    │  │    Storage    │  │  - Monitoring │  │
│  └───────────────┘  └───────────────┘  └───────────────┘  │
│         │                   │                   │          │
│         └───────────────────┴───────────────────┘          │
│                            │                               │
│                   VPC Service Controls                     │
│                   (Perimeter Protection)                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                   Cloud Interconnect
                    (AWS ↔ GCP VPN)
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      AWS Organization                       │
│                    (Primary Cloud)                          │
└─────────────────────────────────────────────────────────────┘
```

## Contents

- [README.md](README.md) - This file
- [metadata.yaml](metadata.yaml) - Directory metadata and compliance mappings
- [gcp-organization.tf](gcp-organization.tf) - GCP Organization and folder structure
- [gcp-iam-policies.tf](gcp-iam-policies.tf) - IAM policies and service accounts
- [gcp-vpc-security.tf](gcp-vpc-security.tf) - VPC networks and firewall rules
- [gcp-security-command-center.tf](gcp-security-command-center.tf) - Security Command Center configuration
- [gcp-kms-encryption.tf](gcp-kms-encryption.tf) - Cloud KMS key management
- [deploy-gcp-security.sh](deploy-gcp-security.sh) - Deployment automation script

## Key Features

### 1. Organization Structure
- **Organization Policies**: Centralized policy enforcement
- **Folder Hierarchy**: Production, Development, Shared Services
- **Project Isolation**: Separate billing and IAM per project
- **Resource Hierarchy**: Inherited permissions and policies

### 2. Identity and Access Management
- **Google Workspace Integration**: Corporate SSO via SAML
- **Service Accounts**: Least-privilege automation accounts
- **IAM Conditions**: Context-aware access (IP, time, resource)
- **Workload Identity**: GKE pod-to-service authentication
- **IAM Recommender**: Automated privilege reduction suggestions

### 3. VPC Security
- **Private Google Access**: Service access without public IPs
- **Cloud NAT**: Controlled outbound internet access
- **Firewall Rules**: Deny-by-default with explicit allows
- **VPC Flow Logs**: Network traffic monitoring
- **Private Service Connect**: Private endpoints for Google APIs

### 4. VPC Service Controls
- **Data Perimeter**: Prevent data exfiltration
- **Service Perimeter**: Isolated environment for sensitive data
- **Access Levels**: Context-aware access policies
- **Ingress/Egress Rules**: Controlled data flow

### 5. Security Command Center
- **Asset Discovery**: Automated inventory of all GCP resources
- **Vulnerability Scanning**: Container and VM vulnerability detection
- **Security Health Analytics**: Built-in security checks
- **Event Threat Detection**: Anomaly detection for threats
- **Findings Management**: Centralized security findings

### 6. Encryption and Key Management
- **Cloud KMS**: Centralized key management
- **Customer-Managed Keys (CMEK)**: Encryption at rest control
- **Key Rotation**: Automatic 90-day rotation
- **HSM Protection**: Hardware security module backing
- **Key Access Logs**: Audit trail for key usage

## Usage

### Deploy GCP Security Infrastructure

```bash
# Set environment variables
export GCP_ORG_ID=123456789012
export GCP_BILLING_ACCOUNT=ABCDEF-123456-ABCDEF
export GCP_REGION=us-central1

# Run deployment script
./deploy-gcp-security.sh
```

### Deploy Terraform Configuration

```bash
cd /path/to/gcp

# Initialize Terraform
terraform init

# Plan deployment
terraform plan \
  -var="org_id=$GCP_ORG_ID" \
  -var="billing_account=$GCP_BILLING_ACCOUNT"

# Apply configuration
terraform apply
```

### Verify Security Posture

```bash
# Check Security Command Center findings
gcloud scc findings list \
  --organization=$GCP_ORG_ID \
  --filter="state=ACTIVE"

# Review IAM recommendations
gcloud recommender recommendations list \
  --project=$PROJECT_ID \
  --recommender=google.iam.policy.Recommender

# Audit organization policies
gcloud resource-manager org-policies list \
  --organization=$GCP_ORG_ID
```

## GCP vs AWS Security Comparison

| Feature | AWS | GCP | Implementation |
|---------|-----|-----|----------------|
| **Organization** | AWS Organizations | GCP Organization | Both configured |
| **IAM** | AWS IAM | Cloud IAM | Unified via SSO |
| **Network** | VPC | VPC | VPN interconnect |
| **Firewall** | Security Groups | Firewall Rules | Similar rules |
| **Threat Detection** | GuardDuty | Event Threat Detection | Both enabled |
| **Vulnerability Scanning** | Inspector | Container Scanning | Both enabled |
| **SIEM** | Wazuh (primary) | Cloud Logging → Wazuh | Unified SIEM |
| **Encryption** | KMS | Cloud KMS | CMEK in both |
| **Compliance** | Security Hub | Security Command Center | Both monitored |

## Multi-Cloud Use Cases

### 1. Disaster Recovery
- **Primary**: AWS (us-east-1, us-west-2)
- **DR Site**: GCP (us-central1)
- **RTO**: 4 hours
- **RPO**: 1 hour

### 2. Kubernetes Workloads
- **AWS**: EKS for production applications
- **GCP**: GKE for development and testing
- **Image Registry**: Artifact Registry (GCP) + ECR (AWS)

### 3. Data Processing
- **AWS**: Primary data lake (S3)
- **GCP**: BigQuery for analytics
- **Data Transfer**: Secure VPN + Cloud Storage Transfer Service

### 4. CI/CD Pipeline
- **AWS**: ECS for build agents
- **GCP**: Cloud Build for GKE deployments
- **Artifact Storage**: Nexus on GCP, ECR on AWS

## PCI DSS Compliance Mapping

| Requirement | Description | GCP Implementation |
|------------|-------------|-------------------|
| **1.3** | Prohibit direct public access to CDE | VPC Service Controls isolate CDE |
| **2.2** | Configuration standards | Organization Policies enforce standards |
| **7.1** | Limit access to cardholder data | IAM conditions + VPC Service Controls |
| **8.3** | Multi-factor authentication | Google Workspace enforces MFA |
| **10.2** | Audit logs | Cloud Logging with 7-year retention |
| **11.4** | Intrusion detection | Event Threat Detection enabled |
| **12.8** | Third-party service providers | Service accounts with least privilege |

## Cost Breakdown

### Monthly GCP Costs
- **Compute (GKE)**: $150/month (2 clusters, dev + prod)
- **Networking (VPN, NAT)**: $50/month
- **Cloud KMS**: $6/month (20 keys)
- **Cloud Logging**: $30/month (500GB/month)
- **Security Command Center**: Free (Standard tier)
- **VPC Service Controls**: Free

**Total Monthly**: ~$236/month (~$2,832/year)

## Integration with AWS

### VPN Tunnel Configuration
```
AWS VPC (10.0.0.0/16) ←→ Cloud VPN ←→ GCP VPC (172.16.0.0/16)
```

### Unified Logging
```
GCP Cloud Logging → Pub/Sub → AWS Kinesis → Wazuh SIEM
```

### Shared Services
- **DNS**: Route53 (AWS) with Cloud DNS (GCP) forwarding
- **Secrets**: AWS Secrets Manager + GCP Secret Manager
- **Monitoring**: CloudWatch (AWS) + Cloud Monitoring (GCP) → Grafana

## Security Considerations

- **Least Privilege**: Service accounts follow principle of least privilege
- **Encryption**: All data encrypted at rest (CMEK) and in transit (TLS 1.3)
- **Audit Logging**: All admin actions logged to Cloud Logging
- **Network Isolation**: Private Google Access, no public IPs
- **Data Residency**: Data stays in us-central1 region
- **Backup**: Daily snapshots, 30-day retention

## Troubleshooting

### VPN Tunnel Down

**Symptoms**: No connectivity between AWS and GCP

**Solutions**:
1. Check Cloud VPN status in GCP Console
2. Verify AWS VPN connection status
3. Check firewall rules allow VPN traffic
4. Review Cloud Router BGP sessions
5. Validate pre-shared keys match

### IAM Permission Errors

**Symptoms**: Service account access denied

**Solutions**:
1. Review IAM policy bindings
2. Check organization policies (constraints)
3. Verify service account key validity
4. Use `gcloud policy-analyzer` for debugging
5. Check IAM Recommender for suggestions

### Security Command Center Alerts

**Symptoms**: Active security findings

**Solutions**:
1. Review finding details in SCC console
2. Check severity and category
3. Follow remediation recommendations
4. Update firewall rules or IAM policies
5. Mark as resolved after fixing

## Related Directories

- [../aws/](../aws/) - AWS security configurations
- [../../kubernetes-security/](../../kubernetes-security/) - GKE security hardening
- [../../siem-soc/wazuh-deployment/](../../siem-soc/wazuh-deployment/) - Unified SIEM for AWS + GCP
- [../../devsecops/ci-cd-pipelines/](../../devsecops/ci-cd-pipelines/) - Multi-cloud CI/CD

## References

- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [VPC Service Controls](https://cloud.google.com/vpc-service-controls)
- [Security Command Center](https://cloud.google.com/security-command-center)
- [Cloud KMS Documentation](https://cloud.google.com/kms/docs)
- [GCP PCI DSS Compliance](https://cloud.google.com/security/compliance/pci-dss)
