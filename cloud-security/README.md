# Cloud Security

This directory contains cloud security implementations, configurations, and best practices for AWS, GCP, Azure, and multi-cloud environments.

## Contents

### [AWS](aws/)
Production-ready AWS security configurations and architectures

#### [Multi-Account Setup](aws/multi-account-setup/)
- AWS Organizations structure
- Control Tower landing zone configurations
- Service Control Policies (SCPs)
- Account baseline templates
- Cross-account role configurations

#### [IAM Policies](aws/iam-policies/)
- Least-privilege IAM policies
- IAM Identity Center (SSO) configurations
- Permission boundaries
- Service-specific policies
- IRSA (IAM Roles for Service Accounts) for EKS

#### [Security Hub Configs](aws/security-hub-configs/)
- Multi-account Security Hub setup
- Custom security standards
- Automated remediation workflows
- Integration with SIEM
- Compliance reporting automation

#### [GuardDuty Automation](aws/guardduty-automation/)
- Multi-account GuardDuty deployment
- Custom threat detection rules
- Automated response workflows
- S3 protection configurations
- EKS protection settings

#### [KMS Encryption](aws/kms-encryption/)
- Customer Managed Keys (CMK) configurations
- Key rotation automation
- Cross-account key sharing
- Envelope encryption patterns
- CloudHSM integration

#### [VPC Network Security](aws/vpc-network-security/)
- Hub-and-spoke topology with Transit Gateway
- VPC Flow Logs analysis
- Network segmentation patterns
- AWS Network Firewall rules
- PrivateLink configurations

#### [WAF & Shield](aws/waf-shield/)
- WAF rules and rule groups
- Rate limiting configurations
- Bot protection
- Shield Advanced DDoS protection
- CloudFront security configurations

### [GCP](gcp/)
- GKE security configurations
- Cloud Armor policies
- VPC Service Controls
- Identity and Access Management

### [Azure](azure/)
- Azure Security Center configurations
- Network Security Groups
- Azure Policy definitions
- Sentinel integration

### [Zero Trust Architecture](zero-trust-architecture/)
- Identity verification patterns
- Device trust configurations
- Network micro-segmentation
- Continuous verification workflows
- BeyondCorp implementation guides

## Key Concepts

### AWS Multi-Account Strategy
Best practices for organizing workloads across multiple AWS accounts for security isolation, compliance, and cost management.

### Network Segmentation
Implementing defense-in-depth with multiple layers:
- VPC isolation for different environments (prod, staging, dev)
- Dedicated CDE (Cardholder Data Environment) VPC for PCI compliance
- Private subnets for data layer
- Public subnets for load balancers only
- Transit Gateway for controlled inter-VPC communication

### Data Protection
- Encryption at rest (EBS, S3, RDS, EFS)
- Encryption in transit (TLS 1.3, mTLS)
- Key management and rotation
- Data classification and handling

### Identity & Access Management
- Centralized identity with IAM Identity Center
- MFA enforcement for all human access
- Service accounts with least-privilege
- Just-in-time access patterns
- Session recording and monitoring

## PCI DSS Implementation

Security controls mapping to PCI DSS 4.0 requirements:

**Requirement 1 & 2:** Network segmentation, CDE isolation, secure baseline configurations
**Requirement 3 & 4:** KMS encryption, tokenization, TLS enforcement
**Requirement 7 & 8:** IAM least-privilege, MFA, centralized authentication
**Requirement 10:** Comprehensive logging with CloudTrail and VPC Flow Logs
**Requirement 11:** GuardDuty, Security Hub, vulnerability scanning

## Related Directories
- [Compliance](../compliance/) - Compliance automation and frameworks
- [Infrastructure as Code](../infrastructure-as-code/) - IaC for cloud security
- [Monitoring & Observability](../monitoring-observability/) - Security monitoring
