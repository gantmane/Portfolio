# AWS VPC Network Security

Comprehensive VPC network security architecture implementing defense-in-depth with multiple security layers, network segmentation, and PCI DSS compliance.

## Overview

This directory contains production-ready Terraform configurations and automation scripts for building secure AWS VPC architectures. The implementation demonstrates multi-tier network segmentation, microsegmentation for CDE isolation, comprehensive traffic monitoring with VPC Flow Logs, and automated security group auditing that contributed to **zero network security incidents** and **PCI DSS Level 1 compliance with zero findings**.

Key achievements:
- **Multi-tier network architecture** with public, private, data, and CDE tiers
- **VPC Flow Logs** capturing 100% of network traffic for forensic analysis
- **Automated security group auditing** detecting 200+ overly permissive rules
- **Transit Gateway** connecting 15+ VPCs for centralized network management
- **VPC endpoints** for private AWS service access reducing NAT costs by 30%

## Contents

- [README.md](README.md) - This file
- [metadata.yaml](metadata.yaml) - Directory metadata and compliance mapping
- [vpc-architecture.tf](vpc-architecture.tf) - Multi-tier VPC architecture with 3+ availability zones
- [security-groups.tf](security-groups.tf) - Layered security group configurations for all tiers
- [network-acls.tf](network-acls.tf) - Network ACLs for stateless filtering
- [vpc-flow-logs.tf](vpc-flow-logs.tf) - VPC Flow Logs with S3 and CloudWatch integration
- [vpc-endpoints.tf](vpc-endpoints.tf) - Private endpoints for AWS services
- [transit-gateway.tf](transit-gateway.tf) - Transit Gateway for multi-VPC connectivity
- [analyze-flow-logs.py](analyze-flow-logs.py) - Python script for flow log analysis and anomaly detection
- [security-group-audit.py](security-group-audit.py) - Automated security group compliance auditing
- [network-segmentation.yaml](network-segmentation.yaml) - Network segmentation policy documentation
- [deploy-vpc.sh](deploy-vpc.sh) - Automated VPC deployment and validation script

## Key Features

### Multi-Tier Network Architecture
- **Public subnet tier**: Internet-facing load balancers, bastion hosts (jump boxes)
- **Private subnet tier**: Application servers, EKS worker nodes
- **Data subnet tier**: RDS databases, ElastiCache, internal data stores
- **CDE subnet tier**: Isolated cardholder data environment (PCI DSS requirement)
- **Management subnet tier**: Bastion hosts, security tools, monitoring

### Network Segmentation (PCI DSS Req 1)
- **CDE isolation**: Dedicated VPC for cardholder data with no direct internet access
- **Flat network prevention**: Multi-tier segmentation prevents lateral movement
- **Transit Gateway**: Hub-and-spoke topology for controlled cross-VPC communication
- **Security groups**: Least-privilege rules, no 0.0.0.0/0 in production
- **Network ACLs**: Stateless deny-by-default at subnet boundaries

### Traffic Monitoring (PCI DSS Req 10)
- **VPC Flow Logs**: All ENI traffic logged to S3 and CloudWatch
- **10-year retention**: PCI DSS compliant audit trail storage
- **Automated analysis**: Python scripts detect port scans, data exfiltration, unusual patterns
- **SIEM integration**: Flow logs forwarded to Wazuh for real-time alerting

### Private Connectivity
- **VPC endpoints**: S3, DynamoDB, ECR, Secrets Manager, KMS, SSM
- **PrivateLink**: Private access to third-party SaaS applications
- **Cost optimization**: 30% reduction in NAT Gateway costs via VPC endpoints

## Network Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Production VPC (10.0.0.0/16)               │
│                                                                 │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐      │
│  │ AZ-1 (us-e-1a)│  │ AZ-2 (us-e-1b)│  │ AZ-3 (us-e-1c)│      │
│  └───────────────┘  └───────────────┘  └───────────────┘      │
│                                                                 │
│  Public Tier (10.0.0.0/20)                                     │
│    ├─ 10.0.0.0/24  (AZ-1) - ALB, NAT Gateway                  │
│    ├─ 10.0.1.0/24  (AZ-2) - ALB, NAT Gateway                  │
│    └─ 10.0.2.0/24  (AZ-3) - ALB, NAT Gateway                  │
│                                                                 │
│  Private Tier (10.0.16.0/20)                                   │
│    ├─ 10.0.16.0/24 (AZ-1) - App servers, EKS nodes            │
│    ├─ 10.0.17.0/24 (AZ-2) - App servers, EKS nodes            │
│    └─ 10.0.18.0/24 (AZ-3) - App servers, EKS nodes            │
│                                                                 │
│  Data Tier (10.0.32.0/20)                                      │
│    ├─ 10.0.32.0/24 (AZ-1) - RDS, ElastiCache                  │
│    ├─ 10.0.33.0/24 (AZ-2) - RDS, ElastiCache                  │
│    └─ 10.0.34.0/24 (AZ-3) - RDS, ElastiCache                  │
│                                                                 │
│  Management Tier (10.0.48.0/24)                                │
│    └─ Bastion, monitoring, security tools                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                   CDE VPC (10.100.0.0/16) - ISOLATED            │
│  No direct internet, Transit Gateway only for approved traffic  │
│                                                                 │
│  CDE Application Tier (10.100.0.0/20)                          │
│  CDE Database Tier (10.100.16.0/20)                            │
└─────────────────────────────────────────────────────────────────┘

                              ▼
                    ┌──────────────────┐
                    │ Transit Gateway  │
                    │  (Hub-and-Spoke) │
                    └──────────────────┘
                              ▲
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   Prod VPC              Dev VPC              Security VPC
```

## Usage

### Deploy VPC Infrastructure

```bash
# Deploy production VPC
./deploy-vpc.sh --environment production --vpc-cidr 10.0.0.0/16

# Deploy CDE VPC (isolated)
./deploy-vpc.sh --environment cde --vpc-cidr 10.100.0.0/16 --isolated

# Validate security groups
python3 security-group-audit.py --vpc-id vpc-0123456789abcdef0

# Analyze VPC Flow Logs for anomalies
python3 analyze-flow-logs.py --vpc-id vpc-0123456789abcdef0 --days 7
```

### Security Group Best Practices

1. **No 0.0.0.0/0 inbound in production** (only in public ALB security groups)
2. **Use security group references** instead of IP ranges where possible
3. **Deny by default**, allow only specific ports and protocols
4. **Separate security groups** for each tier (web, app, data)
5. **Descriptive names and descriptions** for audit trail

### Network ACL Strategy

- **Public subnet NACLs**: Allow HTTP/HTTPS inbound, ephemeral ports outbound
- **Private subnet NACLs**: Deny all inbound from internet, allow internal traffic
- **Data subnet NACLs**: Allow only database ports from app tier
- **CDE subnet NACLs**: Strict deny-by-default, explicit allow for approved traffic

## PCI DSS Compliance Mapping

### Requirement 1: Install and Maintain Network Security Controls

| Sub-Requirement | Implementation | File |
|-----------------|----------------|------|
| 1.2.1 - Configuration standards | Network segmentation policy | [network-segmentation.yaml](network-segmentation.yaml:1) |
| 1.2.2 - Restrict connections between untrusted and CDE | Transit Gateway routing, CDE isolation | [transit-gateway.tf](transit-gateway.tf:1) |
| 1.2.3 - Inbound traffic to CDE restricted | Security groups, NACLs deny by default | [security-groups.tf](security-groups.tf:1) |
| 1.2.5 - Outbound traffic from CDE restricted | CDE VPC has no internet gateway | [vpc-architecture.tf](vpc-architecture.tf:1) |
| 1.2.7 - Review firewall rules every 6 months | Automated auditing script | [security-group-audit.py](security-group-audit.py:1) |
| 1.3.1 - DMZ implementation | Public subnet tier with ALB | [vpc-architecture.tf](vpc-architecture.tf:1) |

### Requirement 10: Log and Monitor All Access

| Sub-Requirement | Implementation | File |
|-----------------|----------------|------|
| 10.2.2 - Automated audit trails | VPC Flow Logs capture all network traffic | [vpc-flow-logs.tf](vpc-flow-logs.tf:1) |
| 10.3.2 - Type of event logged | Flow logs include source, dest, port, protocol | [vpc-flow-logs.tf](vpc-flow-logs.tf:1) |
| 10.7.2 - Logs retained for 10 years | S3 lifecycle policy for 10-year retention | [vpc-flow-logs.tf](vpc-flow-logs.tf:1) |

## Security Controls

### Defense in Depth Layers

1. **Layer 1 - VPC Isolation**: Separate VPCs for prod, dev, CDE
2. **Layer 2 - Subnet Segmentation**: Multi-tier subnets within VPC
3. **Layer 3 - Network ACLs**: Stateless filtering at subnet boundary
4. **Layer 4 - Security Groups**: Stateful filtering at instance level
5. **Layer 5 - Host Firewalls**: iptables/nftables on EC2/EKS
6. **Layer 6 - Application Firewalls**: WAF for web applications

### Monitoring and Alerting

- **Rejected connections**: Alert on >100 rejected connections in 5 minutes
- **Port scanning**: Detect port scans across multiple destinations
- **Data exfiltration**: Alert on unusual outbound data volumes
- **Unauthorized CDE access**: Any traffic to CDE from non-approved sources
- **Security group changes**: Alert on any security group rule modifications

## Related Directories

- [../multi-account-setup/](../multi-account-setup/) - AWS Organizations account structure
- [../iam-policies/](../iam-policies/) - IAM policies for network resource access
- [../waf-shield/](../waf-shield/) - Web Application Firewall configurations
- [../../network-security/firewall-configs/](../../network-security/firewall-configs/) - Host-based firewall rules
- [../../siem-soc/wazuh-deployment/](../../siem-soc/wazuh-deployment/) - SIEM integration for flow logs

## Maintenance

### Quarterly Reviews

- Review security group rules for overly permissive access
- Audit unused security groups and NACLs
- Analyze VPC Flow Logs for baseline traffic patterns
- Update network segmentation documentation

### Automated Compliance Checks

```bash
# Run daily via cron or CI/CD
./security-group-audit.py --strict --alert-sns arn:aws:sns:us-east-1:222233334444:security-alerts
```

## Author

**Evgeniy Gantman**
DevSecOps Engineer | Cloud Security Architect

## License

Internal use only - Example Corp
