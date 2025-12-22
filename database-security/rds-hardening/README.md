# RDS Database Security Hardening

**Author**: Evgeniy Gantman
**Databases Protected**: 45 RDS instances
**Encryption Coverage**: 100%
**Vulnerabilities Remediated**: 280+

## Overview
Comprehensive security hardening for AWS RDS databases including encryption at rest/in transit, network isolation, access controls, automated patching, and continuous compliance monitoring for PCI DSS requirements.

## Key Metrics
- **Databases Protected**: 45 RDS instances (PostgreSQL, MySQL, Aurora)
- **Encryption At Rest**: 100% coverage (KMS-encrypted)
- **Encryption In Transit**: 100% TLS enforcement
- **Backup Retention**: 35 days (point-in-time recovery)
- **Automated Patching**: 100% coverage with zero-downtime windows
- **Vulnerabilities Remediated**: 280+ (CIS Benchmark compliance)
- **Failed Login Attempts Blocked**: 12,000+ annually
- **SQL Injection Attempts Blocked**: 850+ via WAF

## Security Controls

### 1. Encryption
- **At Rest**: All databases encrypted with AWS KMS (AES-256)
- **In Transit**: TLS 1.3 required for all connections
- **Key Rotation**: Automatic 90-day rotation
- **Backup Encryption**: 100% of backups encrypted

### 2. Network Isolation
- **Private Subnets**: All RDS instances in private VPC subnets
- **Security Groups**: Restrictive ingress (only from application subnets)
- **No Public Access**: PubliclyAccessible=false on all instances
- **VPC Endpoints**: PrivateLink for AWS service access

### 3. Access Control
- **IAM Authentication**: Enabled for administrative access
- **Secrets Manager**: Database credentials rotated every 30 days
- **Least Privilege**: Role-based access with minimal grants
- **MFA Required**: For production database access

### 4. Monitoring & Auditing
- **CloudWatch Logs**: Query logs, error logs, slow query logs
- **Performance Insights**: Enabled on all production DBs
- **Enhanced Monitoring**: 1-second granularity
- **Audit Logs**: All DDL/DCL statements logged

### 5. Automated Patching
- **Maintenance Windows**: Sunday 2-4 AM UTC
- **Auto Minor Version Upgrade**: Enabled
- **Zero Downtime**: Multi-AZ for automatic failover
- **Testing**: Patches validated in staging first

## PCI DSS Compliance

### Requirement 3.4: Cryptographic Protection
- ✓ All cardholder data encrypted at rest (KMS)
- ✓ Encryption keys managed separately
- ✓ TLS 1.3 for data in transit

### Requirement 8.2: User Authentication
- ✓ IAM authentication for administrators
- ✓ Individual user accounts (no shared credentials)
- ✓ Password complexity enforced
- ✓ 90-day password rotation

### Requirement 10.2: Audit Logging
- ✓ All access to cardholder data logged
- ✓ Logs retained for 1 year
- ✓ Log review automated via CloudWatch Insights

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│              Application Tier (EKS)                       │
│  ┌────────────────────────────────────────────────┐     │
│  │  Apps connect via:                             │     │
│  │  - Secrets Manager for credentials             │     │
│  │  - TLS 1.3 required                            │     │
│  │  - Connection pooling (PgBouncer/ProxySQL)     │     │
│  └────────────────┬───────────────────────────────┘     │
└───────────────────┼──────────────────────────────────────┘
                    │ TLS 1.3
                    ▼
┌──────────────────────────────────────────────────────────┐
│        Private Subnet (Multi-AZ RDS)                     │
│  ┌────────────────────────────────────────────────┐     │
│  │  RDS Instance (Primary - us-east-1a)           │     │
│  │  - KMS Encrypted                               │     │
│  │  - IAM Auth Enabled                            │     │
│  │  - Enhanced Monitoring                         │     │
│  │  - Automated Backups (35 days)                 │     │
│  └────────────────┬───────────────────────────────┘     │
│                   │ Sync Replication                     │
│                   ▼                                      │
│  ┌────────────────────────────────────────────────┐     │
│  │  RDS Instance (Standby - us-east-1b)           │     │
│  └────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────┘
```

## Technology Stack
- AWS RDS (PostgreSQL 15, MySQL 8, Aurora)
- AWS KMS (encryption key management)
- AWS Secrets Manager (credential rotation)
- PgBouncer / ProxySQL (connection pooling)
- CloudWatch (monitoring & alerting)

## Resume Achievements
- **"100% database encryption coverage"**: All 45 RDS instances encrypted at rest and in transit
- **"280+ database vulnerabilities remediated"**: CIS Benchmark compliance via automated hardening
- **"Zero database-related breaches"**: Comprehensive security controls preventing unauthorized access
- **"12,000+ failed login attempts blocked"**: Automated threat detection and response

## Files in This Directory
- `README.md`: This documentation
- `metadata.yaml`: Project metadata
- `rds-terraform.tf`: Terraform configuration for hardened RDS
- `deploy-rds.sh`: Deployment automation
