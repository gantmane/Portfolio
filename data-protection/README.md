# Data Protection

**Author**: Evgeniy Gantman
**Last Updated**: December 2025
**Purpose**: Data security, encryption, and privacy controls

## Overview

This directory contains data protection implementations including encryption at rest/in transit, tokenization for PCI DSS scope reduction, and data loss prevention (DLP) policies.

## Contents

### [DLP Policies](dlp-policies/)
Data Loss Prevention rule configurations.
- Sensitive data detection patterns
- PII and PAN identification
- Automated alerting and blocking

### [DLP Implementation](dlp-implementation/)
DLP deployment and integration guides.

### [Encryption at Rest](encryption-at-rest/)
Storage encryption configurations.
- AWS KMS key management
- EBS volume encryption
- S3 bucket encryption
- RDS encryption

### [Encryption in Transit](encryption-in-transit/)
Transport layer security configurations.
- TLS 1.3 enforcement
- Certificate management
- mTLS for service mesh

### [Tokenization](tokenization/)
PAN tokenization for PCI DSS scope reduction.
- Token vault architecture
- Detokenization workflows
- Audit logging

## Key Controls

| Control | Implementation |
|---------|----------------|
| **Encryption at Rest** | KMS, CloudHSM |
| **Encryption in Transit** | TLS 1.3, mTLS |
| **Tokenization** | PAN tokenization at API Gateway |
| **Key Management** | AWS KMS with automatic rotation |
| **DLP** | Pattern-based detection and blocking |

## PCI DSS Alignment

| Requirement | Control |
|-------------|---------|
| 3.5.1 | Encryption at rest with KMS |
| 4.1.1 | TLS 1.3 for all transmissions |
| 3.4 | PAN tokenization |
| 3.6 | Key management procedures |

## Related Sections

- [Cloud Security](../cloud-security/) - AWS KMS configurations
- [Compliance](../compliance/) - PCI DSS requirements
- [Network Security](../network-security/) - TLS configurations
