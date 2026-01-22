# AWS KMS Encryption

Customer Managed Keys (CMK) and encryption patterns for data protection at rest.

## Overview

This directory contains AWS Key Management Service (KMS) configurations implementing encryption at rest for all data, meeting PCI DSS Requirement 3 for protecting stored cardholder data. All implementations use AES-256 encryption with automatic key rotation and comprehensive audit logging.

**Resume Achievement:** Implemented AWS KMS CMKs with 90-day automatic rotation for all services (RDS, EBS, S3, Secrets Manager), achieving 100% encryption coverage and PCI DSS Requirement 3 compliance with zero data breaches.

Key features include:
- Separate CMKs for each service and environment
- Automatic 90-day key rotation
- Cross-account key sharing for backup/DR
- CloudHSM integration for highest security workloads
- Comprehensive key usage auditing and alerting

## Contents

- **README.md** - This file
- **metadata.yaml** - Directory metadata and compliance mappings
- **kms-keys.tf** - Terraform configuration for service-specific CMKs
- **key-rotation-policy.tf** - Automatic 90-day rotation configuration
- **cross-account-sharing.tf** - Cross-account key sharing for DR
- **envelope-encryption-example.py** - Python example of envelope encryption pattern
- **key-audit-logging.py** - Python script to audit key usage and detect anomalies
- **cloudhsm-integration.tf** - CloudHSM custom key store for CDE
- **key-lifecycle.yaml** - Key lifecycle management policy (creation to deletion)
- **rotate-keys.sh** - Manual key rotation script with validation

## Key Features

- **Service-specific CMKs** - Dedicated keys for RDS, EBS, S3, Secrets Manager, SNS, SQS
- **90-day rotation** - Automatic key material rotation every 90 days (PCI DSS compliant)
- **Multi-region keys** - For disaster recovery and cross-region replication
- **CloudHSM integration** - FIPS 140-2 Level 3 validated hardware for CDE
- **Envelope encryption** - Two-tier encryption for application-level data protection
- **Key usage monitoring** - Real-time alerting on unauthorized key access attempts
- **Least-privilege** - Key policies with strict conditions (MFA, source IP)

## Encryption Strategy

### Service-Specific Keys

```
Environment/Service Matrix:
├── Production
│   ├── rds-prod-cmk (RDS databases)
│   ├── ebs-prod-cmk (EC2 volumes)
│   ├── s3-prod-cmk (S3 buckets)
│   ├── secrets-prod-cmk (Secrets Manager)
│   └── sns-prod-cmk (SNS topics)
├── CDE (Cardholder Data Environment)
│   ├── rds-cde-cmk (PAN databases) - CloudHSM backed
│   ├── ebs-cde-cmk (CDE EC2 volumes)
│   └── s3-cde-cmk (Tokenization vault)
└── Development
    └── dev-cmk (Shared for dev/staging)
```

## Usage

### Deploy KMS Keys

```bash
# Initialize Terraform
terraform init

# Plan deployment
terraform plan -out=kms.tfplan

# Apply
terraform apply kms.tfplan
```

### Encrypt Data with Python

```python
# Using envelope encryption pattern
python3 envelope-encryption-example.py \
    --key-id "arn:aws:kms:us-east-1:222233334444:key/12345678-1234-1234-1234-123456789012" \
    --plaintext "Sensitive cardholder data" \
    --output encrypted-data.bin
```

### Audit Key Usage

```bash
# Audit all key usage in last 24 hours
python3 key-audit-logging.py --hours 24

# Detect anomalies
python3 key-audit-logging.py --detect-anomalies
```

### Manual Key Rotation

```bash
# Rotate specific key
./rotate-keys.sh --key-id 12345678-1234-1234-1234-123456789012 --verify
```

## PCI DSS Compliance Mapping

| Requirement | Control | Implementation |
|------------|---------|----------------|
| Req 3.4 - Render PAN Unreadable | Encryption at rest | AES-256 encryption for all PAN storage locations |
| Req 3.5 - Protect cryptographic keys | Key protection | KMS keys never leave AWS, CloudHSM for CDE |
| Req 3.6 - Key management procedures | Key lifecycle | Automated 90-day rotation, access logging, least-privilege |
| Req 3.7 - Cryptography strength | Strong encryption | AES-256-GCM, RSA-2048+ for key wrapping |
| Req 10.3 - Audit logs for key access | Logging | CloudTrail logs all KMS API calls to SIEM |

## Key Rotation Strategy

### Automatic Rotation (Recommended)
- **Frequency:** Every 90 days
- **Services:** All CMKs for production and CDE
- **Process:** AWS automatically rotates key material while keeping key ID constant
- **Decryption:** Old key material retained for decrypting existing data

### Manual Rotation (Special Cases)
- **Use case:** Suspected key compromise, compliance requirements
- **Process:** Create new CMK, update aliases, re-encrypt data
- **Script:** `rotate-keys.sh` automates the process

## Envelope Encryption Pattern

For application-level data encryption:

```
1. Generate Data Encryption Key (DEK) using KMS CMK
2. Encrypt plaintext data with DEK (AES-256-GCM)
3. Encrypt DEK with CMK (wrapped DEK)
4. Store: Encrypted data + Wrapped DEK
5. Decrypt: Unwrap DEK with CMK, decrypt data with DEK
```

**Benefits:**
- Limits CMK usage (better performance, lower cost)
- Enables local encryption/decryption
- Supports large data volumes

## Security Best Practices Implemented

1. **Key Policies with Conditions**
   ```json
   "Condition": {
     "Bool": {"kms:GrantIsForAWSResource": "true"},
     "StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"},
     "IpAddress": {"aws:SourceIp": "10.0.0.0/8"}
   }
   ```

2. **Separate Keys per Service/Environment**
   - Limits blast radius of key compromise
   - Enables service-specific key policies
   - Simplifies compliance auditing

3. **CloudHSM for Highest Security**
   - FIPS 140-2 Level 3 validated
   - Single-tenant hardware security modules
   - You control key lifecycle

4. **Multi-Region Keys for DR**
   - Automatic key replication to DR region
   - Consistent key IDs across regions
   - Simplifies cross-region encrypted backups

## Key Lifecycle Management

### Creation
1. Define key policy with least-privilege
2. Enable automatic rotation
3. Create alias for easy reference
4. Tag with Environment, Service, PCIScope

### Active Use
1. Monitor key usage with CloudWatch metrics
2. Alert on unusual usage patterns
3. Quarterly access review

### Rotation
1. Automatic every 90 days (PCI DSS compliant)
2. Manual rotation on suspected compromise
3. Validate rotation completed successfully

### Retirement
1. Schedule key deletion (7-30 day waiting period)
2. Ensure no active usage
3. Export audit logs for retention
4. Document deletion reason

## CloudHSM Integration (CDE)

For PCI DSS in-scope CDE workloads:

```
KMS Custom Key Store → CloudHSM Cluster
├── Single-tenant HSM
├── FIPS 140-2 Level 3
├── You control key material
└── Audit logs to SIEM
```

**Use cases:**
- PAN encryption at rest
- Tokenization vault keys
- TDE (Transparent Data Encryption) for databases

## Monitoring & Alerting

### CloudWatch Alarms
- Unauthorized key access attempts
- Key deletion attempts
- Abnormal key usage volume
- Failed decryption attempts

### Integration with SIEM (Wazuh)
All KMS CloudTrail events forwarded to Wazuh for:
- Correlation with other security events
- Long-term retention (3 years)
- Compliance reporting

## Cost Optimization

- **CMK cost:** $1/month per key
- **API requests:** $0.03 per 10,000 requests
- **Optimization:** Use envelope encryption to reduce KMS API calls by 90%

## Related Directories

- [../multi-account-setup/](../multi-account-setup/) - Cross-account key sharing setup
- [../../../data-protection/](../../../data-protection/) - Encryption implementations
- [../../../compliance/pci-dss-4.0/](../../../compliance/pci-dss-4.0/) - PCI DSS Req 3 implementation

## References

- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [PCI DSS v4.0 Requirement 3](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf)
- [NIST SP 800-57: Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
