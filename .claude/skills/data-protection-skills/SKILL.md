---
name: data-protection-skills
description: Data security and privacy expertise for encryption, DLP, key management, data classification, masking, and tokenization. Use when protecting sensitive data, implementing encryption strategies, or ensuring privacy compliance.
allowed-tools: Read, Grep, Glob, Bash(aws:*), Bash(openssl:*)
nist_csf_function: PROTECT
nist_csf_categories: [PR.DS-01, PR.DS-02, PR.DS-05, PR.DS-06, PR.AA-05]
mitre_attack_coverage: [T1005, T1041, T1565, T1486, T1552, T1119, T1530]
---

# Data Protection Skills

> **NIST CSF 2.0 Alignment**: PROTECT Function - Data Security
> Supports data classification, encryption, privacy controls, and data loss prevention

## Data Classification ⇒ ID.AM-07, PR.DS-01

### Classification Levels ⇒ ID.AM-07
| Level | Description | Examples | Controls | NIST CSF |
|-------|-------------|----------|----------|----------|
| **Public** | No impact if disclosed | Marketing, public docs | None required | - |
| **Internal** | Minor business impact | Internal policies | Access control | PR.AA-05 |
| **Confidential** | Significant impact | Financial data, PII | Encryption, audit | PR.DS-01, DE.CM-09 |
| **Restricted** | Severe impact, regulated | PHI, PCI, secrets | Full controls | PR.DS-01, PR.AA-05 |

### Data Discovery ⇒ ID.AM-07
- Automated scanning (Macie, Purview, DLP) ⇒ ID.AM-07
- Regex patterns for sensitive data ⇒ PR.DS-01
- Manual data inventory ⇒ ID.AM-01
- Data flow mapping ⇒ ID.AM-02

## Encryption Strategies ⇒ PR.DS-01, PR.DS-02

### Encryption at Rest ⇒ PR.DS-01

#### AWS KMS ⇒ PR.DS-01 (Key management)
```hcl
# Customer Managed Key ⇒ PR.DS-01
resource "aws_kms_key" "data" {
  description             = "Data encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true  # ⇒ PR.DS-01 (Key rotation)

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM policies"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::ACCOUNT:root" }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}
```

#### Encryption Methods ⇒ PR.DS-01
| Method | Use Case | Key Management | NIST CSF |
|--------|----------|----------------|----------|
| SSE-S3 | Default S3 | AWS managed | PR.DS-01 |
| SSE-KMS | Audit, compliance | AWS or CMK | PR.DS-01, DE.CM-09 |
| SSE-C | Customer keys | Customer | PR.DS-01 |
| Client-side | E2E encryption | Customer | PR.DS-01, PR.DS-02 |

### Encryption in Transit ⇒ PR.DS-02
```yaml
# ⇒ PR.DS-02: Transport layer security
tls_policy:
  minimum_version: "TLS 1.3"
  cipher_suites:
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
  certificate_rotation: automatic  # ⇒ PR.DS-02
  hsts_enabled: true  # ⇒ PR.DS-02
```

## Key Management ⇒ PR.DS-01

### Key Hierarchy ⇒ PR.DS-01
```
Root Key (HSM) - Never exported ⇒ PR.DS-01
    │
    ├── KEK (Region A) - Key Encryption Key
    │       │
    │       └── DEKs - Data Encryption Keys
    │
    └── KEK (Region B)
            │
            └── DEKs
```

### Key Rotation Policy ⇒ PR.DS-01
```yaml
# ⇒ PR.DS-01: Cryptographic key lifecycle management
key_rotation:
  root_key:
    rotation: manual
    ceremony_required: true  # ⇒ GV.PO-03

  key_encryption_keys:
    rotation_period: 365 days
    automatic: true

  data_encryption_keys:
    rotation_period: 90 days
    automatic: true
```

## Data Masking & Tokenization ⇒ PR.DS-01, PR.DS-05

### Masking Patterns ⇒ PR.DS-05 (Privacy protection)
```python
# ⇒ PR.DS-05: Data minimization through masking

# Credit card: **** **** **** 1234 ⇒ T1005 defense
def mask_cc(cc): return f"**** **** **** {cc[-4:]}"

# SSN: ***-**-1234 ⇒ PR.DS-05
def mask_ssn(ssn): return f"***-**-{ssn[-4:]}"

# Email: j***@e***.com ⇒ PR.DS-05
def mask_email(email):
    local, domain = email.split('@')
    parts = domain.split('.')
    return f"{local[0]}***@{parts[0][0]}***.{parts[-1]}"

# Phone: (***) ***-1234 ⇒ PR.DS-05
def mask_phone(phone): return f"(***) ***-{phone[-4:]}"
```

### Tokenization Flow ⇒ PR.DS-01
```
Original Data → Tokenization Service → Token (non-sensitive)
                        │
                        └─→ Vault (stores original, HSM-protected) ⇒ PR.DS-01

Detokenization: Token → Service → Original (authorized only) ⇒ PR.AA-05
```

## Data Loss Prevention (DLP) ⇒ PR.DS-01, T1041 defense

### DLP Rules ⇒ PR.DS-01, DE.CM-01
```yaml
# ⇒ PR.DS-01, DE.CM-01: Prevent data exfiltration
dlp_rules:
  credit_cards:  # ⇒ T1005 defense
    pattern: '\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b'
    action: block
    alert: high

  ssn:  # ⇒ PR.DS-05
    pattern: '\b(?!000|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b'
    action: block
    alert: high

  aws_keys:  # ⇒ T1552 defense
    pattern: 'AKIA[0-9A-Z]{16}'
    action: block
    alert: critical

  api_keys:  # ⇒ T1552 defense
    pattern: '(?i)(api[_-]?key|apikey)\s*[:=]\s*[\'"]?([a-zA-Z0-9]{32,})'
    action: warn
    alert: medium
```

### AWS Macie ⇒ ID.AM-07, PR.DS-01
```bash
# Enable Macie ⇒ ID.AM-07 (Data discovery)
aws macie2 enable-macie

# Create classification job ⇒ ID.AM-07
aws macie2 create-classification-job \
  --job-type SCHEDULED \
  --s3-job-definition '{"bucketDefinitions":[{"accountId":"123","buckets":["my-bucket"]}]}'
```

## Privacy Engineering ⇒ PR.DS-05

### Data Minimization ⇒ PR.DS-05
```yaml
# ⇒ PR.DS-05: Collect only what's necessary
data_collection:
  required:
    - email  # Account identification
    - name   # Personalization

  optional:
    - phone  # 2FA (with consent)
    - address # Shipping only

  prohibited:
    - ssn    # Unless legally required
    - biometric # Without explicit consent
```

### GDPR/CCPA Requirements ⇒ GV.OC-01, PR.DS-05
| Right | GDPR | CCPA | Implementation | NIST CSF |
|-------|------|------|----------------|----------|
| Access | Art. 15 | §1798.100 | Data export API | PR.DS-05 |
| Deletion | Art. 17 | §1798.105 | Anonymization | PR.DS-05 |
| Portability | Art. 20 | §1798.100 | JSON export | PR.DS-05 |
| Opt-out | N/A | §1798.120 | Consent management | PR.DS-05 |

### Data Subject Request Handling ⇒ PR.DS-05
```python
# ⇒ PR.DS-05: Privacy rights implementation
def handle_dsr(user_id, request_type):
    if request_type == "access":  # ⇒ PR.DS-05
        return export_user_data(user_id)
    elif request_type == "delete":  # ⇒ PR.DS-05
        anonymize_user(user_id)
        delete_from_systems(user_id)
        notify_third_parties(user_id)
    elif request_type == "portability":  # ⇒ PR.DS-05
        return export_user_data(user_id, format="json")
```

## Data Retention ⇒ GV.PO-01, PR.DS-05

### Retention Policy ⇒ GV.PO-01
```yaml
# ⇒ GV.PO-01: Data lifecycle management
retention:
  active_accounts: indefinite
  inactive_accounts: 2 years
  deleted_accounts: 30 days (recovery)
  logs: 90 days  # ⇒ DE.CM-09
  backups: 7 years (compliance)  # ⇒ GV.OC-01

  automated_deletion:  # ⇒ PR.DS-05
    enabled: true
    review_before_delete: true
```

## Secure Data Handling ⇒ PR.DS-01

### Database Security ⇒ PR.DS-01
- Row-level security (RLS) ⇒ PR.AA-05
- Column-level encryption ⇒ PR.DS-01
- Transparent Data Encryption (TDE) ⇒ PR.DS-01
- Database activity monitoring ⇒ DE.CM-09
- Query audit logging ⇒ DE.CM-09

### Backup Security ⇒ PR.DS-01, RC.RP-02
- Encrypted backups ⇒ PR.DS-01
- Immutable storage (WORM) ⇒ PR.DS-06, T1486 defense
- Cross-region replication ⇒ RC.RP-02
- Backup access logging ⇒ DE.CM-09
- Recovery testing ⇒ RC.RP-04

## Data Security Checklist ⇒ PR.DS-01

| Category | Control | NIST CSF | Status |
|----------|---------|----------|--------|
| Discovery | Data inventory complete | ID.AM-07 | ☐ |
| Classification | Labels defined | ID.AM-07 | ☐ |
| Encryption | At-rest (all storage) | PR.DS-01 | ☐ |
| Encryption | In-transit (TLS 1.3) | PR.DS-02 | ☐ |
| Key Management | Rotation enabled | PR.DS-01 | ☐ |
| Access | Least privilege | PR.AA-05 | ☐ |
| Audit | Logging enabled | DE.CM-09 | ☐ |
| DLP | Policies active | PR.DS-01 | ☐ |
| Privacy | Consent management | PR.DS-05 | ☐ |
| Retention | Automated deletion | GV.PO-01 | ☐ |

## MITRE ATT&CK Coverage

This skill addresses defense against:
- **T1005**: Data from Local System
- **T1041**: Exfiltration Over C2 Channel
- **T1565**: Data Manipulation
- **T1486**: Data Encrypted for Impact (ransomware)
- **T1552**: Unsecured Credentials
- **T1119**: Automated Collection
- **T1530**: Data from Cloud Storage Object
