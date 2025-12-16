# Cross-Account KMS Key Sharing Configuration
# Author: Evgeniy Gantman
# Purpose: Enable cross-account KMS key access for backup and DR scenarios
# PCI DSS: Requirement 3.5 (Key Management), Requirement 12.10 (Incident Response)

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ===========================
# Cross-Account Key Policy for Backups
# ===========================

# Allow Backup Account to use production S3 CMK
resource "aws_kms_key_policy" "s3_prod_cross_account" {
  key_id = aws_kms_key.s3_prod.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::222233334444:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow S3 Service"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.us-east-1.amazonaws.com"
          }
        }
      },
      {
        Sid    = "AllowBackupAccountDecryption"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::555566667777:root"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = [
              "s3.us-east-1.amazonaws.com",
              "backup.us-east-1.amazonaws.com"
            ]
            "aws:PrincipalOrgID" = "o-exampleorgid"
          }
          StringLike = {
            "kms:EncryptionContext:aws:s3:arn" = [
              "arn:aws:s3:::examplepay-backups-*",
              "arn:aws:s3:::examplepay-dr-*"
            ]
          }
        }
      },
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = "s3:PutObject"
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# ===========================
# DR Region Key Sharing
# ===========================

# Primary region RDS key with DR access
resource "aws_kms_key_policy" "rds_prod_dr" {
  key_id = aws_kms_key.rds_prod.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::222233334444:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow RDS Service Primary Region"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "rds.us-east-1.amazonaws.com"
            "aws:SourceAccount" = "222233334444"
          }
        }
      },
      {
        Sid    = "Allow RDS Service DR Region"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:CreateGrant",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "rds.us-west-2.amazonaws.com"
            "aws:SourceAccount" = "222233334444"
          }
        }
      },
      {
        Sid    = "Allow Cross-Region RDS Replication"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = "222233334444"
          }
          StringLike = {
            "kms:EncryptionContext:aws:rds:arn" = [
              "arn:aws:rds:us-east-1:222233334444:db:*",
              "arn:aws:rds:us-west-2:222233334444:db:*"
            ]
          }
        }
      }
    ]
  })
}

# ===========================
# Cross-Account Grant for Backups
# ===========================

# Create grant allowing backup account to use encryption
resource "aws_kms_grant" "backup_account_grant" {
  name              = "backup-account-cross-account-grant"
  key_id            = aws_kms_key.s3_prod.key_id
  grantee_principal = "arn:aws:iam::555566667777:role/BackupServiceRole"
  operations = [
    "Decrypt",
    "DescribeKey",
    "GenerateDataKey",
    "CreateGrant",
    "RetireGrant"
  ]

  constraints {
    encryption_context_subset = {
      "backup-type" = "automated"
      "environment" = "production"
    }
  }

  retire_on_delete = true
}

# ===========================
# CDE Cross-Account Restrictions
# ===========================

# CDE keys should NOT allow cross-account access
# This is enforced via explicit Deny
resource "aws_kms_key_policy" "rds_cde_restricted" {
  key_id = aws_kms_key.rds_cde.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::444455556666:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow RDS in CDE Account Only"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService"     = "rds.us-east-1.amazonaws.com"
            "aws:SourceAccount"  = "444455556666"
          }
          IpAddress = {
            "aws:SourceIp" = "10.0.0.0/8"
          }
        }
      },
      {
        Sid    = "DenyCrossAccountAccess"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalAccount" = "444455556666"
          }
        }
      },
      {
        Sid    = "Deny Key Deletion"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DeleteImportedKeyMaterial"
        ]
        Resource = "*"
      }
    ]
  })
}

# ===========================
# CloudTrail Log Encryption (Organization-wide)
# ===========================

# CloudTrail key accessible by all member accounts
resource "aws_kms_key" "cloudtrail_org" {
  description             = "CMK for organization-wide CloudTrail logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = true

  tags = {
    Name        = "cloudtrail-org-cmk"
    Environment = "organization"
    Service     = "cloudtrail"
    Purpose     = "Centralized audit logging"
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_key_policy" "cloudtrail_org" {
  key_id = aws_kms_key.cloudtrail_org.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::111122223333:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "kms:GenerateDataKey*"
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:*:trail/*"
          }
          StringEquals = {
            "aws:SourceOrgID" = "o-exampleorgid"
          }
        }
      },
      {
        Sid    = "Allow CloudTrail to describe key"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "kms:DescribeKey"
        Resource = "*"
      },
      {
        Sid    = "Allow member accounts to decrypt logs"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = "o-exampleorgid"
          }
        }
      }
    ]
  })
}

# ===========================
# Outputs
# ===========================

output "cross_account_sharing_enabled" {
  description = "Cross-account KMS sharing status"
  value = {
    backup_account = "555566667777"
    dr_enabled     = "RDS multi-region replication configured"
    cde_isolated   = "CDE keys deny cross-account access"
    cloudtrail_org = "Organization-wide CloudTrail encryption enabled"
  }
}

output "cloudtrail_org_key_id" {
  description = "Organization CloudTrail CMK ID"
  value       = aws_kms_key.cloudtrail_org.key_id
}

output "backup_grant_id" {
  description = "Backup account KMS grant ID"
  value       = aws_kms_grant.backup_account_grant.grant_id
}
