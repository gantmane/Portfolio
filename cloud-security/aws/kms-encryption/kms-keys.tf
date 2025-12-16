# AWS KMS Customer Managed Keys
# Author: Evgeniy Gantman
# Purpose: Service-specific CMKs with automatic rotation
# PCI DSS: Requirement 3 (Protect Stored Cardholder Data)

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
# Production RDS CMK
# ===========================

resource "aws_kms_key" "rds_prod" {
  description             = "CMK for Production RDS databases"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = true

  tags = {
    Name        = "rds-prod-cmk"
    Environment = "production"
    Service     = "rds"
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "rds_prod" {
  name          = "alias/rds-prod"
  target_key_id = aws_kms_key.rds_prod.key_id
}

resource "aws_kms_key_policy" "rds_prod" {
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
        Sid    = "Allow RDS to use the key"
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
            "kms:ViaService" = [
              "rds.us-east-1.amazonaws.com",
              "rds.us-west-2.amazonaws.com"
            ]
          }
        }
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

# ===========================
# Production EBS CMK
# ===========================

resource "aws_kms_key" "ebs_prod" {
  description             = "CMK for Production EBS volumes"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "ebs-prod-cmk"
    Environment = "production"
    Service     = "ebs"
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "ebs_prod" {
  name          = "alias/ebs-prod"
  target_key_id = aws_kms_key.ebs_prod.key_id
}

# ===========================
# Production S3 CMK
# ===========================

resource "aws_kms_key" "s3_prod" {
  description             = "CMK for Production S3 buckets"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = true

  tags = {
    Name        = "s3-prod-cmk"
    Environment = "production"
    Service     = "s3"
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "s3_prod" {
  name          = "alias/s3-prod"
  target_key_id = aws_kms_key.s3_prod.key_id
}

resource "aws_kms_key_policy" "s3_prod" {
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
        Sid    = "Allow S3 to use the key"
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
      }
    ]
  })
}

# ===========================
# CDE RDS CMK (CloudHSM-backed)
# ===========================

resource "aws_kms_key" "rds_cde" {
  description              = "CMK for CDE RDS databases (PCI DSS in-scope)"
  deletion_window_in_days  = 30
  enable_key_rotation      = true
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  # custom_key_store_id would be set to CloudHSM cluster ID in production

  tags = {
    Name        = "rds-cde-cmk"
    Environment = "production"
    Service     = "rds"
    PCIScope    = "in-scope"
    DataClass   = "cardholder-data"
    Compliance  = "pci-dss-4.0"
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "rds_cde" {
  name          = "alias/rds-cde"
  target_key_id = aws_kms_key.rds_cde.key_id
}

resource "aws_kms_key_policy" "rds_cde" {
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
# Secrets Manager CMK
# ===========================

resource "aws_kms_key" "secrets_prod" {
  description             = "CMK for Secrets Manager"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "secrets-prod-cmk"
    Environment = "production"
    Service     = "secretsmanager"
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "secrets_prod" {
  name          = "alias/secrets-prod"
  target_key_id = aws_kms_key.secrets_prod.key_id
}

# ===========================
# SNS/SQS CMK
# ===========================

resource "aws_kms_key" "messaging_prod" {
  description             = "CMK for SNS and SQS"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "messaging-prod-cmk"
    Environment = "production"
    Service     = "sns-sqs"
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "messaging_prod" {
  name          = "alias/messaging-prod"
  target_key_id = aws_kms_key.messaging_prod.key_id
}

# ===========================
# Development Shared CMK
# ===========================

resource "aws_kms_key" "dev_shared" {
  description             = "Shared CMK for development and staging"
  deletion_window_in_days = 7  # Shorter for dev
  enable_key_rotation     = false  # Not required for dev

  tags = {
    Name        = "dev-shared-cmk"
    Environment = "development"
    Service     = "all"
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "dev_shared" {
  name          = "alias/dev-shared"
  target_key_id = aws_kms_key.dev_shared.key_id
}

# ===========================
# CloudWatch Logs CMK
# ===========================

resource "aws_kms_key" "cloudwatch_logs" {
  description             = "CMK for CloudWatch Logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "cloudwatch-logs-cmk"
    Environment = "production"
    Service     = "logs"
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "cloudwatch_logs" {
  name          = "alias/cloudwatch-logs"
  target_key_id = aws_kms_key.cloudwatch_logs.key_id
}

resource "aws_kms_key_policy" "cloudwatch_logs" {
  key_id = aws_kms_key.cloudwatch_logs.id

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
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:*:222233334444:*"
          }
        }
      }
    ]
  })
}

# ===========================
# Outputs
# ===========================

output "kms_key_ids" {
  description = "Map of KMS key names to IDs"
  value = {
    rds_prod         = aws_kms_key.rds_prod.id
    ebs_prod         = aws_kms_key.ebs_prod.id
    s3_prod          = aws_kms_key.s3_prod.id
    rds_cde          = aws_kms_key.rds_cde.id
    secrets_prod     = aws_kms_key.secrets_prod.id
    messaging_prod   = aws_kms_key.messaging_prod.id
    dev_shared       = aws_kms_key.dev_shared.id
    cloudwatch_logs  = aws_kms_key.cloudwatch_logs.id
  }
}

output "kms_key_arns" {
  description = "Map of KMS key names to ARNs"
  value = {
    rds_prod         = aws_kms_key.rds_prod.arn
    ebs_prod         = aws_kms_key.ebs_prod.arn
    s3_prod          = aws_kms_key.s3_prod.arn
    rds_cde          = aws_kms_key.rds_cde.arn
    secrets_prod     = aws_kms_key.secrets_prod.arn
    messaging_prod   = aws_kms_key.messaging_prod.arn
    dev_shared       = aws_kms_key.dev_shared.arn
    cloudwatch_logs  = aws_kms_key.cloudwatch_logs.arn
  }
}

output "kms_key_aliases" {
  description = "Map of KMS key alias names"
  value = {
    rds_prod         = aws_kms_alias.rds_prod.name
    ebs_prod         = aws_kms_alias.ebs_prod.name
    s3_prod          = aws_kms_alias.s3_prod.name
    rds_cde          = aws_kms_alias.rds_cde.name
    secrets_prod     = aws_kms_alias.secrets_prod.name
    messaging_prod   = aws_kms_alias.messaging_prod.name
    dev_shared       = aws_kms_alias.dev_shared.name
    cloudwatch_logs  = aws_kms_alias.cloudwatch_logs.name
  }
}
