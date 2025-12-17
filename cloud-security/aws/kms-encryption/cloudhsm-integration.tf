# AWS CloudHSM Integration with KMS
# Author: Evgeniy Gantman
# Purpose: CloudHSM custom key store for PCI DSS Level 1 compliance
# PCI DSS: Requirement 3.5.3 (Hardware Security Modules for key management)

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
# CloudHSM Cluster
# ===========================

# CloudHSM cluster for CDE key material
resource "aws_cloudhsm_v2_cluster" "cde_hsm" {
  hsm_type   = "hsm1.medium"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name        = "examplepay-cde-hsm"
    Environment = "production"
    Purpose     = "PCI DSS CDE Key Storage"
    PCIScope    = "in-scope"
    Compliance  = "pci-dss-4.0"
    DataClass   = "cardholder-data"
    ManagedBy   = "terraform"
  }
}

# HSM instances (minimum 2 for HA, recommend 3+)
resource "aws_cloudhsm_v2_hsm" "cde_hsm_az1" {
  cluster_id        = aws_cloudhsm_v2_cluster.cde_hsm.cluster_id
  subnet_id         = var.private_subnet_ids[0]
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "examplepay-cde-hsm-az1"
    AZ   = data.aws_availability_zones.available.names[0]
  }
}

resource "aws_cloudhsm_v2_hsm" "cde_hsm_az2" {
  cluster_id        = aws_cloudhsm_v2_cluster.cde_hsm.cluster_id
  subnet_id         = var.private_subnet_ids[1]
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "examplepay-cde-hsm-az2"
    AZ   = data.aws_availability_zones.available.names[1]
  }
}

resource "aws_cloudhsm_v2_hsm" "cde_hsm_az3" {
  cluster_id        = aws_cloudhsm_v2_cluster.cde_hsm.cluster_id
  subnet_id         = var.private_subnet_ids[2]
  availability_zone = data.aws_availability_zones.available.names[2]

  tags = {
    Name = "examplepay-cde-hsm-az3"
    AZ   = data.aws_availability_zones.available.names[2]
  }
}

# ===========================
# KMS Custom Key Store
# ===========================

# Custom key store backed by CloudHSM
# Note: Requires CloudHSM cluster to be initialized and activated
# See deployment documentation for manual initialization steps
resource "aws_kms_custom_key_store" "cde_keystore" {
  custom_key_store_name = "examplepay-cde-keystore"
  cloud_hsm_cluster_id  = aws_cloudhsm_v2_cluster.cde_hsm.cluster_id

  # Trust anchor certificate from CloudHSM cluster
  # Must be obtained after cluster initialization
  trust_anchor_certificate = var.cloudhsm_trust_anchor_cert

  # CloudHSM key store password (stored in Secrets Manager)
  key_store_password = data.aws_secretsmanager_secret_version.hsm_password.secret_string

  depends_on = [
    aws_cloudhsm_v2_hsm.cde_hsm_az1,
    aws_cloudhsm_v2_hsm.cde_hsm_az2,
    aws_cloudhsm_v2_hsm.cde_hsm_az3
  ]
}

# ===========================
# KMS Keys with CloudHSM Backing
# ===========================

# CDE Database Encryption Key (CloudHSM-backed)
resource "aws_kms_key" "rds_cde_hsm" {
  description              = "CMK for CDE RDS (CloudHSM-backed for PCI DSS Level 1)"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"

  # Link to CloudHSM custom key store
  custom_key_store_id = aws_kms_custom_key_store.cde_keystore.id

  # Deletion protection
  deletion_window_in_days = 30
  is_enabled              = true

  tags = {
    Name        = "rds-cde-hsm-cmk"
    Environment = "production"
    Service     = "rds"
    PCIScope    = "in-scope"
    DataClass   = "cardholder-data"
    Compliance  = "pci-dss-4.0"
    HSMBacked   = "true"
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "rds_cde_hsm" {
  name          = "alias/rds-cde-hsm"
  target_key_id = aws_kms_key.rds_cde_hsm.key_id
}

# CDE S3 Encryption Key (CloudHSM-backed)
resource "aws_kms_key" "s3_cde_hsm" {
  description              = "CMK for CDE S3 buckets (CloudHSM-backed)"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"

  custom_key_store_id     = aws_kms_custom_key_store.cde_keystore.id
  deletion_window_in_days = 30
  is_enabled              = true

  tags = {
    Name        = "s3-cde-hsm-cmk"
    Environment = "production"
    Service     = "s3"
    PCIScope    = "in-scope"
    DataClass   = "cardholder-data"
    Compliance  = "pci-dss-4.0"
    HSMBacked   = "true"
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "s3_cde_hsm" {
  name          = "alias/s3-cde-hsm"
  target_key_id = aws_kms_key.s3_cde_hsm.key_id
}

# ===========================
# Key Policies (CloudHSM Keys)
# ===========================

resource "aws_kms_key_policy" "rds_cde_hsm" {
  key_id = aws_kms_key.rds_cde_hsm.id

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
        Sid    = "Allow RDS Service"
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
            "kms:ViaService"    = "rds.us-east-1.amazonaws.com"
            "aws:SourceAccount" = "444455556666"
          }
          # Restrict to CDE VPC
          StringEquals = {
            "aws:SourceVpc" = var.cde_vpc_id
          }
        }
      },
      {
        Sid    = "Deny Non-HSM Key Operations"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:ImportKeyMaterial",
          "kms:GetParametersForImport"
        ]
        Resource = "*"
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
      },
      {
        Sid    = "Require MFA for Key Management"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:DisableKey",
          "kms:UpdateKeyDescription",
          "kms:PutKeyPolicy",
          "kms:TagResource",
          "kms:UntagResource"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

# ===========================
# CloudWatch Alarms for CloudHSM
# ===========================

# Alarm on CloudHSM cluster state changes
resource "aws_cloudwatch_metric_alarm" "cloudhsm_degraded" {
  alarm_name          = "cloudhsm-cluster-degraded"
  alarm_description   = "Alert when CloudHSM cluster is not in ACTIVE state"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HsmStatus"
  namespace           = "AWS/CloudHSM"
  period              = "300"
  statistic           = "Minimum"
  threshold           = "1"
  treat_missing_data  = "breaching"

  dimensions = {
    ClusterId = aws_cloudhsm_v2_cluster.cde_hsm.cluster_id
  }

  alarm_actions = [
    "arn:aws:sns:us-east-1:444455556666:security-alerts-critical"
  ]

  tags = {
    Severity = "Critical"
    PCIScope = "yes"
    Purpose  = "CloudHSM availability monitoring"
  }
}

# ===========================
# CloudHSM Security Group
# ===========================

resource "aws_security_group" "cloudhsm" {
  name_description = "Security group for CloudHSM cluster"
  vpc_id          = var.cde_vpc_id

  # CloudHSM cluster communication (HSMs to each other)
  ingress {
    description = "CloudHSM cluster communication"
    from_port   = 2223
    to_port     = 2225
    protocol    = "tcp"
    self        = true
  }

  # Client connections from CDE application subnets
  ingress {
    description = "CloudHSM client connections"
    from_port   = 2223
    to_port     = 2225
    protocol    = "tcp"
    cidr_blocks = var.cde_application_subnet_cidrs
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name     = "examplepay-cloudhsm-sg"
    PCIScope = "yes"
    Purpose  = "CloudHSM cluster security"
  }
}

# ===========================
# IAM Role for CloudHSM Management
# ===========================

resource "aws_iam_role" "cloudhsm_admin" {
  name               = "CloudHSMAdministrator"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::444455556666:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
          IpAddress = {
            "aws:SourceIp" = var.corporate_ip_ranges
          }
        }
      }
    ]
  })

  tags = {
    Name     = "CloudHSMAdministrator"
    PCIScope = "yes"
  }
}

resource "aws_iam_role_policy" "cloudhsm_admin" {
  name = "CloudHSMAdminPolicy"
  role = aws_iam_role.cloudhsm_admin.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudHSMManagement"
        Effect = "Allow"
        Action = [
          "cloudhsm:Describe*",
          "cloudhsm:List*",
          "cloudhsm:CreateHsm",
          "cloudhsm:DeleteHsm",
          "cloudhsm:CreateCluster",
          "cloudhsm:InitializeCluster",
          "cloudhsm:TagResource",
          "cloudhsm:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "KMSCustomKeyStore"
        Effect = "Allow"
        Action = [
          "kms:CreateCustomKeyStore",
          "kms:ConnectCustomKeyStore",
          "kms:DisconnectCustomKeyStore",
          "kms:DescribeCustomKeyStores",
          "kms:UpdateCustomKeyStore"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyKeyDeletion"
        Effect = "Deny"
        Action = [
          "kms:ScheduleKeyDeletion",
          "cloudhsm:DeleteCluster"
        ]
        Resource = "*"
      }
    ]
  })
}

# ===========================
# Secrets Manager for HSM Credentials
# ===========================

data "aws_secretsmanager_secret" "hsm_password" {
  name = "cloudhsm/cde-cluster/kmsuser-password"
}

data "aws_secretsmanager_secret_version" "hsm_password" {
  secret_id = data.aws_secretsmanager_secret.hsm_password.id
}

# ===========================
# Variables
# ===========================

variable "private_subnet_ids" {
  description = "Private subnet IDs for CloudHSM (one per AZ)"
  type        = list(string)
}

variable "cde_vpc_id" {
  description = "VPC ID for CDE environment"
  type        = string
}

variable "cde_application_subnet_cidrs" {
  description = "CIDR blocks for CDE application subnets"
  type        = list(string)
}

variable "cloudhsm_trust_anchor_cert" {
  description = "CloudHSM cluster trust anchor certificate"
  type        = string
  sensitive   = true
}

variable "corporate_ip_ranges" {
  description = "Corporate IP ranges for CloudHSM administration"
  type        = list(string)
  default     = ["192.0.2.0/24"]
}

# ===========================
# Data Sources
# ===========================

data "aws_availability_zones" "available" {
  state = "available"
}

# ===========================
# Outputs
# ===========================

output "cloudhsm_cluster_id" {
  description = "CloudHSM cluster ID"
  value       = aws_cloudhsm_v2_cluster.cde_hsm.cluster_id
}

output "cloudhsm_cluster_state" {
  description = "CloudHSM cluster state"
  value       = aws_cloudhsm_v2_cluster.cde_hsm.cluster_state
}

output "custom_key_store_id" {
  description = "KMS custom key store ID"
  value       = aws_kms_custom_key_store.cde_keystore.id
}

output "hsm_backed_keys" {
  description = "CloudHSM-backed KMS keys"
  value = {
    rds_cde = aws_kms_key.rds_cde_hsm.id
    s3_cde  = aws_kms_key.s3_cde_hsm.id
  }
}

output "hsm_security_group_id" {
  description = "CloudHSM security group ID"
  value       = aws_security_group.cloudhsm.id
}
