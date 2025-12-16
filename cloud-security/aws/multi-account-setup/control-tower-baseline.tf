# AWS Control Tower Baseline Configuration
# Author: Evgeniy Gantman
# Purpose: Control Tower landing zone with security baseline
# PCI DSS: Requirements 2, 10, 11

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Control Tower is typically set up via console, but we can configure
# the foundational resources and guardrails programmatically

# ===========================
# IAM Identity Center (SSO)
# ===========================

# Note: IAM Identity Center must be enabled manually in the management account
# This configuration assumes it's already set up

data "aws_ssoadmin_instances" "main" {}

# Permission Set for Security Auditors (Read-Only)
resource "aws_ssoadmin_permission_set" "security_auditor" {
  name             = "SecurityAuditor"
  description      = "Read-only access for security auditing and compliance"
  instance_arn     = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  session_duration = "PT4H" # 4 hours

  tags = {
    Purpose = "Security Auditing"
    PCIScope = "yes"
  }
}

resource "aws_ssoadmin_managed_policy_attachment" "security_auditor_readonly" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.security_auditor.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_ssoadmin_managed_policy_attachment" "security_auditor_viewonly" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.security_auditor.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# Permission Set for DevOps Engineers
resource "aws_ssoadmin_permission_set" "devops_engineer" {
  name             = "DevOpsEngineer"
  description      = "DevOps engineers with deployment permissions"
  instance_arn     = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  session_duration = "PT8H" # 8 hours

  tags = {
    Purpose = "DevOps Engineering"
  }
}

# Custom inline policy for DevOps (least-privilege)
resource "aws_ssoadmin_permission_set_inline_policy" "devops_engineer" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.devops_engineer.arn

  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DevOpsReadAccess"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "eks:Describe*",
          "eks:List*",
          "rds:Describe*",
          "s3:List*",
          "s3:Get*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Get*",
          "logs:Describe*"
        ]
        Resource = "*"
      },
      {
        Sid    = "DevOpsDeployAccess"
        Effect = "Allow"
        Action = [
          "eks:UpdateNodegroupConfig",
          "eks:UpdateClusterConfig",
          "ecs:UpdateService",
          "ecs:RegisterTaskDefinition",
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = ["us-east-1", "us-west-2", "eu-west-1"]
          }
        }
      },
      {
        Sid      = "DenyProductionCDEModification"
        Effect   = "Deny"
        Action   = ["*"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceAccount" = "444455556666" # CDE account
          }
        }
      }
    ]
  })
}

# Permission Set for Network Administrators
resource "aws_ssoadmin_permission_set" "network_admin" {
  name             = "NetworkAdministrator"
  description      = "Network administrators for VPC and network management"
  instance_arn     = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  session_duration = "PT4H"

  tags = {
    Purpose = "Network Administration"
  }
}

resource "aws_ssoadmin_managed_policy_attachment" "network_admin" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.network_admin.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/job-function/NetworkAdministrator"
}

# ===========================
# Baseline Security Services
# ===========================

# Enable AWS Config in all accounts (via StackSets in real implementation)
# This is a template showing the configuration

resource "aws_config_configuration_recorder" "main" {
  name     = "default-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "default-delivery-channel"
  s3_bucket_name = "examplecorp-central-config"  # Central Config bucket

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# IAM Role for AWS Config
resource "aws_iam_role" "config_role" {
  name = "AWSConfigRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Purpose = "AWS Config Service Role"
  }
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

# ===========================
# AWS Config Rules (PCI DSS)
# ===========================

# Req 2: Ensure SSH is not open to 0.0.0.0/0
resource "aws_config_config_rule" "restricted_ssh" {
  name = "restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Req 3: Ensure EBS volumes are encrypted
resource "aws_config_config_rule" "encrypted_volumes" {
  name = "encrypted-volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Req 3: Ensure S3 buckets have encryption enabled
resource "aws_config_config_rule" "s3_bucket_server_side_encryption_enabled" {
  name = "s3-bucket-server-side-encryption-enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Req 1: Ensure security groups do not allow unrestricted access
resource "aws_config_config_rule" "restricted_common_ports" {
  name = "restricted-common-ports"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({
    blockedPort1 = "20"
    blockedPort2 = "21"
    blockedPort3 = "3389"
    blockedPort4 = "3306"
    blockedPort5 = "5432"
  })

  depends_on = [aws_config_configuration_recorder.main]
}

# Req 8: Ensure MFA is enabled for root user
resource "aws_config_config_rule" "root_account_mfa_enabled" {
  name = "root-account-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Req 10: Ensure CloudTrail is enabled
resource "aws_config_config_rule" "cloud_trail_enabled" {
  name = "cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Req 10: Ensure CloudTrail log file validation is enabled
resource "aws_config_config_rule" "cloud_trail_log_file_validation_enabled" {
  name = "cloudtrail-log-file-validation-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# ===========================
# Outputs
# ===========================

output "sso_instance_arn" {
  description = "IAM Identity Center instance ARN"
  value       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
}

output "security_auditor_permission_set_arn" {
  description = "Security Auditor permission set ARN"
  value       = aws_ssoadmin_permission_set.security_auditor.arn
}

output "devops_engineer_permission_set_arn" {
  description = "DevOps Engineer permission set ARN"
  value       = aws_ssoadmin_permission_set.devops_engineer.arn
}

output "network_admin_permission_set_arn" {
  description = "Network Administrator permission set ARN"
  value       = aws_ssoadmin_permission_set.network_admin.arn
}

output "config_rules_deployed" {
  description = "AWS Config rules deployed for PCI DSS compliance"
  value = [
    aws_config_config_rule.restricted_ssh.name,
    aws_config_config_rule.encrypted_volumes.name,
    aws_config_config_rule.s3_bucket_server_side_encryption_enabled.name,
    aws_config_config_rule.restricted_common_ports.name,
    aws_config_config_rule.root_account_mfa_enabled.name,
    aws_config_config_rule.cloud_trail_enabled.name,
    aws_config_config_rule.cloud_trail_log_file_validation_enabled.name
  ]
}
