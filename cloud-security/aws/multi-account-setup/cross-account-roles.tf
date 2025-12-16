# Cross-Account IAM Roles for Multi-Account Access
# Author: Evgeniy Gantman
# Purpose: Define cross-account roles for secure access patterns
# PCI DSS: Requirement 7 (Access Control), Requirement 8 (Authentication)

terraform {
  required_version = ">= 1.5.0"
}

variable "management_account_id" {
  description = "Management account ID"
  type        = string
  default     = "999988887777"
}

variable "security_audit_account_id" {
  description = "Security audit account ID"
  type        = string
  default     = "111122223333"
}

# ===========================
# Security Audit Role (Read-Only)
# ===========================

resource "aws_iam_role" "security_audit" {
  name        = "SecurityAuditRole"
  description = "Cross-account read-only access for security auditing"

  # Trust policy - Allow Security Audit account to assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.security_audit_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
          IpAddress = {
            "aws:SourceIp" = [
              "10.0.0.0/8",      # Corporate network
              "192.0.2.0/24"     # VPN range
            ]
          }
        }
      }
    ]
  })

  tags = {
    Purpose  = "Security Auditing"
    PCIScope = "yes"
  }
}

resource "aws_iam_role_policy_attachment" "security_audit_readonly" {
  role       = aws_iam_role.security_audit.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "security_audit_viewonly" {
  role       = aws_iam_role.security_audit.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# ===========================
# Network Administrator Role
# ===========================

resource "aws_iam_role" "network_admin" {
  name        = "NetworkAdminRole"
  description = "Cross-account network administration access"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.management_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = {
    Purpose = "Network Administration"
  }
}

resource "aws_iam_policy" "network_admin" {
  name        = "NetworkAdminPolicy"
  description = "Network administration permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VPCManagement"
        Effect = "Allow"
        Action = [
          "ec2:*Vpc*",
          "ec2:*Subnet*",
          "ec2:*RouteTable*",
          "ec2:*InternetGateway*",
          "ec2:*NatGateway*",
          "ec2:*NetworkAcl*",
          "ec2:*VpnGateway*",
          "ec2:*CustomerGateway*",
          "ec2:*VpnConnection*",
          "ec2:*TransitGateway*",
          "ec2:*FlowLogs*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecurityGroupManagement"
        Effect = "Allow"
        Action = [
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
          "ec2:UpdateSecurityGroupRuleDescriptionsEgress"
        ]
        Resource = "*"
      },
      {
        Sid    = "Route53Management"
        Effect = "Allow"
        Action = [
          "route53:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "NetworkFirewallManagement"
        Effect = "Allow"
        Action = [
          "network-firewall:*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "network_admin" {
  role       = aws_iam_role.network_admin.name
  policy_arn = aws_iam_policy.network_admin.arn
}

# ===========================
# CI/CD Deployment Role
# ===========================

resource "aws_iam_role" "cicd_deployment" {
  name        = "CICDDeploymentRole"
  description = "Cross-account access for CI/CD pipelines"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.management_account_id}:role/GitLabRunnerRole"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "gitlab-runner-external-id-12345"
          }
        }
      }
    ]
  })

  max_session_duration = 3600 # 1 hour

  tags = {
    Purpose = "CI/CD Deployment"
  }
}

resource "aws_iam_policy" "cicd_deployment" {
  name        = "CICDDeploymentPolicy"
  description = "Least-privilege deployment permissions for CI/CD"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EKSDeployment"
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters",
          "eks:DescribeNodegroup",
          "eks:ListNodegroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECRImagePush"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = "*"
      },
      {
        Sid    = "LambdaDeployment"
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:PublishVersion",
          "lambda:CreateAlias",
          "lambda:UpdateAlias"
        ]
        Resource = "arn:aws:lambda:*:*:function:*"
      },
      {
        Sid    = "S3ArtifactAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::examplepay-artifacts/*",
          "arn:aws:s3:::examplepay-artifacts"
        ]
      },
      {
        Sid      = "DenyCDEAccess"
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

resource "aws_iam_role_policy_attachment" "cicd_deployment" {
  role       = aws_iam_role.cicd_deployment.name
  policy_arn = aws_iam_policy.cicd_deployment.arn
}

# ===========================
# Break Glass Emergency Access Role
# ===========================

resource "aws_iam_role" "break_glass" {
  name        = "BreakGlassRole"
  description = "Emergency access role (requires MFA, logged to SIEM)"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${var.management_account_id}:user/emergency-admin-1",
            "arn:aws:iam::${var.management_account_id}:user/emergency-admin-2"
          ]
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
          NumericLessThan = {
            "aws:MultiFactorAuthAge" = "900" # MFA must be < 15 minutes old
          }
        }
      }
    ]
  })

  max_session_duration = 3600 # 1 hour max

  tags = {
    Purpose       = "Emergency Access"
    PCIScope      = "yes"
    AlertOnAssume = "true" # Trigger SIEM alert
  }
}

resource "aws_iam_role_policy_attachment" "break_glass_admin" {
  role       = aws_iam_role.break_glass.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# CloudWatch alarm to alert on Break Glass role assumption
resource "aws_cloudwatch_log_metric_filter" "break_glass_usage" {
  name           = "BreakGlassRoleAssumed"
  log_group_name = "/aws/cloudtrail/organization-trail"
  pattern        = "{ $.eventName = \"AssumeRole\" && $.requestParameters.roleArn = \"*BreakGlassRole\" }"

  metric_transformation {
    name      = "BreakGlassRoleAssumptions"
    namespace = "Security/AccessControl"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "break_glass_alert" {
  alarm_name          = "break-glass-role-assumed"
  alarm_description   = "Alert when Break Glass emergency access role is assumed"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "BreakGlassRoleAssumptions"
  namespace           = "Security/AccessControl"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  treat_missing_data  = "notBreaching"

  alarm_actions = [
    "arn:aws:sns:us-east-1:${var.management_account_id}:security-alerts"
  ]

  tags = {
    Severity = "Critical"
    PCIScope = "yes"
  }
}

# ===========================
# Outputs
# ===========================

output "security_audit_role_arn" {
  description = "Security Audit role ARN for cross-account access"
  value       = aws_iam_role.security_audit.arn
}

output "network_admin_role_arn" {
  description = "Network Admin role ARN"
  value       = aws_iam_role.network_admin.arn
}

output "cicd_deployment_role_arn" {
  description = "CI/CD Deployment role ARN"
  value       = aws_iam_role.cicd_deployment.arn
}

output "break_glass_role_arn" {
  description = "Break Glass emergency access role ARN"
  value       = aws_iam_role.break_glass.arn
}
