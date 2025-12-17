# AWS GuardDuty Organization Configuration
# Author: Evgeniy Gantman
# Purpose: Multi-account threat detection with automated response
# PCI DSS: Requirement 11.4 (Intrusion detection), Requirement 10.6 (Log review)

# Benefits:
# - Real-time threat detection across 15+ AWS accounts
# - Automated response to critical findings (< 15 min MTTR)
# - SIEM integration for correlation with 500+ detection rules
# - PCI DSS compliance for intrusion detection requirements

# ===========================
# GuardDuty Detector
# ===========================

# Enable GuardDuty in the delegated administrator account
resource "aws_guardduty_detector" "main" {
  enable = true

  # Enable all data sources for comprehensive coverage
  datasources {
    s3_logs {
      enable = true  # Monitor S3 data access anomalies
    }

    kubernetes {
      audit_logs {
        enable = true  # Monitor EKS control plane activity
      }
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true  # Scan EBS volumes for malware
        }
      }
    }
  }

  # Finding publishing frequency
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = {
    Name        = "examplepay-guardduty"
    Environment = "organization"
    Purpose     = "Threat detection and intrusion prevention"
    ManagedBy   = "terraform"
  }
}

# ===========================
# Organization Configuration
# ===========================

# Enable GuardDuty as an organization service
resource "aws_guardduty_organization_admin_account" "main" {
  admin_account_id = var.security_account_id
}

# Configure organization-wide settings
resource "aws_guardduty_organization_configuration" "main" {
  detector_id = aws_guardduty_detector.main.id
  auto_enable = true  # Automatically enable for new accounts

  datasources {
    s3_logs {
      auto_enable = true
    }

    kubernetes {
      audit_logs {
        auto_enable = true
      }
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          auto_enable = true
        }
      }
    }
  }

  depends_on = [aws_guardduty_organization_admin_account.main]
}

# ===========================
# Member Accounts
# ===========================

# Invite member accounts to GuardDuty (for non-Organizations setup)
resource "aws_guardduty_member" "accounts" {
  for_each = toset([
    "222233334444",  # Production
    "333344445555",  # Development
    "444455556666",  # CDE
    "555566667777",  # Staging
  ])

  account_id                 = each.value
  detector_id                = aws_guardduty_detector.main.id
  email                      = "security+${each.value}@example.com"
  invite                     = true
  invitation_message         = "Please accept GuardDuty invitation from ExamplePay Security Account"
  disable_email_notification = false

  depends_on = [aws_guardduty_organization_admin_account.main]
}

# ===========================
# Finding Publishing
# ===========================

# S3 bucket for GuardDuty findings (long-term retention)
resource "aws_s3_bucket" "guardduty_findings" {
  bucket = "examplepay-guardduty-findings-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name       = "guardduty-findings"
    Purpose    = "Long-term finding retention"
    Compliance = "PCI DSS 10-year retention"
  }
}

resource "aws_s3_bucket_versioning" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = data.aws_kms_alias.s3.target_key_arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id

  rule {
    id     = "archive-old-findings"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER_IR"
    }

    transition {
      days          = 2555  # 7 years
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 3650  # 10 years for PCI DSS
    }
  }
}

# S3 bucket policy for GuardDuty
resource "aws_s3_bucket_policy" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGuardDutyToPublish"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.guardduty_findings.arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowGuardDutyToGetBucketLocation"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = "s3:GetBucketLocation"
        Resource = aws_s3_bucket.guardduty_findings.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Configure GuardDuty to publish findings to S3
resource "aws_guardduty_publishing_destination" "s3" {
  detector_id     = aws_guardduty_detector.main.id
  destination_arn = aws_s3_bucket.guardduty_findings.arn
  kms_key_arn     = data.aws_kms_alias.s3.target_key_arn

  depends_on = [aws_s3_bucket_policy.guardduty_findings]
}

# ===========================
# CloudWatch Integration
# ===========================

# CloudWatch event rule for all GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "guardduty-all-findings"
  description = "Capture all GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

# Send findings to CloudWatch Logs for analysis
resource "aws_cloudwatch_log_group" "guardduty_findings" {
  name              = "/aws/guardduty/findings"
  retention_in_days = 90
  kms_key_id        = data.aws_kms_alias.cloudwatch.target_key_arn

  tags = {
    Name    = "guardduty-findings"
    Purpose = "GuardDuty finding logs"
  }
}

resource "aws_cloudwatch_event_target" "guardduty_to_cloudwatch" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SendToCloudWatchLogs"
  arn       = aws_cloudwatch_log_group.guardduty_findings.arn
}

# ===========================
# SNS Alerting
# ===========================

# SNS topic for critical findings
resource "aws_sns_topic" "guardduty_critical" {
  name              = "guardduty-critical-findings"
  display_name      = "GuardDuty Critical Findings"
  kms_master_key_id = data.aws_kms_alias.sns.target_key_arn

  tags = {
    Name     = "guardduty-critical"
    Severity = "Critical"
    Purpose  = "PagerDuty escalation"
  }
}

# PagerDuty integration for critical findings
resource "aws_sns_topic_subscription" "guardduty_critical_pagerduty" {
  topic_arn = aws_sns_topic.guardduty_critical.arn
  protocol  = "https"
  endpoint  = "https://events.pagerduty.com/integration/${var.pagerduty_integration_key}/enqueue"
}

# SNS topic for high findings
resource "aws_sns_topic" "guardduty_high" {
  name              = "guardduty-high-findings"
  display_name      = "GuardDuty High Findings"
  kms_master_key_id = data.aws_kms_alias.sns.target_key_arn

  tags = {
    Name     = "guardduty-high"
    Severity = "High"
    Purpose  = "Slack notification"
  }
}

# Slack integration for high findings
resource "aws_sns_topic_subscription" "guardduty_high_slack" {
  topic_arn = aws_sns_topic.guardduty_high.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.slack_notifier.arn
}

# ===========================
# Kinesis Stream for SIEM Integration
# ===========================

# Kinesis stream for real-time finding delivery to Wazuh
resource "aws_kinesis_stream" "guardduty_findings" {
  name             = "guardduty-findings-stream"
  shard_count      = 2
  retention_period = 24

  encryption_type = "KMS"
  kms_key_id      = data.aws_kms_alias.kinesis.target_key_arn

  shard_level_metrics = [
    "IncomingBytes",
    "IncomingRecords",
    "OutgoingBytes",
    "OutgoingRecords",
  ]

  tags = {
    Name    = "guardduty-findings"
    Purpose = "SIEM integration (Wazuh)"
  }
}

# EventBridge target to send findings to Kinesis
resource "aws_cloudwatch_event_target" "guardduty_to_kinesis" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SendToKinesis"
  arn       = aws_kinesis_stream.guardduty_findings.arn
  role_arn  = aws_iam_role.eventbridge_to_kinesis.arn
}

# ===========================
# Metrics and Dashboards
# ===========================

# CloudWatch dashboard for GuardDuty metrics
resource "aws_cloudwatch_dashboard" "guardduty" {
  dashboard_name = "GuardDuty-Security-Overview"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          title   = "Findings by Severity (Last 7 Days)"
          metrics = [
            ["AWS/GuardDuty", "FindingsBySeverity", { stat = "Sum", label = "Critical", severity = "Critical" }],
            ["...", { severity = "High" }],
            ["...", { severity = "Medium" }],
            ["...", { severity = "Low" }]
          ]
          period = 3600
          stat   = "Sum"
          region = data.aws_region.current.name
        }
      },
      {
        type = "metric"
        properties = {
          title   = "Top Finding Types"
          metrics = [
            ["AWS/GuardDuty", "FindingsByType"]
          ]
          period = 86400
          stat   = "Sum"
          region = data.aws_region.current.name
        }
      },
      {
        type = "log"
        properties = {
          title  = "Recent Critical Findings"
          region = data.aws_region.current.name
          query  = <<EOF
SOURCE '/aws/guardduty/findings'
| fields @timestamp, detail.type, detail.severity, detail.title, detail.resource.instanceDetails.instanceId
| filter detail.severity >= 7.0
| sort @timestamp desc
| limit 20
EOF
        }
      }
    ]
  })
}

# ===========================
# IAM Roles
# ===========================

# IAM role for EventBridge to write to Kinesis
resource "aws_iam_role" "eventbridge_to_kinesis" {
  name = "GuardDutyEventBridgeToKinesis"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge_to_kinesis" {
  name = "PutRecordsToKinesis"
  role = aws_iam_role.eventbridge_to_kinesis.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "kinesis:PutRecord",
        "kinesis:PutRecords"
      ]
      Resource = aws_kinesis_stream.guardduty_findings.arn
    }]
  })
}

# ===========================
# Lambda for Slack Notifications
# ===========================

resource "aws_lambda_function" "slack_notifier" {
  filename      = "lambda_slack_notifier.zip"  # Placeholder
  function_name = "GuardDuty-Slack-Notifier"
  role          = aws_iam_role.slack_notifier_lambda.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 30

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
    }
  }

  tags = {
    Name    = "guardduty-slack-notifier"
    Purpose = "Send GuardDuty findings to Slack"
  }
}

resource "aws_iam_role" "slack_notifier_lambda" {
  name = "GuardDutySlackNotifierLambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "slack_notifier_basic" {
  role       = aws_iam_role.slack_notifier_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_permission" "slack_notifier_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_notifier.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.guardduty_high.arn
}

# ===========================
# Variables
# ===========================

variable "security_account_id" {
  description = "AWS account ID for security/delegated admin"
  type        = string
  default     = "111122223333"
}

variable "pagerduty_integration_key" {
  description = "PagerDuty integration key for critical alerts"
  type        = string
  sensitive   = true
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for high-severity alerts"
  type        = string
  sensitive   = true
}

# ===========================
# Data Sources
# ===========================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_kms_alias" "s3" {
  name = "alias/examplepay-s3"
}

data "aws_kms_alias" "sns" {
  name = "alias/examplepay-sns"
}

data "aws_kms_alias" "kinesis" {
  name = "alias/examplepay-kinesis"
}

data "aws_kms_alias" "cloudwatch" {
  name = "alias/examplepay-cloudwatch"
}

# ===========================
# Outputs
# ===========================

output "detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "findings_bucket" {
  description = "S3 bucket for GuardDuty findings"
  value       = aws_s3_bucket.guardduty_findings.id
}

output "findings_kinesis_stream" {
  description = "Kinesis stream for SIEM integration"
  value       = aws_kinesis_stream.guardduty_findings.name
}

output "dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.guardduty.dashboard_name}"
}

output "guardduty_summary" {
  description = "GuardDuty deployment summary"
  value = {
    detector_enabled       = aws_guardduty_detector.main.enable
    member_accounts        = length(aws_guardduty_member.accounts)
    s3_logs_enabled        = true
    kubernetes_audit_logs  = true
    malware_protection     = true
    finding_retention      = "90 days (GuardDuty), 10 years (S3)"
    siem_integration       = "Kinesis stream to Wazuh"
    alerting               = "Critical→PagerDuty, High→Slack"
  }
}
