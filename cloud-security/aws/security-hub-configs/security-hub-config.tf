# AWS Security Hub Core Configuration
# Author: Evgeniy Gantman
# Purpose: Enable and configure Security Hub for centralized security management
# PCI DSS: Continuous compliance monitoring (multiple requirements)

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
# Enable Security Hub
# ===========================

resource "aws_securityhub_account" "main" {
  enable_default_standards = false  # We'll enable standards explicitly
  control_finding_generator = "SECURITY_CONTROL"  # Use security controls

  auto_enable_controls = true  # Auto-enable new controls when standards update
}

# ===========================
# Product Subscriptions (Finding Sources)
# ===========================

# GuardDuty integration
resource "aws_securityhub_product_subscription" "guardduty" {
  product_arn = "arn:aws:securityhub:${data.aws_region.current.name}::product/aws/guardduty"

  depends_on = [aws_securityhub_account.main]
}

# Inspector integration
resource "aws_securityhub_product_subscription" "inspector" {
  product_arn = "arn:aws:securityhub:${data.aws_region.current.name}::product/aws/inspector"

  depends_on = [aws_securityhub_account.main]
}

# Macie integration
resource "aws_securityhub_product_subscription" "macie" {
  product_arn = "arn:aws:securityhub:${data.aws_region.current.name}::product/aws/macie"

  depends_on = [aws_securityhub_account.main]
}

# IAM Access Analyzer integration
resource "aws_securityhub_product_subscription" "access_analyzer" {
  product_arn = "arn:aws:securityhub:${data.aws_region.current.name}::product/aws/access-analyzer"

  depends_on = [aws_securityhub_account.main]
}

# Firewall Manager integration
resource "aws_securityhub_product_subscription" "firewall_manager" {
  product_arn = "arn:aws:securityhub:${data.aws_region.current.name}::product/aws/firewall-manager"

  depends_on = [aws_securityhub_account.main]
}

# Systems Manager Patch Manager integration
resource "aws_securityhub_product_subscription" "systems_manager" {
  product_arn = "arn:aws:securityhub:${data.aws_region.current.name}::product/aws/ssm-patch-manager"

  depends_on = [aws_securityhub_account.main]
}

# ===========================
# SNS Topics for Alerting
# ===========================

# Critical findings (PagerDuty integration)
resource "aws_sns_topic" "critical_findings" {
  name              = "security-hub-critical-findings"
  display_name      = "Security Hub Critical Findings"
  kms_master_key_id = data.aws_kms_alias.sns.target_key_arn

  tags = {
    Name     = "security-hub-critical"
    Severity = "Critical"
    Purpose  = "Real-time alerting for critical security findings"
  }
}

resource "aws_sns_topic_subscription" "critical_pagerduty" {
  topic_arn = aws_sns_topic.critical_findings.arn
  protocol  = "https"
  endpoint  = var.pagerduty_endpoint_url
}

resource "aws_sns_topic_subscription" "critical_email" {
  topic_arn = aws_sns_topic.critical_findings.arn
  protocol  = "email"
  endpoint  = "security-oncall@example.com"
}

# High findings (Slack integration)
resource "aws_sns_topic" "high_findings" {
  name              = "security-hub-high-findings"
  display_name      = "Security Hub High Findings"
  kms_master_key_id = data.aws_kms_alias.sns.target_key_arn

  tags = {
    Name     = "security-hub-high"
    Severity = "High"
  }
}

resource "aws_sns_topic_subscription" "high_slack" {
  topic_arn = aws_sns_topic.high_findings.arn
  protocol  = "https"
  endpoint  = var.slack_webhook_url
}

resource "aws_sns_topic_subscription" "high_email" {
  topic_arn = aws_sns_topic.high_findings.arn
  protocol  = "email"
  endpoint  = "security-team@example.com"
}

# Medium findings (Email only)
resource "aws_sns_topic" "medium_findings" {
  name              = "security-hub-medium-findings"
  display_name      = "Security Hub Medium Findings"
  kms_master_key_id = data.aws_kms_alias.sns.target_key_arn

  tags = {
    Name     = "security-hub-medium"
    Severity = "Medium"
  }
}

resource "aws_sns_topic_subscription" "medium_email" {
  topic_arn = aws_sns_topic.medium_findings.arn
  protocol  = "email"
  endpoint  = "security-team@example.com"
}

# ===========================
# EventBridge Rules for Severity-Based Routing
# ===========================

# Route critical findings to critical SNS topic
resource "aws_cloudwatch_event_rule" "critical_findings" {
  name        = "security-hub-critical-findings"
  description = "Route critical Security Hub findings to PagerDuty"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL"]
        }
        Workflow = {
          Status = ["NEW"]
        }
      }
    }
  })

  tags = {
    Name = "security-hub-critical-findings"
  }
}

resource "aws_cloudwatch_event_target" "critical_findings_sns" {
  rule      = aws_cloudwatch_event_rule.critical_findings.name
  target_id = "SendToCriticalSNS"
  arn       = aws_sns_topic.critical_findings.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.findings[0].Severity.Label"
      title       = "$.detail.findings[0].Title"
      description = "$.detail.findings[0].Description"
      resource    = "$.detail.findings[0].Resources[0].Id"
      account     = "$.detail.findings[0].AwsAccountId"
      region      = "$.detail.findings[0].Resources[0].Region"
    }

    input_template = <<EOF
{
  "AlarmName": "Security Hub Critical Finding",
  "AlarmDescription": "<title>",
  "NewStateValue": "ALARM",
  "NewStateReason": "<description>",
  "StateChangeTime": "$${timestamp}",
  "Trigger": {
    "Severity": "<severity>",
    "Resource": "<resource>",
    "Account": "<account>",
    "Region": "<region>"
  }
}
EOF
  }
}

# Route high findings to high SNS topic
resource "aws_cloudwatch_event_rule" "high_findings" {
  name        = "security-hub-high-findings"
  description = "Route high Security Hub findings to Slack"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["HIGH"]
        }
        Workflow = {
          Status = ["NEW"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "high_findings_sns" {
  rule      = aws_cloudwatch_event_rule.high_findings.name
  target_id = "SendToHighSNS"
  arn       = aws_sns_topic.high_findings.arn
}

# Route medium findings to medium SNS topic
resource "aws_cloudwatch_event_rule" "medium_findings" {
  name        = "security-hub-medium-findings"
  description = "Route medium Security Hub findings to email"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["MEDIUM"]
        }
        Workflow = {
          Status = ["NEW"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "medium_findings_sns" {
  rule      = aws_cloudwatch_event_rule.medium_findings.name
  target_id = "SendToMediumSNS"
  arn       = aws_sns_topic.medium_findings.arn
}

# ===========================
# SNS Topic Policies
# ===========================

resource "aws_sns_topic_policy" "critical_findings" {
  arn = aws_sns_topic.critical_findings.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.critical_findings.arn
      }
    ]
  })
}

resource "aws_sns_topic_policy" "high_findings" {
  arn = aws_sns_topic.high_findings.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.high_findings.arn
      }
    ]
  })
}

resource "aws_sns_topic_policy" "medium_findings" {
  arn = aws_sns_topic.medium_findings.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.medium_findings.arn
      }
    ]
  })
}

# ===========================
# S3 Bucket for Findings Export
# ===========================

resource "aws_s3_bucket" "security_hub_findings" {
  bucket = "examplepay-security-hub-findings-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name    = "security-hub-findings"
    Purpose = "Long-term storage of Security Hub findings"
  }
}

resource "aws_s3_bucket_versioning" "security_hub_findings" {
  bucket = aws_s3_bucket.security_hub_findings.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_hub_findings" {
  bucket = aws_s3_bucket.security_hub_findings.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = data.aws_kms_alias.s3.target_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "security_hub_findings" {
  bucket = aws_s3_bucket.security_hub_findings.id

  rule {
    id     = "findings-lifecycle"
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
      days          = 730
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 3650  # 10 years
    }
  }
}

resource "aws_s3_bucket_public_access_block" "security_hub_findings" {
  bucket = aws_s3_bucket.security_hub_findings.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ===========================
# Data Sources
# ===========================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_kms_alias" "sns" {
  name = "alias/messaging-prod"
}

data "aws_kms_alias" "s3" {
  name = "alias/s3-prod"
}

# ===========================
# Variables
# ===========================

variable "pagerduty_endpoint_url" {
  description = "PagerDuty SNS integration endpoint"
  type        = string
  default     = "https://events.pagerduty.com/integration/12345/enqueue"
  sensitive   = true
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for security notifications"
  type        = string
  default     = "https://hooks.slack.com/services/T00/B00/XXXX"
  sensitive   = true
}

# ===========================
# Outputs
# ===========================

output "security_hub_arn" {
  description = "Security Hub ARN"
  value       = aws_securityhub_account.main.arn
}

output "sns_topic_arns" {
  description = "SNS topic ARNs for findings"
  value = {
    critical = aws_sns_topic.critical_findings.arn
    high     = aws_sns_topic.high_findings.arn
    medium   = aws_sns_topic.medium_findings.arn
  }
}

output "findings_bucket" {
  description = "S3 bucket for findings export"
  value       = aws_s3_bucket.security_hub_findings.id
}

output "security_hub_enabled" {
  description = "Security Hub status"
  value = {
    enabled            = true
    control_generator  = "SECURITY_CONTROL"
    auto_enable        = true
    integrated_services = [
      "GuardDuty",
      "Inspector",
      "Macie",
      "IAM Access Analyzer",
      "Firewall Manager",
      "Systems Manager"
    ]
  }
}
