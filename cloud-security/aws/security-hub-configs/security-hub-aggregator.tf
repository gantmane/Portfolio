# Security Hub Finding Aggregator Configuration
# Author: Evgeniy Gantman
# Purpose: Multi-region and multi-account finding aggregation
# PCI DSS: Requirement 10.6 (Review logs for anomalies), Requirement 12.10 (Centralized monitoring)

# Benefits:
# - Unified security view across 15+ AWS accounts
# - Cross-region finding aggregation
# - Centralized compliance reporting
# - Single pane of glass for security operations
# - Reduced operational overhead

# ===========================
# Finding Aggregator
# ===========================

# Create finding aggregator in home region (central security account)
# This aggregates findings from all regions into a single region for unified view
resource "aws_securityhub_finding_aggregator" "main" {
  linking_mode = "ALL_REGIONS"

  # Specify regions to aggregate from
  regions = [
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1"
  ]
}

# ===========================
# Organization Configuration
# ===========================

# Enable Security Hub for all organization accounts automatically
resource "aws_securityhub_organization_configuration" "main" {
  auto_enable           = true
  auto_enable_standards = true

  organization_configuration {
    configuration_type = "CENTRAL"
  }
}

# ===========================
# Member Account Configuration
# ===========================

# Get all organization accounts
data "aws_organizations_organization" "main" {}

# Invite member accounts to Security Hub (for non-Organizations setups)
# Note: With Organizations, this is automatic via auto_enable above
resource "aws_securityhub_member" "organization_accounts" {
  for_each = toset([
    "222233334444",  # Production account
    "333344445555",  # Development account
    "444455556666",  # CDE account
    "555566667777",  # Staging account
  ])

  account_id = each.value
  email      = "security+${each.value}@example.com"
  invite     = true

  depends_on = [aws_securityhub_account.main]
}

# ===========================
# Cross-Region Findings Aggregation
# ===========================

# Replicate findings to central region for analysis
# This creates a complete picture of security posture across all regions

# Custom insight for cross-region critical findings
resource "aws_securityhub_insight" "cross_region_critical" {
  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
  }

  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  filters {
    workflow_status {
      comparison = "EQUALS"
      value      = "NEW"
    }
  }

  group_by_attribute = "Region"
  name               = "Critical Findings by Region (Aggregated)"

  depends_on = [aws_securityhub_finding_aggregator.main]
}

# Custom insight for cross-account findings
resource "aws_securityhub_insight" "cross_account_high" {
  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "HIGH"
    }
  }

  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }
  }

  group_by_attribute = "AwsAccountId"
  name               = "High Severity Non-Compliant Resources by Account"

  depends_on = [aws_securityhub_finding_aggregator.main]
}

# ===========================
# Aggregated Reporting
# ===========================

# SNS topic for aggregated critical findings
resource "aws_sns_topic" "aggregated_critical" {
  name              = "security-hub-aggregated-critical"
  display_name      = "Security Hub Aggregated Critical Findings"
  kms_master_key_id = data.aws_kms_alias.sns.target_key_arn

  tags = {
    Name        = "security-hub-aggregated-critical"
    Purpose     = "Centralized critical finding alerts"
    Aggregation = "true"
  }
}

# Email subscription for executive team
resource "aws_sns_topic_subscription" "aggregated_critical_email" {
  topic_arn = aws_sns_topic.aggregated_critical.arn
  protocol  = "email"
  endpoint  = "security-executives@example.com"
}

# EventBridge rule for aggregated critical findings
# This catches findings from all regions and accounts
resource "aws_cloudwatch_event_rule" "aggregated_critical_findings" {
  name        = "security-hub-aggregated-critical"
  description = "Aggregate critical findings from all regions and accounts"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL"]
        }
        RecordState = ["ACTIVE"]
        Workflow = {
          Status = ["NEW"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "aggregated_critical_sns" {
  rule      = aws_cloudwatch_event_rule.aggregated_critical_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.aggregated_critical.arn

  input_transformer {
    input_paths = {
      account    = "$.detail.findings[0].AwsAccountId"
      region     = "$.detail.findings[0].Region"
      title      = "$.detail.findings[0].Title"
      severity   = "$.detail.findings[0].Severity.Label"
      resourceId = "$.detail.findings[0].Resources[0].Id"
    }

    input_template = <<EOF
{
  "alert": "Security Hub Critical Finding (Aggregated View)",
  "account": "<account>",
  "region": "<region>",
  "finding": "<title>",
  "severity": "<severity>",
  "resource": "<resourceId>",
  "dashboard": "https://console.aws.amazon.com/securityhub/home?region=us-east-1#/summary"
}
EOF
  }
}

# ===========================
# Aggregated CloudWatch Dashboard
# ===========================

# Unified dashboard showing security posture across all regions and accounts
resource "aws_cloudwatch_dashboard" "security_hub_aggregated" {
  dashboard_name = "SecurityHub-Aggregated-View"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          title   = "Critical Findings (All Regions)"
          metrics = [
            ["AWS/SecurityHub", "FindingsBySeverity", { stat = "Sum", label = "Critical" }]
          ]
          period = 300
          stat   = "Sum"
          region = "us-east-1"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type = "metric"
        properties = {
          title   = "Findings by Account"
          metrics = [
            ["AWS/SecurityHub", "FindingsByAccount", { stat = "Sum" }]
          ]
          period = 3600
          stat   = "Sum"
          region = "us-east-1"
        }
      },
      {
        type = "log"
        properties = {
          title  = "Recent Critical Findings (All Regions)"
          region = "us-east-1"
          query  = <<EOF
SOURCE '/aws/events/securityhub'
| fields @timestamp, detail.findings.0.Title, detail.findings.0.Severity.Label, detail.findings.0.Region
| filter detail.findings.0.Severity.Label = "CRITICAL"
| sort @timestamp desc
| limit 20
EOF
        }
      },
      {
        type = "metric"
        properties = {
          title   = "Compliance Score (PCI DSS - All Accounts)"
          metrics = [
            ["AWS/SecurityHub", "ComplianceScore", { standard = "pci-dss" }]
          ]
          period = 86400
          stat   = "Average"
          region = "us-east-1"
          yAxis = {
            left = {
              min = 0
              max = 100
            }
          }
        }
      },
      {
        type = "metric"
        properties = {
          title   = "Finding Resolution Rate (7 days)"
          metrics = [
            ["AWS/SecurityHub", "FindingsResolved", { stat = "Sum", period = 604800 }],
            [".", "FindingsCreated", { stat = "Sum", period = 604800 }]
          ]
          region = "us-east-1"
        }
      }
    ]
  })
}

# ===========================
# Aggregated Metrics and Alarms
# ===========================

# Alarm for spike in critical findings across all regions
resource "aws_cloudwatch_metric_alarm" "aggregated_critical_spike" {
  alarm_name          = "security-hub-aggregated-critical-spike"
  alarm_description   = "Alert when critical findings spike across all regions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "FindingsBySeverity"
  namespace           = "AWS/SecurityHub"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Severity = "CRITICAL"
  }

  alarm_actions = [aws_sns_topic.aggregated_critical.arn]

  tags = {
    Severity    = "Critical"
    Purpose     = "Detect sudden increase in security findings"
    Aggregation = "Multi-region"
  }
}

# Alarm for declining compliance score
resource "aws_cloudwatch_metric_alarm" "compliance_score_decline" {
  alarm_name          = "security-hub-compliance-score-decline"
  alarm_description   = "Alert when overall compliance score drops"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ComplianceScore"
  namespace           = "AWS/SecurityHub"
  period              = "86400"  # Daily
  statistic           = "Average"
  threshold           = "90"     # 90% compliance target
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.aggregated_critical.arn]

  tags = {
    Severity    = "High"
    Purpose     = "Maintain high compliance posture"
    Aggregation = "Multi-account"
  }
}

# ===========================
# Kinesis Stream for SIEM Integration
# ===========================

# Stream aggregated findings to external SIEM (Wazuh)
resource "aws_kinesis_stream" "security_hub_findings" {
  name             = "security-hub-aggregated-findings"
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
    Name        = "security-hub-aggregated-findings"
    Purpose     = "SIEM integration for centralized logging"
    Aggregation = "All findings"
  }
}

# Kinesis Firehose for delivery to S3 (for long-term retention and SIEM)
resource "aws_kinesis_firehose_delivery_stream" "security_hub_to_s3" {
  name        = "security-hub-findings-to-s3"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.security_hub_findings.arn
    prefix     = "findings/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"

    buffer_size     = 5
    buffer_interval = 300

    compression_format = "GZIP"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = "/aws/kinesisfirehose/security-hub-findings"
      log_stream_name = "S3Delivery"
    }
  }

  kinesis_source_configuration {
    kinesis_stream_arn = aws_kinesis_stream.security_hub_findings.arn
    role_arn           = aws_iam_role.firehose.arn
  }

  tags = {
    Name    = "security-hub-findings-to-s3"
    Purpose = "Long-term finding retention for compliance"
  }
}

# EventBridge rule to send all findings to Kinesis
resource "aws_cloudwatch_event_rule" "all_findings_to_kinesis" {
  name        = "security-hub-all-findings-to-kinesis"
  description = "Send all Security Hub findings to Kinesis for SIEM"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })
}

resource "aws_cloudwatch_event_target" "findings_to_kinesis" {
  rule      = aws_cloudwatch_event_rule.all_findings_to_kinesis.name
  target_id = "SendToKinesis"
  arn       = aws_kinesis_stream.security_hub_findings.arn
  role_arn  = aws_iam_role.events_to_kinesis.arn
}

# ===========================
# S3 Bucket for Finding Archive
# ===========================

resource "aws_s3_bucket" "security_hub_findings" {
  bucket = "examplepay-security-hub-findings-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "security-hub-findings-archive"
    Purpose     = "Long-term finding retention"
    Compliance  = "PCI DSS Req 10.5 (1 year online, 3 years archive)"
    Aggregation = "All regions and accounts"
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
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "security_hub_findings" {
  bucket = aws_s3_bucket.security_hub_findings.id

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
      days          = 1095  # 3 years
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 2555  # 7 years (PCI DSS retention)
    }
  }
}

# ===========================
# IAM Roles
# ===========================

resource "aws_iam_role" "firehose" {
  name = "SecurityHubFirehoseRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "firehose.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "firehose" {
  name = "FirehoseS3DeliveryPolicy"
  role = aws_iam_role.firehose.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.security_hub_findings.arn,
          "${aws_s3_bucket.security_hub_findings.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kinesis:GetRecords",
          "kinesis:GetShardIterator",
          "kinesis:DescribeStream"
        ]
        Resource = aws_kinesis_stream.security_hub_findings.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          data.aws_kms_alias.s3.target_key_arn,
          data.aws_kms_alias.kinesis.target_key_arn
        ]
      }
    ]
  })
}

resource "aws_iam_role" "events_to_kinesis" {
  name = "EventBridgeToKinesisRole"

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

resource "aws_iam_role_policy" "events_to_kinesis" {
  name = "EventBridgeKinesisPolicy"
  role = aws_iam_role.events_to_kinesis.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "kinesis:PutRecord",
        "kinesis:PutRecords"
      ]
      Resource = aws_kinesis_stream.security_hub_findings.arn
    }]
  })
}

# ===========================
# Outputs
# ===========================

output "finding_aggregator_arn" {
  description = "ARN of the Security Hub finding aggregator"
  value       = aws_securityhub_finding_aggregator.main.id
}

output "aggregation_regions" {
  description = "Regions aggregated for centralized finding view"
  value       = aws_securityhub_finding_aggregator.main.regions
}

output "dashboard_url" {
  description = "CloudWatch dashboard for aggregated security view"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=${aws_cloudwatch_dashboard.security_hub_aggregated.dashboard_name}"
}

output "findings_archive_bucket" {
  description = "S3 bucket for long-term finding retention"
  value       = aws_s3_bucket.security_hub_findings.id
}

output "kinesis_stream" {
  description = "Kinesis stream for SIEM integration"
  value       = aws_kinesis_stream.security_hub_findings.name
}

output "aggregation_summary" {
  description = "Summary of Security Hub aggregation configuration"
  value = {
    mode              = "Multi-region and multi-account aggregation"
    regions           = length(aws_securityhub_finding_aggregator.main.regions)
    member_accounts   = length(aws_securityhub_member.organization_accounts)
    siem_integration  = "Kinesis Stream to Wazuh"
    retention_period  = "7 years (PCI DSS compliant)"
    dashboard         = "Unified CloudWatch dashboard"
  }
}
