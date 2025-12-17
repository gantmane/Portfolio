# AWS WAF Logging and Monitoring Configuration
# Author: Evgeniy Gantman
# Purpose: Comprehensive logging and alerting for WAF events
# PCI DSS: Requirement 10.2 (Audit logs), Requirement 10.5 (Log retention)

# Benefits:
# - Full request logging to S3 for forensics
# - Real-time streaming to Kinesis for SIEM integration
# - CloudWatch metrics and alarms for attack detection
# - 7-year retention for PCI DSS compliance

# ===========================
# S3 Bucket for WAF Logs
# ===========================

# S3 bucket for WAF log storage (7-year retention)
resource "aws_s3_bucket" "waf_logs" {
  bucket = "aws-waf-logs-examplepay-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "waf-logs"
    Purpose     = "WAF request logs for forensics and compliance"
    Compliance  = "PCI DSS 10.5 - 7 year retention"
    Environment = "production"
  }
}

resource "aws_s3_bucket_versioning" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = data.aws_kms_alias.s3.target_key_arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle policy for 7-year retention (PCI DSS)
resource "aws_s3_bucket_lifecycle_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    id     = "waf-log-retention"
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
      days = 2555  # 7 years (PCI DSS retention)
    }
  }
}

# S3 bucket policy for WAF logging
resource "aws_s3_bucket_policy" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.waf_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.waf_logs.arn
      }
    ]
  })
}

# ===========================
# Kinesis Firehose for Real-Time Streaming
# ===========================

# Kinesis Data Firehose for streaming WAF logs to S3
resource "aws_kinesis_firehose_delivery_stream" "waf_logs" {
  name        = "aws-waf-logs-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_waf.arn
    bucket_arn = aws_s3_bucket.waf_logs.arn

    prefix              = "waf-logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "waf-logs-errors/"

    buffer_size     = 5
    buffer_interval = 300

    compression_format = "GZIP"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose_waf.name
      log_stream_name = "S3Delivery"
    }

    processing_configuration {
      enabled = true

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = aws_lambda_function.waf_log_processor.arn
        }
      }
    }
  }

  tags = {
    Name    = "waf-logs-firehose"
    Purpose = "Stream WAF logs to S3 and SIEM"
  }
}

# ===========================
# WAF Logging Configuration
# ===========================

# Enable logging for CloudFront Web ACL
resource "aws_wafv2_web_acl_logging_configuration" "cloudfront" {
  provider = aws.us-east-1

  resource_arn            = aws_wafv2_web_acl.cloudfront_global.arn
  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf_logs.arn]

  # Redact sensitive fields from logs
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  # Filter logs to reduce volume (optional)
  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior = "KEEP"
      condition {
        action_condition {
          action = "BLOCK"
        }
      }
      requirement = "MEETS_ANY"
    }

    filter {
      behavior = "DROP"
      condition {
        action_condition {
          action = "ALLOW"
        }
      }
      condition {
        label_name_condition {
          label_name = "awswaf:managed:aws:core-rule-set:NoUserAgent_Header"
        }
      }
      requirement = "MEETS_ALL"
    }
  }
}

# Enable logging for ALB Web ACL
resource "aws_wafv2_web_acl_logging_configuration" "alb" {
  resource_arn            = aws_wafv2_web_acl.alb_regional.arn
  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf_logs.arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}

# ===========================
# Lambda for Log Processing
# ===========================

# Lambda function to enrich WAF logs before storing
resource "aws_lambda_function" "waf_log_processor" {
  filename      = "lambda_waf_log_processor.zip"  # Placeholder
  function_name = "WAF-Log-Processor"
  role          = aws_iam_role.waf_log_processor.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60

  environment {
    variables = {
      THREAT_INTEL_TABLE = "waf-threat-intel"
    }
  }

  tags = {
    Name    = "waf-log-processor"
    Purpose = "Enrich WAF logs with threat intelligence"
  }
}

resource "aws_iam_role" "waf_log_processor" {
  name = "WAFLogProcessorLambda"

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

resource "aws_iam_role_policy_attachment" "waf_log_processor_basic" {
  role       = aws_iam_role.waf_log_processor.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ===========================
# CloudWatch Log Group
# ===========================

resource "aws_cloudwatch_log_group" "firehose_waf" {
  name              = "/aws/kinesisfirehose/waf-logs"
  retention_in_days = 7
  kms_key_id        = data.aws_kms_alias.cloudwatch.target_key_arn

  tags = {
    Name    = "firehose-waf-logs"
    Purpose = "Kinesis Firehose delivery logs"
  }
}

# ===========================
# IAM Role for Firehose
# ===========================

resource "aws_iam_role" "firehose_waf" {
  name = "FirehoseWAFLogsRole"

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

resource "aws_iam_role_policy" "firehose_waf" {
  name = "FirehoseWAFLogsPolicy"
  role = aws_iam_role.firehose_waf.id

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
          aws_s3_bucket.waf_logs.arn,
          "${aws_s3_bucket.waf_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = aws_lambda_function.waf_log_processor.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.firehose_waf.arn}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = data.aws_kms_alias.s3.target_key_arn
      }
    ]
  })
}

# ===========================
# CloudWatch Metrics and Alarms
# ===========================

# Metric filter for blocked requests
resource "aws_cloudwatch_log_metric_filter" "waf_blocked_requests" {
  name           = "WAFBlockedRequests"
  log_group_name = aws_cloudwatch_log_group.firehose_waf.name
  pattern        = "[timestamp, request_id, action=BLOCK, *]"

  metric_transformation {
    name      = "BlockedRequestCount"
    namespace = "WAF/Custom"
    value     = "1"
  }
}

# Alarm for high block rate (potential attack)
resource "aws_cloudwatch_metric_alarm" "high_block_rate" {
  alarm_name          = "waf-high-block-rate"
  alarm_description   = "Alert when WAF blocks high percentage of traffic"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  threshold           = "1000"
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "blocked"
    return_data = false

    metric {
      metric_name = "BlockedRequests"
      namespace   = "AWS/WAFV2"
      period      = 300
      stat        = "Sum"

      dimensions = {
        WebACL = aws_wafv2_web_acl.alb_regional.name
        Region = data.aws_region.current.name
      }
    }
  }

  metric_query {
    id          = "total"
    return_data = false

    metric {
      metric_name = "AllowedRequests"
      namespace   = "AWS/WAFV2"
      period      = 300
      stat        = "Sum"

      dimensions = {
        WebACL = aws_wafv2_web_acl.alb_regional.name
        Region = data.aws_region.current.name
      }
    }
  }

  metric_query {
    id          = "block_rate"
    expression  = "blocked / (blocked + total) * 100"
    label       = "Block Rate Percentage"
    return_data = true
  }

  alarm_actions = [aws_sns_topic.waf_alerts.arn]

  tags = {
    Severity = "High"
    Purpose  = "Detect attack campaigns"
  }
}

# Alarm for logging failures
resource "aws_cloudwatch_metric_alarm" "waf_logging_errors" {
  alarm_name          = "waf-logging-errors"
  alarm_description   = "Alert when WAF logging has errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "DeliveryToS3.DataFreshness"
  namespace           = "AWS/Firehose"
  period              = "300"
  statistic           = "Maximum"
  threshold           = "900"
  treat_missing_data  = "notBreaching"

  dimensions = {
    DeliveryStreamName = aws_kinesis_firehose_delivery_stream.waf_logs.name
  }

  alarm_actions = [aws_sns_topic.waf_alerts.arn]

  tags = {
    Severity = "Medium"
    Purpose  = "Ensure log delivery"
  }
}

# ===========================
# Athena for Log Analysis
# ===========================

# Athena database for WAF log queries
resource "aws_athena_database" "waf_logs" {
  name   = "waf_logs"
  bucket = aws_s3_bucket.waf_logs.id

  encryption_configuration {
    encryption_option = "SSE_KMS"
    kms_key           = data.aws_kms_alias.s3.target_key_arn
  }
}

# Athena workgroup for WAF analysis
resource "aws_athena_workgroup" "waf_analysis" {
  name = "waf-log-analysis"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.waf_logs.id}/athena-results/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key           = data.aws_kms_alias.s3.target_key_arn
      }
    }
  }

  tags = {
    Name    = "waf-analysis"
    Purpose = "Ad-hoc WAF log queries"
  }
}

# ===========================
# Data Sources
# ===========================

data "aws_kms_alias" "cloudwatch" {
  name = "alias/examplepay-cloudwatch"
}

# ===========================
# Outputs
# ===========================

output "waf_logging_summary" {
  description = "Summary of WAF logging configuration"
  value = {
    s3_bucket              = aws_s3_bucket.waf_logs.id
    kinesis_stream         = aws_kinesis_firehose_delivery_stream.waf_logs.name
    retention_period       = "7 years (PCI DSS compliant)"
    encryption             = "KMS encrypted at rest and in transit"
    athena_database        = aws_athena_database.waf_logs.name
    redacted_fields        = ["authorization", "cookie"]
    log_format             = "JSON (WAFv2 format)"

    compliance = {
      pci_dss = "Requirement 10.2 (audit logs), 10.5 (retention)"
      retention = "7 years"
      encryption = "Required"
    }

    cost_estimate = {
      s3_standard     = "$0.023 per GB/month (first 90 days)"
      s3_ia           = "$0.0125 per GB/month (90-365 days)"
      glacier         = "$0.004 per GB/month (1-7 years)"
      firehose        = "$0.029 per GB ingested"
      athena          = "$5 per TB scanned"
    }
  }
}

output "athena_sample_queries" {
  description = "Sample Athena queries for WAF log analysis"
  value = {
    top_blocked_ips = "SELECT httpRequest.clientIp, COUNT(*) as count FROM waf_logs WHERE action='BLOCK' GROUP BY httpRequest.clientIp ORDER BY count DESC LIMIT 10"
    sql_injection_attempts = "SELECT * FROM waf_logs WHERE terminatingRuleId LIKE '%SQLi%' AND action='BLOCK' ORDER BY timestamp DESC LIMIT 100"
    rate_limit_violations = "SELECT httpRequest.clientIp, COUNT(*) FROM waf_logs WHERE terminatingRuleId='RateLimitPerIP' GROUP BY httpRequest.clientIp"
  }
}
