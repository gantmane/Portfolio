# VPC Flow Logs Configuration
# Author: Evgeniy Gantman
# Purpose: Capture all network traffic for forensic analysis and compliance
# PCI DSS: Requirement 10.2.2 (Audit trails), Requirement 10.7 (Retain audit logs)

# ===========================
# S3 Bucket for Flow Logs (Long-term storage)
# ===========================

resource "aws_s3_bucket" "flow_logs" {
  bucket = "examplepay-prod-vpc-flow-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "examplepay-prod-vpc-flow-logs"
    Environment = "production"
    Purpose     = "VPC Flow Logs storage"
    Compliance  = "pci-dss-4.0"
    Retention   = "10-years"
  }
}

# Enable versioning
resource "aws_s3_bucket_versioning" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:${data.aws_caller_identity.current.account_id}:alias/s3-prod"
    }
    bucket_key_enabled = true
  }
}

# Lifecycle policy for 10-year retention
resource "aws_s3_bucket_lifecycle_configuration" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  rule {
    id     = "flow-logs-lifecycle"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "INTELLIGENT_TIERING"
    }

    transition {
      days          = 365
      storage_class = "GLACIER_IR"
    }

    transition {
      days          = 730  # 2 years
      storage_class = "GLACIER"
    }

    transition {
      days          = 1095  # 3 years
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 3650  # 10 years (PCI DSS requirement)
    }
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy for VPC Flow Logs
resource "aws_s3_bucket_policy" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

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
        Resource = "${aws_s3_bucket.flow_logs.arn}/*"
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
        Resource = aws_s3_bucket.flow_logs.arn
      },
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.flow_logs.arn}/*"
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
# CloudWatch Log Group for Flow Logs (Real-time analysis)
# ===========================

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flow-logs/production"
  retention_in_days = 365  # 1 year in CloudWatch, then archived to S3

  kms_key_id = "arn:aws:kms:us-east-1:${data.aws_caller_identity.current.account_id}:alias/cloudwatch-logs"

  tags = {
    Name        = "examplepay-prod-vpc-flow-logs"
    Environment = "production"
    Purpose     = "VPC Flow Logs real-time analysis"
  }
}

# ===========================
# IAM Role for Flow Logs to CloudWatch
# ===========================

resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs-to-cloudwatch"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "vpc-flow-logs-role"
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# ===========================
# VPC Flow Logs (Dual destination: S3 + CloudWatch)
# ===========================

# Flow logs to S3 (all accepted and rejected traffic)
resource "aws_flow_log" "production_to_s3" {
  vpc_id               = aws_vpc.production.id
  traffic_type         = "ALL"  # Capture both accepted and rejected
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.flow_logs.arn

  # Enhanced log format with additional fields
  log_format = "$${account-id} $${action} $${bytes} $${dstaddr} $${dstport} $${end} $${flow-direction} $${instance-id} $${interface-id} $${log-status} $${packets} $${pkt-dstaddr} $${pkt-srcaddr} $${protocol} $${srcaddr} $${srcport} $${start} $${subnet-id} $${tcp-flags} $${type} $${vpc-id}"

  tags = {
    Name        = "examplepay-prod-flow-logs-s3"
    Environment = "production"
    Destination = "S3"
  }
}

# Flow logs to CloudWatch (for real-time monitoring and alerting)
resource "aws_flow_log" "production_to_cloudwatch" {
  vpc_id               = aws_vpc.production.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn

  log_format = "$${account-id} $${action} $${bytes} $${dstaddr} $${dstport} $${end} $${flow-direction} $${instance-id} $${interface-id} $${log-status} $${packets} $${pkt-dstaddr} $${pkt-srcaddr} $${protocol} $${srcaddr} $${srcport} $${start} $${subnet-id} $${tcp-flags} $${type} $${vpc-id}"

  tags = {
    Name        = "examplepay-prod-flow-logs-cloudwatch"
    Environment = "production"
    Destination = "CloudWatch"
  }
}

# ===========================
# CloudWatch Metric Filters for Anomaly Detection
# ===========================

# Rejected connections (potential attacks)
resource "aws_cloudwatch_log_metric_filter" "rejected_connections" {
  name           = "VPCFlowLogsRejectedConnections"
  log_group_name = aws_cloudwatch_log_group.flow_logs.name
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action=REJECT, log_status]"

  metric_transformation {
    name      = "RejectedConnectionsCount"
    namespace = "VPCFlowLogs/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "excessive_rejected_connections" {
  alarm_name          = "vpc-flow-excessive-rejected-connections"
  alarm_description   = "Alert on excessive rejected connections (potential attack)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "RejectedConnectionsCount"
  namespace           = "VPCFlowLogs/Security"
  period              = "300"  # 5 minutes
  statistic           = "Sum"
  threshold           = "100"
  treat_missing_data  = "notBreaching"

  alarm_actions = [
    "arn:aws:sns:us-east-1:${data.aws_caller_identity.current.account_id}:security-alerts"
  ]

  tags = {
    Severity = "Medium"
    Purpose  = "Network security monitoring"
  }
}

# SSH from non-corporate IPs
resource "aws_cloudwatch_log_metric_filter" "ssh_from_internet" {
  name           = "VPCFlowLogsSSHFromInternet"
  log_group_name = aws_cloudwatch_log_group.flow_logs.name

  # Match port 22 traffic (SSH)
  pattern = "[version, account_id, interface_id, srcaddr != 192.0.2.*, dstaddr, srcport, dstport=22, protocol=6, packets, bytes, start, end, action=ACCEPT, log_status]"

  metric_transformation {
    name      = "SSHFromInternetCount"
    namespace = "VPCFlowLogs/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ssh_from_internet" {
  alarm_name          = "vpc-flow-ssh-from-internet"
  alarm_description   = "Alert on SSH from non-corporate IPs"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "SSHFromInternetCount"
  namespace           = "VPCFlowLogs/Security"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  treat_missing_data  = "notBreaching"

  alarm_actions = [
    "arn:aws:sns:us-east-1:${data.aws_caller_identity.current.account_id}:security-alerts"
  ]

  tags = {
    Severity = "High"
    Purpose  = "Unauthorized access detection"
  }
}

# High data transfer (potential data exfiltration)
resource "aws_cloudwatch_log_metric_filter" "high_data_transfer" {
  name           = "VPCFlowLogsHighDataTransfer"
  log_group_name = aws_cloudwatch_log_group.flow_logs.name
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes > 100000000, start, end, action, log_status]"

  metric_transformation {
    name      = "HighDataTransferBytes"
    namespace = "VPCFlowLogs/Security"
    value     = "$bytes"
  }
}

resource "aws_cloudwatch_metric_alarm" "high_data_transfer" {
  alarm_name          = "vpc-flow-high-data-transfer"
  alarm_description   = "Alert on unusually high data transfer (potential exfiltration)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "HighDataTransferBytes"
  namespace           = "VPCFlowLogs/Security"
  period              = "900"  # 15 minutes
  statistic           = "Sum"
  threshold           = "10737418240"  # 10 GB
  treat_missing_data  = "notBreaching"

  alarm_actions = [
    "arn:aws:sns:us-east-1:${data.aws_caller_identity.current.account_id}:security-alerts-critical"
  ]

  tags = {
    Severity = "Critical"
    Purpose  = "Data exfiltration detection"
  }
}

# ===========================
# Kinesis Firehose for SIEM Integration (Optional)
# ===========================

# Stream flow logs to Wazuh SIEM via Kinesis Firehose
resource "aws_kinesis_firehose_delivery_stream" "flow_logs_to_siem" {
  name        = "vpc-flow-logs-to-siem"
  destination = "http_endpoint"

  http_endpoint_configuration {
    url                = "https://wazuh.example.com/api/flow-logs"
    name               = "WazuhSIEM"
    access_key         = data.aws_secretsmanager_secret_version.wazuh_api_key.secret_string
    buffering_size     = 5  # MB
    buffering_interval = 300  # 5 minutes
    role_arn           = aws_iam_role.firehose_flow_logs.arn

    s3_configuration {
      role_arn           = aws_iam_role.firehose_flow_logs.arn
      bucket_arn         = aws_s3_bucket.flow_logs.arn
      prefix             = "failed-deliveries/"
      error_output_prefix = "errors/"
      compression_format = "GZIP"
    }

    request_configuration {
      content_encoding = "GZIP"
    }
  }

  tags = {
    Name        = "vpc-flow-logs-to-siem"
    Environment = "production"
  }
}

# IAM role for Kinesis Firehose
resource "aws_iam_role" "firehose_flow_logs" {
  name = "firehose-vpc-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "firehose_flow_logs" {
  name = "firehose-vpc-flow-logs-policy"
  role = aws_iam_role.firehose_flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.flow_logs.arn,
          "${aws_s3_bucket.flow_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# ===========================
# Data Sources
# ===========================

data "aws_caller_identity" "current" {}

data "aws_secretsmanager_secret_version" "wazuh_api_key" {
  secret_id = "wazuh/api-key"
}

# ===========================
# Outputs
# ===========================

output "flow_logs_s3_bucket" {
  description = "S3 bucket for VPC Flow Logs"
  value       = aws_s3_bucket.flow_logs.id
}

output "flow_logs_cloudwatch_log_group" {
  description = "CloudWatch Log Group for VPC Flow Logs"
  value       = aws_cloudwatch_log_group.flow_logs.name
}

output "flow_logs_enabled" {
  description = "VPC Flow Logs status"
  value = {
    s3_destination = aws_flow_log.production_to_s3.id
    cloudwatch_destination = aws_flow_log.production_to_cloudwatch.id
    retention = "10 years"
    coverage = "100% of VPC traffic"
  }
}
