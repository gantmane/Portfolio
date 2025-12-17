# GuardDuty Threat Intelligence Integration
# Author: Evgeniy Gantman
# Purpose: Integrate custom and AWS-managed threat intelligence feeds
# PCI DSS: Requirement 11.4 (Keep intrusion-detection mechanisms up to date)

# Benefits:
# - Custom IP/domain threat lists
# - Whitelisting for known safe sources
# - Integration with AWS-managed threat intelligence
# - Automated daily updates

# ===========================
# Threat List S3 Buckets
# ===========================

# S3 bucket for custom threat intelligence lists
resource "aws_s3_bucket" "threat_intel" {
  bucket = "examplepay-guardduty-threat-intel-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name    = "guardduty-threat-intel"
    Purpose = "Custom threat intelligence feeds"
  }
}

resource "aws_s3_bucket_versioning" "threat_intel" {
  bucket = aws_s3_bucket.threat_intel.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "threat_intel" {
  bucket = aws_s3_bucket.threat_intel.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "threat_intel" {
  bucket = aws_s3_bucket.threat_intel.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ===========================
# Malicious IP List (Custom Threat Intel)
# ===========================

# Upload malicious IP list to S3
resource "aws_s3_object" "malicious_ips" {
  bucket       = aws_s3_bucket.threat_intel.id
  key          = "threat-lists/malicious-ips.txt"
  content_type = "text/plain"

  # Example malicious IPs (in production, this would be from threat feeds)
  content = <<EOF
# Known malicious IPs (ExamplePay Security Team)
# Updated: ${formatdate("YYYY-MM-DD", timestamp())}
# Source: Internal incident response, threat intelligence feeds

# Command and Control Servers
198.51.100.10
198.51.100.20
203.0.113.50

# Cryptocurrency Mining Pools
192.0.2.100
192.0.2.101

# Brute Force Attack Sources
198.51.100.100
198.51.100.101
198.51.100.102

# Data Exfiltration Destinations
203.0.113.200
203.0.113.201

# APT Group Infrastructure (Example - TEST-NET IPs)
192.0.2.50
192.0.2.51
192.0.2.52
EOF

  tags = {
    Name         = "malicious-ips-list"
    ThreatLevel  = "High"
    LastVerified = formatdate("YYYY-MM-DD", timestamp())
  }
}

# Create GuardDuty ThreatIntelSet for malicious IPs
resource "aws_guardduty_threatintelset" "malicious_ips" {
  detector_id = aws_guardduty_detector.main.id
  activate    = true
  format      = "TXT"
  location    = "https://s3.amazonaws.com/${aws_s3_bucket.threat_intel.id}/${aws_s3_object.malicious_ips.key}"
  name        = "ExamplePay-Malicious-IPs"

  tags = {
    Name    = "malicious-ips-threatintelset"
    Purpose = "Custom threat intelligence - known malicious IPs"
  }

  depends_on = [aws_s3_object.malicious_ips]
}

# ===========================
# Malicious Domains List
# ===========================

resource "aws_s3_object" "malicious_domains" {
  bucket       = aws_s3_bucket.threat_intel.id
  key          = "threat-lists/malicious-domains.txt"
  content_type = "text/plain"

  content = <<EOF
# Known malicious domains (ExamplePay Security Team)
# Updated: ${formatdate("YYYY-MM-DD", timestamp())}

# C2 Domains
evil-c2-server.example.com
malicious-command.example.net
backdoor-control.example.org

# Phishing Domains
fake-examplepay-login.example.com
phishing-portal.example.net

# Cryptocurrency Mining
cryptominer-pool.example.com
mining-server.example.net

# Data Exfiltration
exfiltration-endpoint.example.com
data-leak-server.example.net

# Known APT Domains
apt-infrastructure.example.org
malware-distribution.example.com
EOF

  tags = {
    Name         = "malicious-domains-list"
    ThreatLevel  = "High"
    LastVerified = formatdate("YYYY-MM-DD", timestamp())
  }
}

resource "aws_guardduty_threatintelset" "malicious_domains" {
  detector_id = aws_guardduty_detector.main.id
  activate    = true
  format      = "TXT"
  location    = "https://s3.amazonaws.com/${aws_s3_bucket.threat_intel.id}/${aws_s3_object.malicious_domains.key}"
  name        = "ExamplePay-Malicious-Domains"

  tags = {
    Name    = "malicious-domains-threatintelset"
    Purpose = "Custom threat intelligence - known malicious domains"
  }

  depends_on = [aws_s3_object.malicious_domains]
}

# ===========================
# Trusted IP Whitelist (IPSet)
# ===========================

# Upload trusted IP list to S3
resource "aws_s3_object" "trusted_ips" {
  bucket       = aws_s3_bucket.threat_intel.id
  key          = "whitelists/trusted-ips.txt"
  content_type = "text/plain"

  content = <<EOF
# Trusted IP addresses (ExamplePay)
# Updated: ${formatdate("YYYY-MM-DD", timestamp())}

# Corporate Office Networks
10.100.0.0/16
10.200.0.0/16

# VPN Exit Points
203.0.113.10/32
203.0.113.11/32

# Approved Security Scanner IPs (Qualys, Nessus)
198.51.100.200/32
198.51.100.201/32

# Third-Party Partner IPs
192.0.2.150/32
192.0.2.151/32

# AWS VPC CIDR Ranges
10.0.0.0/16
172.31.0.0/16
EOF

  tags = {
    Name         = "trusted-ips-whitelist"
    Purpose      = "Suppress false positives from known sources"
    LastVerified = formatdate("YYYY-MM-DD", timestamp())
  }
}

# Create GuardDuty IPSet for trusted IPs
resource "aws_guardduty_ipset" "trusted_ips" {
  detector_id = aws_guardduty_detector.main.id
  activate    = true
  format      = "TXT"
  location    = "https://s3.amazonaws.com/${aws_s3_bucket.threat_intel.id}/${aws_s3_object.trusted_ips.key}"
  name        = "ExamplePay-Trusted-IPs"

  tags = {
    Name    = "trusted-ips-ipset"
    Purpose = "Whitelist known safe IP addresses"
  }

  depends_on = [aws_s3_object.trusted_ips]
}

# ===========================
# Automated Threat List Updates
# ===========================

# Lambda function to update threat intelligence lists daily
resource "aws_lambda_function" "update_threat_intel" {
  filename      = "lambda_update_threat_intel.zip"  # Placeholder
  function_name = "GuardDuty-Update-ThreatIntel"
  role          = aws_iam_role.update_threat_intel_lambda.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 300

  environment {
    variables = {
      THREAT_INTEL_BUCKET = aws_s3_bucket.threat_intel.id
      DETECTOR_ID         = aws_guardduty_detector.main.id
    }
  }

  tags = {
    Name    = "guardduty-update-threat-intel"
    Purpose = "Automated threat intelligence feed updates"
  }
}

# IAM role for threat intel update Lambda
resource "aws_iam_role" "update_threat_intel_lambda" {
  name = "GuardDutyUpdateThreatIntelLambda"

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

resource "aws_iam_role_policy" "update_threat_intel_lambda" {
  name = "ThreatIntelUpdatePolicy"
  role = aws_iam_role.update_threat_intel_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid    = "S3ThreatIntelBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.threat_intel.arn,
          "${aws_s3_bucket.threat_intel.arn}/*"
        ]
      },
      {
        Sid    = "GuardDutyUpdate"
        Effect = "Allow"
        Action = [
          "guardduty:UpdateThreatIntelSet",
          "guardduty:UpdateIPSet"
        ]
        Resource = "*"
      }
    ]
  })
}

# EventBridge rule to trigger daily updates
resource "aws_cloudwatch_event_rule" "daily_threat_intel_update" {
  name                = "guardduty-daily-threat-intel-update"
  description         = "Update GuardDuty threat intelligence lists daily"
  schedule_expression = "cron(0 6 * * ? *)"  # Daily at 6 AM UTC

  tags = {
    Name    = "daily-threat-intel-update"
    Purpose = "Keep threat intelligence current"
  }
}

resource "aws_cloudwatch_event_target" "threat_intel_update" {
  rule      = aws_cloudwatch_event_rule.daily_threat_intel_update.name
  target_id = "UpdateThreatIntel"
  arn       = aws_lambda_function.update_threat_intel.arn
}

resource "aws_lambda_permission" "allow_eventbridge_threat_intel" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.update_threat_intel.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_threat_intel_update.arn
}

# ===========================
# Threat Intelligence Metrics
# ===========================

# CloudWatch metric filter for threat list hits
resource "aws_cloudwatch_log_metric_filter" "threat_list_hits" {
  name           = "GuardDutyThreatListHits"
  log_group_name = aws_cloudwatch_log_group.guardduty_findings.name
  pattern        = "[timestamp, request_id, level, msg=\"*ThreatIntelSet*\"]"

  metric_transformation {
    name      = "ThreatListMatchCount"
    namespace = "GuardDuty/ThreatIntel"
    value     = "1"
  }
}

# Alarm for high number of threat list matches
resource "aws_cloudwatch_metric_alarm" "high_threat_list_matches" {
  alarm_name          = "guardduty-high-threat-list-matches"
  alarm_description   = "Alert when many IPs/domains match threat lists"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ThreatListMatchCount"
  namespace           = "GuardDuty/ThreatIntel"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.guardduty_high.arn]

  tags = {
    Severity = "High"
    Purpose  = "Detect threat intelligence campaign"
  }
}

# ===========================
# Outputs
# ===========================

output "threat_intel_bucket" {
  description = "S3 bucket for threat intelligence feeds"
  value       = aws_s3_bucket.threat_intel.id
}

output "threatintelsets" {
  description = "Configured GuardDuty threat intelligence sets"
  value = {
    malicious_ips     = aws_guardduty_threatintelset.malicious_ips.id
    malicious_domains = aws_guardduty_threatintelset.malicious_domains.id
  }
}

output "ipsets" {
  description = "Configured GuardDuty IP sets (whitelists)"
  value = {
    trusted_ips = aws_guardduty_ipset.trusted_ips.id
  }
}

output "threat_intel_update_function" {
  description = "Lambda function for daily threat intel updates"
  value       = aws_lambda_function.update_threat_intel.function_name
}

output "threat_intel_summary" {
  description = "Threat intelligence configuration summary"
  value = {
    malicious_ips_count     = length(split("\n", aws_s3_object.malicious_ips.content)) - 5  # Subtract header lines
    malicious_domains_count = length(split("\n", aws_s3_object.malicious_domains.content)) - 3
    trusted_ips_count       = length(split("\n", aws_s3_object.trusted_ips.content)) - 3
    auto_update             = "Daily at 6 AM UTC"
    bucket                  = aws_s3_bucket.threat_intel.id
  }
}
