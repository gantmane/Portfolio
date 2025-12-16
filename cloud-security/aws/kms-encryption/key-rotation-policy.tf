# KMS Key Rotation and Monitoring Configuration
# Author: Evgeniy Gantman
# Purpose: Configure 90-day automatic rotation and monitoring
# PCI DSS: Requirement 3.6 (Key Management)

# Note: Automatic rotation is enabled in kms-keys.tf via enable_key_rotation = true
# This file adds monitoring and alerting for rotation events

# ===========================
# CloudWatch Metric Filters for Key Rotation
# ===========================

resource "aws_cloudwatch_log_metric_filter" "kms_key_rotation" {
  name           = "KMSKeyRotation"
  log_group_name = "/aws/cloudtrail/organization-trail"
  pattern        = "{ $.eventName = \"RotateKey\" || $.eventName = \"EnableKeyRotation\" || $.eventName = \"DisableKeyRotation\" }"

  metric_transformation {
    name      = "KMSKeyRotationEvents"
    namespace = "Security/KMS"
    value     = "1"
  }
}

# ===========================
# Alarms for Key Rotation
# ===========================

# Alert when automatic rotation is disabled
resource "aws_cloudwatch_log_metric_filter" "kms_rotation_disabled" {
  name           = "KMSRotationDisabled"
  log_group_name = "/aws/cloudtrail/organization-trail"
  pattern        = "{ $.eventName = \"DisableKeyRotation\" && $.errorCode NOT EXISTS }"

  metric_transformation {
    name      = "KMSRotationDisabledCount"
    namespace = "Security/KMS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "kms_rotation_disabled_alert" {
  alarm_name          = "kms-rotation-disabled"
  alarm_description   = "Alert when KMS key rotation is disabled"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "KMSRotationDisabledCount"
  namespace           = "Security/KMS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  treat_missing_data  = "notBreaching"

  alarm_actions = [
    "arn:aws:sns:us-east-1:222233334444:security-alerts"
  ]

  tags = {
    Severity = "Critical"
    PCIScope = "yes"
    Purpose  = "PCI DSS Req 3.6 - Key Rotation Monitoring"
  }
}

# ===========================
# Key Deletion Protection
# ===========================

resource "aws_cloudwatch_log_metric_filter" "kms_key_deletion_scheduled" {
  name           = "KMSKeyDeletionScheduled"
  log_group_name = "/aws/cloudtrail/organization-trail"
  pattern        = "{ $.eventName = \"ScheduleKeyDeletion\" && $.errorCode NOT EXISTS }"

  metric_transformation {
    name      = "KMSKeyDeletionCount"
    namespace = "Security/KMS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "kms_key_deletion_alert" {
  alarm_name          = "kms-key-deletion-scheduled"
  alarm_description   = "Alert when KMS key deletion is scheduled"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "KMSKeyDeletionCount"
  namespace           = "Security/KMS"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  treat_missing_data  = "notBreaching"

  alarm_actions = [
    "arn:aws:sns:us-east-1:222233334444:security-alerts-critical"
  ]

  tags = {
    Severity = "Critical"
    PCIScope = "yes"
    Purpose  = "Prevent accidental key deletion"
  }
}

# ===========================
# Unauthorized Key Access Monitoring
# ===========================

resource "aws_cloudwatch_log_metric_filter" "kms_unauthorized_access" {
  name           = "KMSUnauthorizedAccess"
  log_group_name = "/aws/cloudtrail/organization-trail"
  pattern        = "{ ($.eventName = Decrypt || $.eventName = Encrypt || $.eventName = GenerateDataKey) && $.errorCode = \"AccessDeniedException\" }"

  metric_transformation {
    name      = "KMSUnauthorizedAccessAttempts"
    namespace = "Security/KMS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "kms_unauthorized_access_alert" {
  alarm_name          = "kms-unauthorized-access"
  alarm_description   = "Alert on unauthorized KMS key access attempts"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "KMSUnauthorizedAccessAttempts"
  namespace           = "Security/KMS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"  # Alert after 5 failed attempts in 5 minutes
  treat_missing_data  = "notBreaching"

  alarm_actions = [
    "arn:aws:sns:us-east-1:222233334444:security-alerts"
  ]

  tags = {
    Severity = "High"
    PCIScope = "yes"
    Purpose  = "Detect unauthorized key access attempts"
  }
}

# ===========================
# Key Usage Anomaly Detection
# ===========================

# Monitor for unusual spike in KMS API calls
resource "aws_cloudwatch_metric_alarm" "kms_high_usage" {
  alarm_name          = "kms-high-api-usage"
  alarm_description   = "Alert on unusually high KMS API usage (possible data exfiltration)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  datapoints_to_alarm = "2"
  threshold           = "10000"  # 10K requests
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "total_requests"
    return_data = true

    metric {
      metric_name = "UserErrorCount"
      namespace   = "AWS/KMS"
      period      = "300"
      stat        = "Sum"
      dimensions = {}
    }
  }

  alarm_actions = [
    "arn:aws:sns:us-east-1:222233334444:security-alerts"
  ]

  tags = {
    Severity = "Medium"
    Purpose  = "Detect anomalous KMS usage patterns"
  }
}

# ===========================
# SNS Topic for KMS Alerts (Example)
# ===========================

resource "aws_sns_topic" "kms_alerts" {
  name              = "kms-security-alerts"
  display_name      = "KMS Security Alerts"
  kms_master_key_id = aws_kms_key.messaging_prod.id

  tags = {
    Purpose   = "KMS Security Monitoring"
    ManagedBy = "terraform"
  }
}

resource "aws_sns_topic_subscription" "kms_alerts_email" {
  topic_arn = aws_sns_topic.kms_alerts.arn
  protocol  = "email"
  endpoint  = "security-team@example.com"
}

resource "aws_sns_topic_subscription" "kms_alerts_siem" {
  topic_arn = aws_sns_topic.kms_alerts.arn
  protocol  = "https"
  endpoint  = "https://wazuh.example.com/api/sns-webhook"
}

# ===========================
# Outputs
# ===========================

output "rotation_monitoring_enabled" {
  description = "Status of key rotation monitoring"
  value       = "Enabled - CloudWatch alarms for rotation events configured"
}

output "kms_alerts_topic_arn" {
  description = "SNS topic ARN for KMS security alerts"
  value       = aws_sns_topic.kms_alerts.arn
}
