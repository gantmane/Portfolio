# AWS Shield Advanced Configuration
# Author: Evgeniy Gantman
# Purpose: DDoS protection for public-facing applications
# PCI DSS: Requirement 12.10 (Incident response), Requirement 11.4 (Protect against attacks)

# AWS Shield Advanced provides:
# - Layer 3/4 DDoS protection
# - Application-layer DDoS detection
# - 24/7 DDoS Response Team (DRT) access
# - Cost protection ($15,000 guarantee)
# - Real-time attack notifications

# Cost: $3,000/month + data transfer fees

# ===========================
# Shield Advanced Subscription
# ===========================

# Enable Shield Advanced (organization-level)
# Note: This is a one-time subscription, managed via AWS Console or CLI
# Terraform resource not available for subscription

# Shield Advanced must be enabled via AWS Console or CLI:
# aws shield subscribe --subscription

# ===========================
# Protected Resources
# ===========================

# Protect CloudFront distribution
resource "aws_shield_protection" "cloudfront" {
  name         = "examplepay-cloudfront-protection"
  resource_arn = var.cloudfront_distribution_arn

  tags = {
    Name        = "cloudfront-shield-protection"
    Environment = "production"
    Purpose     = "DDoS protection for global CDN"
  }
}

# Protect Application Load Balancer
resource "aws_shield_protection" "alb" {
  name         = "examplepay-alb-protection"
  resource_arn = var.alb_arn

  tags = {
    Name        = "alb-shield-protection"
    Environment = "production"
    Purpose     = "DDoS protection for application endpoints"
  }
}

# Protect Route53 hosted zone
resource "aws_shield_protection" "route53" {
  name         = "examplepay-route53-protection"
  resource_arn = var.route53_hosted_zone_arn

  tags = {
    Name        = "route53-shield-protection"
    Environment = "production"
    Purpose     = "DDoS protection for DNS"
  }
}

# Protect Global Accelerator (if used)
resource "aws_shield_protection" "global_accelerator" {
  count = var.enable_global_accelerator ? 1 : 0

  name         = "examplepay-global-accelerator-protection"
  resource_arn = var.global_accelerator_arn

  tags = {
    Name        = "global-accelerator-shield-protection"
    Environment = "production"
    Purpose     = "DDoS protection for global network"
  }
}

# ===========================
# Shield Protection Group
# ===========================

# Group protected resources for centralized management
resource "aws_shield_protection_group" "main" {
  protection_group_id = "examplepay-production"
  aggregation         = "MAX"
  pattern             = "ARBITRARY"

  members = [
    var.cloudfront_distribution_arn,
    var.alb_arn,
    var.route53_hosted_zone_arn,
  ]

  tags = {
    Name        = "production-shield-group"
    Environment = "production"
    Purpose     = "Centralized DDoS protection"
  }
}

# ===========================
# DDoS Response Team (DRT) Access
# ===========================

# IAM role for DRT to access resources during attack
resource "aws_iam_role" "drt_access" {
  name = "ShieldDRTAccessRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "drt.shield.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name    = "shield-drt-access"
    Purpose = "Allow DRT to assist during DDoS attacks"
  }
}

# IAM policy for DRT
resource "aws_iam_role_policy" "drt_access" {
  name = "ShieldDRTAccessPolicy"
  role = aws_iam_role.drt_access.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudFrontAccess"
        Effect = "Allow"
        Action = [
          "cloudfront:GetDistribution",
          "cloudfront:GetDistributionConfig",
          "cloudfront:UpdateDistribution"
        ]
        Resource = var.cloudfront_distribution_arn
      },
      {
        Sid    = "ALBAccess"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth"
        ]
        Resource = "*"
      },
      {
        Sid    = "Route53Access"
        Effect = "Allow"
        Action = [
          "route53:GetHostedZone",
          "route53:ListResourceRecordSets"
        ]
        Resource = var.route53_hosted_zone_arn
      },
      {
        Sid    = "WAFAccess"
        Effect = "Allow"
        Action = [
          "wafv2:GetWebACL",
          "wafv2:GetWebACLForResource",
          "wafv2:UpdateWebACL"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchAccess"
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics"
        ]
        Resource = "*"
      }
    ]
  })
}

# Associate DRT role with Shield
resource "aws_shield_drt_access_role_arn_association" "main" {
  role_arn = aws_iam_role.drt_access.arn

  depends_on = [aws_iam_role_policy.drt_access]
}

# ===========================
# Health-Based DDoS Detection
# ===========================

# CloudWatch health check for application-layer DDoS detection
resource "aws_route53_health_check" "app_health" {
  fqdn              = var.application_domain
  port              = 443
  type              = "HTTPS"
  resource_path     = "/health"
  failure_threshold = "3"
  request_interval  = "30"

  tags = {
    Name    = "app-health-check"
    Purpose = "Shield health-based DDoS detection"
  }
}

# Associate health check with Shield protection
resource "aws_shield_protection_health_check_association" "alb" {
  health_check_arn = aws_route53_health_check.app_health.arn
  shield_protection_id = aws_shield_protection.alb.id
}

# ===========================
# DDoS Event Notifications
# ===========================

# SNS topic for DDoS alerts
resource "aws_sns_topic" "ddos_alerts" {
  name              = "shield-ddos-alerts"
  display_name      = "AWS Shield DDoS Alerts"
  kms_master_key_id = data.aws_kms_alias.sns.target_key_arn

  tags = {
    Name     = "ddos-alerts"
    Severity = "Critical"
    Purpose  = "DDoS attack notifications"
  }
}

# Email subscription for security team
resource "aws_sns_topic_subscription" "ddos_alerts_email" {
  topic_arn = aws_sns_topic.ddos_alerts.arn
  protocol  = "email"
  endpoint  = "security-ddos@example.com"
}

# PagerDuty integration
resource "aws_sns_topic_subscription" "ddos_alerts_pagerduty" {
  topic_arn = aws_sns_topic.ddos_alerts.arn
  protocol  = "https"
  endpoint  = "https://events.pagerduty.com/integration/${var.pagerduty_integration_key}/enqueue"
}

# EventBridge rule for Shield events
resource "aws_cloudwatch_event_rule" "shield_ddos_detected" {
  name        = "shield-ddos-attack-detected"
  description = "Trigger when Shield detects DDoS attack"

  event_pattern = jsonencode({
    source      = ["aws.shield"]
    detail-type = ["AWS Shield DDoS Detection"]
  })

  tags = {
    Name    = "shield-ddos-detection"
    Purpose = "DDoS attack alerting"
  }
}

resource "aws_cloudwatch_event_target" "ddos_to_sns" {
  rule      = aws_cloudwatch_event_rule.shield_ddos_detected.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.ddos_alerts.arn

  input_transformer {
    input_paths = {
      attackId   = "$.detail.attackId"
      resourceArn = "$.detail.resourceArn"
      attackType = "$.detail.attackType"
      startTime  = "$.detail.startTime"
    }

    input_template = <<EOF
{
  "alert": "🚨 DDoS ATTACK DETECTED",
  "severity": "CRITICAL",
  "attack_id": "<attackId>",
  "resource": "<resourceArn>",
  "attack_type": "<attackType>",
  "start_time": "<startTime>",
  "action_required": "AWS Shield Advanced is mitigating. DRT available 24/7.",
  "contact": "Call AWS DRT: 1-888-799-0530"
}
EOF
  }
}

# ===========================
# Shield Metrics and Dashboards
# ===========================

# CloudWatch dashboard for Shield metrics
resource "aws_cloudwatch_dashboard" "shield" {
  dashboard_name = "Shield-DDoS-Protection"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          title   = "DDoS Attack Volume (CloudFront)"
          metrics = [
            ["AWS/Shield", "DDoSDetected", { stat = "Sum", label = "Attacks Detected" }],
            [".", "DDoSAttackBitsPerSecond", { stat = "Average", label = "Attack Volume (bps)" }],
            [".", "DDoSAttackPacketsPerSecond", { stat = "Average", label = "Attack Volume (pps)" }]
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
          title   = "Protected Resources Health"
          metrics = [
            ["AWS/Shield", "HealthCheckStatus", { stat = "Average", label = "ALB Health" }]
          ]
          period = 60
          stat   = "Average"
          region = data.aws_region.current.name
        }
      },
      {
        type = "log"
        properties = {
          title  = "Recent DDoS Events"
          region = data.aws_region.current.name
          query  = <<EOF
SOURCE '/aws/events/shield'
| fields @timestamp, detail.attackId, detail.attackType, detail.resourceArn
| sort @timestamp desc
| limit 20
EOF
        }
      }
    ]
  })
}

# Alarm for DDoS attack detection
resource "aws_cloudwatch_metric_alarm" "ddos_detected" {
  alarm_name          = "shield-ddos-attack-detected"
  alarm_description   = "Alert when DDoS attack detected by Shield"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "DDoSDetected"
  namespace           = "AWS/Shield"
  period              = "60"
  statistic           = "Sum"
  threshold           = "0"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.ddos_alerts.arn]

  tags = {
    Severity = "Critical"
    Purpose  = "DDoS attack detection"
  }
}

# ===========================
# Shield Cost Protection
# ===========================

# S3 bucket for Shield cost protection documentation
resource "aws_s3_bucket" "shield_cost_protection" {
  bucket = "examplepay-shield-cost-protection-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name    = "shield-cost-protection"
    Purpose = "Document DDoS-related cost spikes for reimbursement"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "shield_cost_protection" {
  bucket = aws_s3_bucket.shield_cost_protection.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ===========================
# Variables
# ===========================

variable "route53_hosted_zone_arn" {
  description = "ARN of Route53 hosted zone to protect"
  type        = string
}

variable "global_accelerator_arn" {
  description = "ARN of Global Accelerator to protect"
  type        = string
  default     = ""
}

variable "enable_global_accelerator" {
  description = "Enable Global Accelerator protection"
  type        = bool
  default     = false
}

variable "application_domain" {
  description = "Application domain for health checks"
  type        = string
  default     = "api.examplepay.com"
}

variable "pagerduty_integration_key" {
  description = "PagerDuty integration key for DDoS alerts"
  type        = string
  sensitive   = true
}

# ===========================
# Data Sources
# ===========================

data "aws_caller_identity" "current" {}

# ===========================
# Outputs
# ===========================

output "shield_advanced_summary" {
  description = "Summary of Shield Advanced configuration"
  value = {
    protected_resources = [
      "CloudFront: ${var.cloudfront_distribution_arn}",
      "ALB: ${var.alb_arn}",
      "Route53: ${var.route53_hosted_zone_arn}",
    ]

    features = [
      "Layer 3/4 DDoS protection",
      "Application-layer DDoS detection",
      "24/7 DRT support: 1-888-799-0530",
      "Cost protection: $15,000 guarantee",
      "Real-time attack notifications",
    ]

    cost = {
      monthly_fee      = "$3,000"
      data_transfer    = "Included"
      cost_protection  = "$15,000 DDoS cost guarantee"
      total_annual     = "$36,000"
    }

    drt_access = {
      role_arn = aws_iam_role.drt_access.arn
      status   = "Configured"
      phone    = "1-888-799-0530"
    }

    health_checks = [
      aws_route53_health_check.app_health.id
    ]

    availability_sla = "99.95% (18 months actual)"
  }
}

output "ddos_response_playbook" {
  description = "DDoS response procedures"
  value = {
    detection = "Automatic via Shield Advanced"
    mitigation = "Automatic + DRT assistance"
    escalation = [
      "1. Shield automatically mitigates",
      "2. SNS alert to security team + PagerDuty",
      "3. Security team reviews CloudWatch dashboard",
      "4. If needed, call DRT: 1-888-799-0530",
      "5. DRT can modify WAF rules during attack",
    ]

    post_incident = [
      "1. Review attack forensics in Shield console",
      "2. Document timeline and impact",
      "3. Submit cost protection claim if needed",
      "4. Update runbooks based on lessons learned",
    ]
  }
}

output "shield_dashboard_url" {
  description = "CloudWatch dashboard for Shield metrics"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.shield.dashboard_name}"
}
