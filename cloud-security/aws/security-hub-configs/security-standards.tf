# Security Hub Standards Configuration
# Author: Evgeniy Gantman
# Purpose: Enable CIS, PCI DSS, and AWS Foundational Security Best Practices
# PCI DSS: Multiple requirements covered by automated checks

# ===========================
# CIS AWS Foundations Benchmark v1.4.0
# ===========================

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/cis-aws-foundations-benchmark/v/1.4.0"

  depends_on = [aws_securityhub_account.main]
}

# Disable specific CIS controls (with justification)
# Note: Only disable controls that are not applicable or have compensating controls

# Disable CIS 1.12 - Credentials unused for 45 days (we use 90 days per company policy)
resource "aws_securityhub_standards_control" "cis_1_12" {
  standards_control_arn = "arn:aws:securityhub:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:control/cis-aws-foundations-benchmark/v/1.4.0/1.12"
  control_status        = "DISABLED"
  disabled_reason       = "Company policy requires 90 days instead of 45 days. Compensating control: IAM.3 check enforces 90-day rotation."

  depends_on = [aws_securityhub_standards_subscription.cis]
}

# Disable CIS 4.1-4.15 - CloudWatch alarms (we use custom alarms + SIEM instead)
resource "aws_securityhub_standards_control" "cis_4_1" {
  standards_control_arn = "arn:aws:securityhub:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:control/cis-aws-foundations-benchmark/v/1.4.0/4.1"
  control_status        = "DISABLED"
  disabled_reason       = "Compensating control: Wazuh SIEM monitors unauthorized API calls with advanced correlation."

  depends_on = [aws_securityhub_standards_subscription.cis]
}

# ===========================
# PCI DSS v3.2.1
# ===========================

resource "aws_securityhub_standards_subscription" "pci_dss" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/3.2.1"

  depends_on = [aws_securityhub_account.main]
}

# All PCI DSS controls enabled by default (no exceptions for compliance)
# PCI DSS controls map to requirements:

# PCI.AutoScaling.1 - Requirement 2 (Secure configurations)
# PCI.CloudTrail.1-5 - Requirement 10 (Logging and monitoring)
# PCI.CodeBuild.1-2 - Requirement 6 (Secure development)
# PCI.Config.1 - Requirement 2 (Configuration management)
# PCI.CW.1 - Requirement 10 (Log monitoring)
# PCI.DMS.1 - Requirement 8 (Access control)
# PCI.EC2.1-6 - Requirement 1, 2 (Network security, secure config)
# PCI.ELB.1 - Requirement 4 (Encryption in transit)
# PCI.ES.1-2 - Requirement 3 (Encryption at rest)
# PCI.GuardDuty.1 - Requirement 11 (Security monitoring)
# PCI.IAM.1-8 - Requirement 7, 8 (Access control, authentication)
# PCI.KMS.1 - Requirement 3 (Key rotation)
# PCI.Lambda.1-2 - Requirement 2, 10 (Secure config, logging)
# PCI.RDS.1-2 - Requirement 3, 8 (Encryption, public access)
# PCI.Redshift.1 - Requirement 8 (Public access)
# PCI.S3.1-6 - Requirement 3, 8 (Encryption, access control)
# PCI.SageMaker.1 - Requirement 8 (Network isolation)
# PCI.SSM.1-4 - Requirement 2, 6 (Patch management)

# ===========================
# AWS Foundational Security Best Practices (FSBP)
# ===========================

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]
}

# Disable non-applicable FSBP controls for specific use cases

# Disable APIGateway.1 (we don't use API Gateway in all accounts)
resource "aws_securityhub_standards_control" "fsbp_apigateway_1" {
  standards_control_arn = "arn:aws:securityhub:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:control/aws-foundational-security-best-practices/v/1.0.0/APIGateway.1"
  control_status        = "DISABLED"
  disabled_reason       = "API Gateway not used in this account. N/A."

  depends_on = [aws_securityhub_standards_subscription.fsbp]
}

# Disable CloudFront checks for accounts that don't use CloudFront
resource "aws_securityhub_standards_control" "fsbp_cloudfront_1" {
  standards_control_arn = "arn:aws:securityhub:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:control/aws-foundational-security-best-practices/v/1.0.0/CloudFront.1"
  control_status        = "DISABLED"
  disabled_reason       = "CloudFront not used in this account. N/A."

  depends_on = [aws_securityhub_standards_subscription.fsbp]
}

# ===========================
# Standard-Specific CloudWatch Alarms
# ===========================

# Alert on critical PCI DSS failures
resource "aws_cloudwatch_metric_alarm" "pci_dss_critical_failures" {
  alarm_name          = "security-hub-pci-dss-critical-failures"
  alarm_description   = "Alert on critical PCI DSS compliance failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "PCIDSSCriticalFindings"
  namespace           = "SecurityHub/Compliance"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.critical_findings.arn]

  tags = {
    Standard = "PCI DSS"
    Severity = "Critical"
  }
}

# Alert on CIS benchmark score drop
resource "aws_cloudwatch_metric_alarm" "cis_score_drop" {
  alarm_name          = "security-hub-cis-score-drop"
  alarm_description   = "Alert when CIS compliance score drops below threshold"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  datapoints_to_alarm = "2"
  metric_name         = "CISComplianceScore"
  namespace           = "SecurityHub/Compliance"
  period              = "3600"
  statistic           = "Average"
  threshold           = "85"  # Alert if score drops below 85%
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.high_findings.arn]

  tags = {
    Standard = "CIS"
    Severity = "High"
  }
}

# ===========================
# EventBridge Rule for Standard-Specific Findings
# ===========================

# Route PCI DSS failures to compliance team
resource "aws_cloudwatch_event_rule" "pci_dss_failures" {
  name        = "security-hub-pci-dss-failures"
  description = "Route PCI DSS compliance failures to compliance team"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Compliance = {
          Status = ["FAILED"]
        }
        ProductFields = {
          StandardsArn = [{
            prefix = "arn:aws:securityhub:::standards/pci-dss"
          }]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "pci_dss_failures_sns" {
  rule      = aws_cloudwatch_event_rule.pci_dss_failures.name
  target_id = "SendToComplianceSNS"
  arn       = aws_sns_topic.critical_findings.arn
}

# ===========================
# Suppression Rules (False Positives)
# ===========================

# Suppress known false positives with documented justification

resource "aws_securityhub_insight" "suppressed_findings" {
  filters {
    workflow_status {
      comparison = "EQUALS"
      value      = "SUPPRESSED"
    }
  }

  group_by_attribute = "ResourceId"

  name = "Suppressed Findings Requiring Review"
}

# ===========================
# Compliance Dashboards
# ===========================

resource "aws_cloudwatch_dashboard" "security_hub_compliance" {
  dashboard_name = "SecurityHub-Compliance"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["SecurityHub/Compliance", "CISComplianceScore"],
            [".", "PCIDSSComplianceScore"],
            [".", "FSBPComplianceScore"]
          ]
          period = 3600
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "Compliance Scores by Standard"
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
          metrics = [
            ["SecurityHub/Findings", "CriticalFindings", { stat = "Sum" }],
            [".", "HighFindings", { stat = "Sum" }],
            [".", "MediumFindings", { stat = "Sum" }]
          ]
          period = 3600
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "Active Findings by Severity"
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["SecurityHub/Standards", "CISFailedChecks"],
            [".", "PCIDSSFailedChecks"],
            [".", "FSBPFailedChecks"]
          ]
          period = 3600
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "Failed Checks by Standard"
        }
      }
    ]
  })
}

# ===========================
# Outputs
# ===========================

output "enabled_standards" {
  description = "Enabled Security Hub standards"
  value = {
    cis_aws_foundations = {
      arn     = aws_securityhub_standards_subscription.cis.standards_arn
      version = "1.4.0"
      checks  = 43
    }
    pci_dss = {
      arn     = aws_securityhub_standards_subscription.pci_dss.standards_arn
      version = "3.2.1"
      checks  = 38
    }
    aws_fsbp = {
      arn     = aws_securityhub_standards_subscription.fsbp.standards_arn
      version = "1.0.0"
      checks  = "200+"
    }
  }
}

output "disabled_controls" {
  description = "Disabled controls with justification"
  value = {
    cis = {
      "1.12" = "Company policy uses 90-day rotation instead of 45 days"
      "4.1"  = "Compensating control: Wazuh SIEM"
    }
    fsbp = {
      "APIGateway.1" = "API Gateway not used"
      "CloudFront.1" = "CloudFront not used"
    }
  }
}

output "compliance_dashboard" {
  description = "CloudWatch dashboard for compliance metrics"
  value       = aws_cloudwatch_dashboard.security_hub_compliance.dashboard_arn
}
