# AWS WAF Managed Rules Configuration
# Author: Evgeniy Gantman
# Purpose: AWS Managed Rule Groups for OWASP Top 10 protection
# PCI DSS: Requirement 6.4.2 (Automated protection mechanisms)

# AWS Managed Rules provide protection against common web exploits
# Rules are automatically updated by AWS as new threats emerge

# ===========================
# Core Rule Set (CRS)
# ===========================

# OWASP Top 10 protection - most comprehensive ruleset
resource "aws_wafv2_rule_group" "crs_overrides" {
  name     = "examplepay-crs-overrides"
  scope    = "REGIONAL"
  capacity = 100

  # Custom overrides for CRS rules
  # Use this to tune sensitivity or exclude specific rules

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "CRSOverrides"
    sampled_requests_enabled   = true
  }

  tags = {
    Name    = "crs-overrides"
    Purpose = "Custom CRS rule tuning"
  }
}

# ===========================
# SQL Injection Protection
# ===========================

# Dedicated SQL injection protection ruleset
# Protects against: UNION SELECT, SQL comments, blind SQLi, etc.

# Note: This is already included in Web ACL configuration
# This file documents the managed rules and their capabilities

locals {
  sqli_managed_rules = {
    name        = "AWSManagedRulesSQLiRuleSet"
    vendor      = "AWS"
    description = "Protection against SQL injection attacks"

    protected_vectors = [
      "UNION-based SQL injection",
      "Error-based SQL injection",
      "Boolean-based blind SQL injection",
      "Time-based blind SQL injection",
      "Stacked queries",
      "SQL comments",
      "INFORMATION_SCHEMA queries",
    ]

    example_blocked_patterns = [
      "' OR '1'='1",
      "'; DROP TABLE users--",
      "UNION SELECT NULL,NULL--",
      "1' AND SLEEP(5)--",
    ]
  }
}

# ===========================
# Cross-Site Scripting (XSS)
# ===========================

# XSS protection included in Known Bad Inputs ruleset
locals {
  xss_managed_rules = {
    name        = "AWSManagedRulesKnownBadInputsRuleSet"
    vendor      = "AWS"
    description = "Protection against XSS and known bad inputs"

    protected_vectors = [
      "Reflected XSS",
      "Stored XSS",
      "DOM-based XSS",
      "Script injection",
      "Event handler injection",
      "CSS injection",
    ]

    example_blocked_patterns = [
      "<script>alert(1)</script>",
      "<img src=x onerror=alert(1)>",
      "javascript:alert(1)",
      "<svg onload=alert(1)>",
    ]
  }
}

# ===========================
# IP Reputation Lists
# ===========================

# AWS-managed IP reputation lists (updated automatically)
locals {
  ip_reputation_rules = {
    name        = "AWSManagedRulesAmazonIpReputationList"
    vendor      = "AWS"
    description = "Block requests from IPs with poor reputation"

    sources = [
      "AWS threat intelligence",
      "Tor exit nodes",
      "Anonymous proxies",
      "Known botnet IPs",
      "Abuse reports",
    ]

    update_frequency = "Automatic (real-time)"
  }
}

# Amazon IP Reputation List (recommended for all deployments)
resource "aws_wafv2_web_acl" "with_ip_reputation" {
  name  = "examplepay-ip-reputation-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 15

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAmazonIpReputationList"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "IPReputationWebACL"
    sampled_requests_enabled   = true
  }

  tags = {
    Name    = "ip-reputation-web-acl"
    Purpose = "IP reputation blocking"
  }
}

# ===========================
# Linux Operating System
# ===========================

# Protection against Linux-specific exploits
locals {
  linux_os_rules = {
    name        = "AWSManagedRulesLinuxRuleSet"
    vendor      = "AWS"
    description = "Protection against Linux-specific attacks"

    protected_vectors = [
      "Local File Inclusion (LFI)",
      "Remote File Inclusion (RFI)",
      "Command injection",
      "Path traversal",
      "Shell injection",
    ]

    example_blocked_patterns = [
      "../../../etc/passwd",
      "'; cat /etc/passwd",
      "|cat /etc/passwd",
      "$(whoami)",
    ]
  }
}

# ===========================
# Windows Operating System
# ===========================

# Protection against Windows-specific exploits (if applicable)
locals {
  windows_os_rules = {
    name        = "AWSManagedRulesWindowsRuleSet"
    vendor      = "AWS"
    description = "Protection against Windows-specific attacks"

    protected_vectors = [
      "PowerShell injection",
      "Windows command injection",
      "Registry manipulation",
      "Windows path traversal",
    ]
  }
}

# ===========================
# PHP Application
# ===========================

# Protection for PHP-based applications (if applicable)
locals {
  php_app_rules = {
    name        = "AWSManagedRulesPHPRuleSet"
    vendor      = "AWS"
    description = "Protection for PHP applications"

    protected_vectors = [
      "PHP code injection",
      "eval() injection",
      "PHP file inclusion",
      "Deserialization attacks",
    ]
  }
}

# ===========================
# Bot Control
# ===========================

# AWS Managed Bot Control (requires additional cost)
# Protects against automated bot traffic

locals {
  bot_control_rules = {
    name        = "AWSManagedRulesBotControlRuleSet"
    vendor      = "AWS"
    description = "Advanced bot detection and mitigation"
    cost        = "$10/month + $1 per million bot requests analyzed"

    features = [
      "Bot classification (verified, suspected, unverified)",
      "Bot challenge (CAPTCHA)",
      "Bot allow/block actions",
      "Bot analytics and reporting",
    ]

    bot_categories = [
      "Search engine bots (allow)",
      "Social media bots (allow)",
      "Scraper bots (block)",
      "Attack bots (block)",
      "Unknown bots (challenge)",
    ]
  }
}

# Example Bot Control rule (commented out - requires separate purchase)
# resource "aws_wafv2_web_acl" "with_bot_control" {
#   name  = "examplepay-bot-control-acl"
#   scope = "REGIONAL"
#
#   default_action {
#     allow {}
#   }
#
#   rule {
#     name     = "AWSManagedRulesBotControlRuleSet"
#     priority = 25
#
#     override_action {
#       none {}
#     }
#
#     statement {
#       managed_rule_group_statement {
#         vendor_name = "AWS"
#         name        = "AWSManagedRulesBotControlRuleSet"
#       }
#     }
#
#     visibility_config {
#       cloudwatch_metrics_enabled = true
#       metric_name                = "BotControl"
#       sampled_requests_enabled   = true
#     }
#   }
# }

# ===========================
# Anonymous IP List
# ===========================

# Block anonymous hosting providers, VPNs, Tor
locals {
  anonymous_ip_rules = {
    name        = "AWSManagedRulesAnonymousIpList"
    vendor      = "AWS"
    description = "Block anonymous IP sources"

    blocked_sources = [
      "Tor exit nodes",
      "Anonymous proxies",
      "VPN providers",
      "Hosting providers (AWS, GCP, Azure, etc.)",
    ]

    use_cases = [
      "Block credential stuffing from botnets",
      "Prevent account takeover attempts",
      "Reduce fraud on payment pages",
    ]
  }
}

# ===========================
# Managed Rules Summary
# ===========================

output "managed_rules_summary" {
  description = "Summary of AWS Managed Rules configuration"
  value = {
    enabled_rule_groups = [
      "AWSManagedRulesCommonRuleSet (CRS) - OWASP Top 10",
      "AWSManagedRulesSQLiRuleSet - SQL Injection",
      "AWSManagedRulesKnownBadInputsRuleSet - XSS and bad inputs",
      "AWSManagedRulesAmazonIpReputationList - IP reputation",
    ]

    optional_rule_groups = [
      "AWSManagedRulesLinuxRuleSet - Linux exploits",
      "AWSManagedRulesWindowsRuleSet - Windows exploits",
      "AWSManagedRulesPHPRuleSet - PHP-specific",
      "AWSManagedRulesBotControlRuleSet - Bot protection ($$$)",
      "AWSManagedRulesAnonymousIpList - Anonymous IPs",
    ]

    auto_update         = "Yes - AWS manages updates"
    cost                = "Included in WAF pricing"
    false_positive_rate = "Low (<0.5% with proper tuning)"
  }
}

# ===========================
# Rule Group Metrics
# ===========================

# CloudWatch metric for CRS
resource "aws_cloudwatch_metric_alarm" "crs_high_block_rate" {
  alarm_name          = "waf-crs-high-block-rate"
  alarm_description   = "Alert when CRS blocks high percentage of traffic"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1000"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Rule   = "AWSManagedRulesCommonRuleSet"
    WebACL = aws_wafv2_web_acl.with_ip_reputation.name
    Region = data.aws_region.current.name
  }

  alarm_actions = [aws_sns_topic.waf_alerts.arn]

  tags = {
    Severity = "Medium"
    Purpose  = "Detect attack campaigns"
  }
}

# CloudWatch metric for SQL injection
resource "aws_cloudwatch_metric_alarm" "sqli_detected" {
  alarm_name          = "waf-sqli-attempts-detected"
  alarm_description   = "Alert when SQL injection attempts detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Rule   = "AWSManagedRulesSQLiRuleSet"
    WebACL = aws_wafv2_web_acl.with_ip_reputation.name
    Region = data.aws_region.current.name
  }

  alarm_actions = [aws_sns_topic.waf_alerts.arn]

  tags = {
    Severity = "High"
    Purpose  = "Detect SQL injection attacks"
  }
}

# SNS topic for WAF alerts
resource "aws_sns_topic" "waf_alerts" {
  name              = "waf-managed-rules-alerts"
  display_name      = "WAF Managed Rules Alerts"
  kms_master_key_id = data.aws_kms_alias.sns.target_key_arn

  tags = {
    Name    = "waf-alerts"
    Purpose = "WAF managed rule alerts"
  }
}

# Email subscription for WAF alerts
resource "aws_sns_topic_subscription" "waf_alerts_email" {
  topic_arn = aws_sns_topic.waf_alerts.arn
  protocol  = "email"
  endpoint  = "security-waf@example.com"
}

# ===========================
# Data Sources
# ===========================

data "aws_kms_alias" "sns" {
  name = "alias/examplepay-sns"
}

# ===========================
# Managed Rules Documentation
# ===========================

# Generate documentation output
output "managed_rules_documentation" {
  description = "Documentation for AWS Managed Rules"
  value = {
    core_rule_set = local.sqli_managed_rules
    xss_protection = local.xss_managed_rules
    ip_reputation = local.ip_reputation_rules
    bot_control = local.bot_control_rules

    tuning_recommendations = [
      "Start with COUNT mode to measure false positives",
      "Exclude rules that cause false positives",
      "Use custom rule groups for application-specific logic",
      "Review CloudWatch metrics weekly",
      "Test rule changes in staging first",
    ]

    reference_urls = {
      aws_managed_rules_guide = "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html"
      owasp_top_10            = "https://owasp.org/www-project-top-ten/"
      pci_dss_requirements    = "https://www.pcisecuritystandards.org/"
    }
  }
}
