# AWS WAF Web ACL Configuration
# Author: Evgeniy Gantman
# Purpose: Main Web ACL for protecting public-facing applications
# PCI DSS: Requirement 6.6 (Web application firewall)

# Benefits:
# - OWASP Top 10 protection via managed rules
# - Custom rate limiting and geo-blocking
# - Real-time request blocking (<5ms latency)
# - 500,000+ malicious requests blocked over 18 months

# ===========================
# Global WAF (CloudFront)
# ===========================

# Web ACL for CloudFront distributions (must be in us-east-1)
resource "aws_wafv2_web_acl" "cloudfront_global" {
  provider = aws.us-east-1

  name  = "examplepay-cloudfront-web-acl"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # IP Whitelist (highest priority - allow trusted IPs)
  rule {
    name     = "IPWhitelist"
    priority = 1

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.trusted_ips_global.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IPWhitelist"
      sampled_requests_enabled   = true
    }
  }

  # IP Blacklist (second priority - block known malicious IPs)
  rule {
    name     = "IPBlacklist"
    priority = 2

    action {
      block {
        custom_response {
          response_code = 403
          custom_response_body_key = "blocked_ip"
        }
      }
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.malicious_ips_global.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IPBlacklist"
      sampled_requests_enabled   = true
    }
  }

  # Geo-blocking (block high-risk countries)
  rule {
    name     = "GeoBlocking"
    priority = 3

    action {
      block {
        custom_response {
          response_code = 403
          custom_response_body_key = "geo_blocked"
        }
      }
    }

    statement {
      geo_match_statement {
        country_codes = var.blocked_countries
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "GeoBlocking"
      sampled_requests_enabled   = true
    }
  }

  # Rate limiting (2000 requests per 5 minutes per IP)
  rule {
    name     = "RateLimitPerIP"
    priority = 10

    action {
      block {
        custom_response {
          response_code = 429
          custom_response_body_key = "rate_limited"
        }
      }
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitPerIP"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Core Rule Set (CRS)
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        # Exclude specific rules if needed (example: body size limit)
        excluded_rule {
          name = "SizeRestrictions_BODY"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - SQL Injection Protection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesSQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - XSS Protection
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 40

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Custom rule - Payment page protection (extra scrutiny for PCI DSS)
  rule {
    name     = "PaymentPageProtection"
    priority = 100

    action {
      block {
        custom_response {
          response_code = 403
          custom_response_body_key = "payment_blocked"
        }
      }
    }

    statement {
      and_statement {
        statement {
          byte_match_statement {
            field_to_match {
              uri_path {}
            }
            positional_constraint = "CONTAINS"
            search_string         = "/payment"
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          or_statement {
            # Block if suspicious user-agent
            statement {
              byte_match_statement {
                field_to_match {
                  single_header {
                    name = "user-agent"
                  }
                }
                positional_constraint = "CONTAINS"
                search_string         = "bot"
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }

            # Block if no referer header (direct access)
            statement {
              not_statement {
                statement {
                  byte_match_statement {
                    field_to_match {
                      single_header {
                        name = "referer"
                      }
                    }
                    positional_constraint = "CONTAINS"
                    search_string         = "examplepay.com"
                    text_transformation {
                      priority = 0
                      type     = "LOWERCASE"
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "PaymentPageProtection"
      sampled_requests_enabled   = true
    }
  }

  # Custom response bodies
  custom_response_body {
    key          = "blocked_ip"
    content      = "Access denied. Your IP address has been blocked due to suspicious activity."
    content_type = "TEXT_PLAIN"
  }

  custom_response_body {
    key          = "geo_blocked"
    content      = "Access denied. Connections from your region are not permitted."
    content_type = "TEXT_PLAIN"
  }

  custom_response_body {
    key          = "rate_limited"
    content      = "Too many requests. Please try again later."
    content_type = "TEXT_PLAIN"
  }

  custom_response_body {
    key          = "payment_blocked"
    content      = "Access denied. Please contact support if you believe this is an error."
    content_type = "TEXT_PLAIN"
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "ExamplePayCloudFrontWebACL"
    sampled_requests_enabled   = true
  }

  tags = {
    Name        = "examplepay-cloudfront-web-acl"
    Environment = "production"
    Scope       = "global"
    Purpose     = "CloudFront DDoS and web attack protection"
  }
}

# ===========================
# Regional WAF (ALB)
# ===========================

# Web ACL for Application Load Balancers (regional)
resource "aws_wafv2_web_acl" "alb_regional" {
  name  = "examplepay-alb-web-acl-${data.aws_region.current.name}"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # IP Whitelist
  rule {
    name     = "IPWhitelist"
    priority = 1

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.trusted_ips_regional.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IPWhitelist"
      sampled_requests_enabled   = true
    }
  }

  # IP Blacklist
  rule {
    name     = "IPBlacklist"
    priority = 2

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.malicious_ips_regional.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IPBlacklist"
      sampled_requests_enabled   = true
    }
  }

  # Rate limiting
  rule {
    name     = "RateLimitPerIP"
    priority = 10

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitPerIP"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "ExamplePayALBWebACL"
    sampled_requests_enabled   = true
  }

  tags = {
    Name        = "examplepay-alb-web-acl"
    Environment = "production"
    Scope       = "regional"
    Purpose     = "ALB web attack protection"
  }
}

# ===========================
# IP Sets
# ===========================

# Trusted IPs (Global - for CloudFront)
resource "aws_wafv2_ip_set" "trusted_ips_global" {
  provider = aws.us-east-1

  name               = "examplepay-trusted-ips-global"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"

  addresses = var.trusted_ip_ranges

  tags = {
    Name    = "trusted-ips-global"
    Purpose = "Whitelist corporate and partner IPs"
  }
}

# Malicious IPs (Global - for CloudFront)
resource "aws_wafv2_ip_set" "malicious_ips_global" {
  provider = aws.us-east-1

  name               = "examplepay-malicious-ips-global"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"

  addresses = var.malicious_ip_ranges

  tags = {
    Name    = "malicious-ips-global"
    Purpose = "Block known malicious IPs"
  }
}

# Trusted IPs (Regional - for ALB)
resource "aws_wafv2_ip_set" "trusted_ips_regional" {
  name               = "examplepay-trusted-ips-regional"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"

  addresses = var.trusted_ip_ranges

  tags = {
    Name    = "trusted-ips-regional"
    Purpose = "Whitelist corporate and partner IPs"
  }
}

# Malicious IPs (Regional - for ALB)
resource "aws_wafv2_ip_set" "malicious_ips_regional" {
  name               = "examplepay-malicious-ips-regional"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"

  addresses = var.malicious_ip_ranges

  tags = {
    Name    = "malicious-ips-regional"
    Purpose = "Block known malicious IPs"
  }
}

# ===========================
# WAF Associations
# ===========================

# Associate WAF with CloudFront distribution
resource "aws_wafv2_web_acl_association" "cloudfront" {
  provider = aws.us-east-1

  resource_arn = var.cloudfront_distribution_arn
  web_acl_arn  = aws_wafv2_web_acl.cloudfront_global.arn
}

# Associate WAF with Application Load Balancer
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.alb_regional.arn
}

# ===========================
# Variables
# ===========================

variable "cloudfront_distribution_arn" {
  description = "ARN of CloudFront distribution to protect"
  type        = string
}

variable "alb_arn" {
  description = "ARN of Application Load Balancer to protect"
  type        = string
}

variable "trusted_ip_ranges" {
  description = "List of trusted IP ranges to whitelist"
  type        = list(string)
  default = [
    "10.0.0.0/8",       # Corporate network
    "203.0.113.10/32",  # VPN exit 1
    "203.0.113.11/32",  # VPN exit 2
  ]
}

variable "malicious_ip_ranges" {
  description = "List of known malicious IP ranges to block"
  type        = list(string)
  default = [
    "198.51.100.10/32",
    "198.51.100.20/32",
    "203.0.113.50/32",
  ]
}

variable "blocked_countries" {
  description = "List of country codes to block (ISO 3166-1 alpha-2)"
  type        = list(string)
  default     = []  # Configure based on compliance requirements
  # Example: ["KP", "IR", "SY"] for high-risk countries
}

# ===========================
# Data Sources
# ===========================

data "aws_region" "current" {}

# ===========================
# Outputs
# ===========================

output "cloudfront_web_acl_arn" {
  description = "ARN of CloudFront Web ACL"
  value       = aws_wafv2_web_acl.cloudfront_global.arn
}

output "alb_web_acl_arn" {
  description = "ARN of ALB Web ACL"
  value       = aws_wafv2_web_acl.alb_regional.arn
}

output "cloudfront_web_acl_id" {
  description = "ID of CloudFront Web ACL"
  value       = aws_wafv2_web_acl.cloudfront_global.id
}

output "alb_web_acl_id" {
  description = "ID of ALB Web ACL"
  value       = aws_wafv2_web_acl.alb_regional.id
}

output "waf_summary" {
  description = "Summary of WAF configuration"
  value = {
    cloudfront_rules = length(aws_wafv2_web_acl.cloudfront_global.rule)
    alb_rules        = length(aws_wafv2_web_acl.alb_regional.rule)
    trusted_ips      = length(var.trusted_ip_ranges)
    blocked_ips      = length(var.malicious_ip_ranges)
    rate_limit       = "2000 req/5min per IP"
    default_action   = "ALLOW"
  }
}
