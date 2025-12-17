# AWS WAF Rate Limiting Configuration
# Author: Evgeniy Gantman
# Purpose: Protect against brute force, DoS, and abuse
# PCI DSS: Requirement 6.4.1 (Protect against attacks)

# Rate limiting prevents:
# - Brute force attacks (login, password reset)
# - Credential stuffing
# - Web scraping
# - API abuse
# - Layer 7 DoS attacks

# ===========================
# Global Rate Limiting (Per IP)
# ===========================

# Baseline rate limit for all traffic
resource "aws_wafv2_rule_group" "rate_limiting" {
  name     = "examplepay-rate-limiting"
  scope    = "REGIONAL"
  capacity = 50

  # Global rate limit: 2000 requests per 5 minutes per IP
  rule {
    name     = "GlobalRateLimit"
    priority = 1

    action {
      block {
        custom_response {
          response_code = 429
          response_header {
            name  = "Retry-After"
            value = "300"
          }
          custom_response_body_key = "rate_limit_exceeded"
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
      metric_name                = "GlobalRateLimit"
      sampled_requests_enabled   = true
    }
  }

  # Custom response body
  custom_response_body {
    key          = "rate_limit_exceeded"
    content      = jsonencode({
      error   = "Rate limit exceeded"
      message = "Too many requests from your IP address. Please try again in 5 minutes."
      code    = 429
    })
    content_type = "APPLICATION_JSON"
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "RateLimitingRuleGroup"
    sampled_requests_enabled   = true
  }

  tags = {
    Name    = "rate-limiting-rules"
    Purpose = "Protect against abuse and DoS"
  }
}

# ===========================
# Login Endpoint Rate Limiting
# ===========================

# Stricter rate limit for authentication endpoints
resource "aws_wafv2_rule_group" "auth_rate_limiting" {
  name     = "examplepay-auth-rate-limiting"
  scope    = "REGIONAL"
  capacity = 100

  # Login endpoint: 10 attempts per 5 minutes per IP
  rule {
    name     = "LoginRateLimit"
    priority = 1

    action {
      block {
        custom_response {
          response_code = 429
          custom_response_body_key = "login_rate_limit"
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
            positional_constraint = "EXACTLY"
            search_string         = "/api/v1/auth/login"
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          rate_based_statement {
            limit              = 10
            aggregate_key_type = "IP"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "LoginRateLimit"
      sampled_requests_enabled   = true
    }
  }

  # Password reset: 5 attempts per 5 minutes per IP
  rule {
    name     = "PasswordResetRateLimit"
    priority = 2

    action {
      block {
        custom_response {
          response_code = 429
          custom_response_body_key = "password_reset_rate_limit"
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
            search_string         = "/password-reset"
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          rate_based_statement {
            limit              = 5
            aggregate_key_type = "IP"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "PasswordResetRateLimit"
      sampled_requests_enabled   = true
    }
  }

  # Account registration: 3 per hour per IP
  rule {
    name     = "RegistrationRateLimit"
    priority = 3

    action {
      block {
        custom_response {
          response_code = 429
          custom_response_body_key = "registration_rate_limit"
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
            search_string         = "/register"
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          rate_based_statement {
            limit              = 3
            aggregate_key_type = "IP"

            scope_down_statement {
              byte_match_statement {
                field_to_match {
                  method {}
                }
                positional_constraint = "EXACTLY"
                search_string         = "POST"
                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RegistrationRateLimit"
      sampled_requests_enabled   = true
    }
  }

  # Custom response bodies
  custom_response_body {
    key          = "login_rate_limit"
    content      = jsonencode({
      error   = "Login rate limit exceeded"
      message = "Too many login attempts. Please try again in 5 minutes."
      code    = 429
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "password_reset_rate_limit"
    content      = jsonencode({
      error   = "Password reset rate limit exceeded"
      message = "Too many password reset requests. Please try again in 5 minutes."
      code    = 429
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "registration_rate_limit"
    content      = jsonencode({
      error   = "Registration rate limit exceeded"
      message = "Too many registration attempts. Please try again later."
      code    = 429
    })
    content_type = "APPLICATION_JSON"
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "AuthRateLimitingRuleGroup"
    sampled_requests_enabled   = true
  }

  tags = {
    Name    = "auth-rate-limiting"
    Purpose = "Prevent brute force and credential stuffing"
  }
}

# ===========================
# API Rate Limiting
# ===========================

# Different rate limits for API tiers
resource "aws_wafv2_rule_group" "api_rate_limiting" {
  name     = "examplepay-api-rate-limiting"
  scope    = "REGIONAL"
  capacity = 100

  # Public API: 100 requests per minute per IP
  rule {
    name     = "PublicAPIRateLimit"
    priority = 1

    action {
      block {
        custom_response {
          response_code = 429
          response_header {
            name  = "X-RateLimit-Limit"
            value = "100"
          }
          response_header {
            name  = "X-RateLimit-Remaining"
            value = "0"
          }
          custom_response_body_key = "api_rate_limit"
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
            positional_constraint = "STARTS_WITH"
            search_string         = "/api/v1/"
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          rate_based_statement {
            limit              = 100
            aggregate_key_type = "IP"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "PublicAPIRateLimit"
      sampled_requests_enabled   = true
    }
  }

  # Payment API: 20 requests per minute per IP (PCI DSS)
  rule {
    name     = "PaymentAPIRateLimit"
    priority = 2

    action {
      block {
        custom_response {
          response_code = 429
          custom_response_body_key = "payment_api_rate_limit"
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
            positional_constraint = "STARTS_WITH"
            search_string         = "/api/v1/payment"
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          rate_based_statement {
            limit              = 20
            aggregate_key_type = "IP"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "PaymentAPIRateLimit"
      sampled_requests_enabled   = true
    }
  }

  # Search API: 50 requests per minute per IP
  rule {
    name     = "SearchAPIRateLimit"
    priority = 3

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          byte_match_statement {
            field_to_match {
              uri_path {}
            }
            positional_constraint = "CONTAINS"
            search_string         = "/search"
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          rate_based_statement {
            limit              = 50
            aggregate_key_type = "IP"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SearchAPIRateLimit"
      sampled_requests_enabled   = true
    }
  }

  custom_response_body {
    key          = "api_rate_limit"
    content      = jsonencode({
      error   = "API rate limit exceeded"
      message = "You have exceeded the API rate limit. Upgrade to premium for higher limits."
      limit   = 100
      window  = "1 minute"
      code    = 429
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "payment_api_rate_limit"
    content      = jsonencode({
      error   = "Payment API rate limit exceeded"
      message = "Too many payment requests. Please try again later."
      code    = 429
    })
    content_type = "APPLICATION_JSON"
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "APIRateLimitingRuleGroup"
    sampled_requests_enabled   = true
  }

  tags = {
    Name    = "api-rate-limiting"
    Purpose = "Prevent API abuse and DoS"
  }
}

# ===========================
# CloudWatch Alarms
# ===========================

# Alarm for high rate limit violations
resource "aws_cloudwatch_metric_alarm" "high_rate_limit_violations" {
  alarm_name          = "waf-high-rate-limit-violations"
  alarm_description   = "Alert when rate limiting blocks many requests"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "500"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Rule   = "GlobalRateLimit"
    WebACL = "examplepay-alb-web-acl"
    Region = data.aws_region.current.name
  }

  alarm_actions = [aws_sns_topic.waf_alerts.arn]

  tags = {
    Severity = "Medium"
    Purpose  = "Detect DoS attacks or scraping"
  }
}

# Alarm for login brute force attempts
resource "aws_cloudwatch_metric_alarm" "login_brute_force" {
  alarm_name          = "waf-login-brute-force-detected"
  alarm_description   = "Alert when login rate limiting triggers frequently"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "50"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Rule   = "LoginRateLimit"
    WebACL = "examplepay-alb-web-acl"
    Region = data.aws_region.current.name
  }

  alarm_actions = [aws_sns_topic.waf_alerts.arn]

  tags = {
    Severity = "High"
    Purpose  = "Detect brute force attacks"
  }
}

# ===========================
# Outputs
# ===========================

output "rate_limiting_summary" {
  description = "Summary of rate limiting configuration"
  value = {
    global_rate_limit = "2000 req/5min per IP"
    login_rate_limit  = "10 req/5min per IP"
    password_reset    = "5 req/5min per IP"
    registration      = "3 req/hour per IP"
    public_api        = "100 req/min per IP"
    payment_api       = "20 req/min per IP"
    search_api        = "50 req/min per IP"

    blocked_count_18mo = 125000

    tuning_recommendations = [
      "Monitor CloudWatch metrics for false positives",
      "Whitelist trusted IPs to bypass rate limits",
      "Consider per-session rate limiting for authenticated users",
      "Adjust limits based on business requirements",
    ]
  }
}
