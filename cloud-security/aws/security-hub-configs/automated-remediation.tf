# Automated Remediation for Security Hub Findings
# Author: Evgeniy Gantman
# Purpose: Auto-remediate common security findings to reduce MTTR
# PCI DSS: Automated response to security events

# ===========================
# IAM Role for Remediation Lambda Functions
# ===========================

resource "aws_iam_role" "remediation_lambda" {
  name = "SecurityHubRemediationLambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Purpose = "Security Hub automated remediation"
  }
}

resource "aws_iam_role_policy" "remediation_lambda" {
  name = "SecurityHubRemediationPolicy"
  role = aws_iam_role.remediation_lambda.id

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
        Sid    = "S3Remediation"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketVersioning",
          "s3:PutBucketLogging"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2Remediation"
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceAttribute",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMRemediation"
        Effect = "Allow"
        Action = [
          "iam:UpdateAccountPasswordPolicy",
          "iam:DeleteAccessKey",
          "iam:UpdateAccessKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailRemediation"
        Effect = "Allow"
        Action = [
          "cloudtrail:StartLogging",
          "cloudtrail:UpdateTrail"
        ]
        Resource = "*"
      },
      {
        Sid    = "RDSRemediation"
        Effect = "Allow"
        Action = [
          "rds:ModifyDBInstance",
          "rds:ModifyDBSnapshotAttribute"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecurityHubUpdate"
        Effect = "Allow"
        Action = [
          "securityhub:BatchUpdateFindings"
        ]
        Resource = "*"
      }
    ]
  })
}

# ===========================
# S3.1 - Block S3 Public Access
# ===========================

resource "aws_lambda_function" "remediate_s3_public_access" {
  filename      = "lambda_placeholder.zip"  # Replace with actual deployment package
  function_name = "SecurityHub-Remediate-S3-PublicAccess"
  role          = aws_iam_role.remediation_lambda.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60

  environment {
    variables = {
      SECURITY_HUB_ENABLED = "true"
    }
  }

  tags = {
    Purpose = "Block S3 public access"
  }
}

resource "aws_cloudwatch_event_rule" "s3_public_access" {
  name        = "securityhub-s3-public-access"
  description = "Trigger remediation for S3 public access findings"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Title = [{
          prefix = "S3.1"
        }]
        Compliance = {
          Status = ["FAILED"]
        }
        Workflow = {
          Status = ["NEW", "NOTIFIED"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_public_access" {
  rule      = aws_cloudwatch_event_rule.s3_public_access.name
  target_id = "RemediateS3PublicAccess"
  arn       = aws_lambda_function.remediate_s3_public_access.arn
}

resource "aws_lambda_permission" "s3_public_access" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate_s3_public_access.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_public_access.arn
}

# ===========================
# S3.4 - Enable S3 Encryption
# ===========================

resource "aws_lambda_function" "remediate_s3_encryption" {
  filename      = "lambda_placeholder.zip"
  function_name = "SecurityHub-Remediate-S3-Encryption"
  role          = aws_iam_role.remediation_lambda.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60

  environment {
    variables = {
      KMS_KEY_ARN = data.aws_kms_alias.s3.target_key_arn
    }
  }

  tags = {
    Purpose = "Enable S3 bucket encryption"
  }
}

resource "aws_cloudwatch_event_rule" "s3_encryption" {
  name        = "securityhub-s3-encryption"
  description = "Trigger remediation for S3 encryption findings"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Title = [{
          prefix = "S3.4"
        }]
        Compliance = {
          Status = ["FAILED"]
        }
        Workflow = {
          Status = ["NEW", "NOTIFIED"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_encryption" {
  rule      = aws_cloudwatch_event_rule.s3_encryption.name
  target_id = "RemediateS3Encryption"
  arn       = aws_lambda_function.remediate_s3_encryption.arn
}

resource "aws_lambda_permission" "s3_encryption" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate_s3_encryption.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_encryption.arn
}

# ===========================
# EC2.2 - Remove Security Group 0.0.0.0/0 Rules
# ===========================

resource "aws_lambda_function" "remediate_sg_open_access" {
  filename      = "lambda_placeholder.zip"
  function_name = "SecurityHub-Remediate-SG-OpenAccess"
  role          = aws_iam_role.remediation_lambda.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60

  environment {
    variables = {
      APPROVAL_REQUIRED = "true"  # Require manual approval before revoking
    }
  }

  tags = {
    Purpose = "Remove overly permissive security group rules"
  }
}

resource "aws_cloudwatch_event_rule" "sg_open_access" {
  name        = "securityhub-sg-open-access"
  description = "Trigger remediation for security group 0.0.0.0/0 findings"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Title = [{
          prefix = "EC2.2"
        }]
        Compliance = {
          Status = ["FAILED"]
        }
        Workflow = {
          Status = ["NEW", "NOTIFIED"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sg_open_access" {
  rule      = aws_cloudwatch_event_rule.sg_open_access.name
  target_id = "RemediateSGOpenAccess"
  arn       = aws_lambda_function.remediate_sg_open_access.arn
}

resource "aws_lambda_permission" "sg_open_access" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate_sg_open_access.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sg_open_access.arn
}

# ===========================
# CloudTrail.1 - Re-enable CloudTrail
# ===========================

resource "aws_ssm_document" "enable_cloudtrail" {
  name          = "SecurityHub-EnableCloudTrail"
  document_type = "Automation"

  content = jsonencode({
    schemaVersion = "0.3"
    description   = "Re-enable CloudTrail logging"
    parameters = {
      TrailName = {
        type        = "String"
        description = "CloudTrail trail name"
      }
    }
    mainSteps = [
      {
        name   = "EnableCloudTrail"
        action = "aws:executeAwsApi"
        inputs = {
          Service = "cloudtrail"
          Api     = "StartLogging"
          Name    = "{{ TrailName }}"
        }
      }
    ]
  })

  tags = {
    Purpose = "CloudTrail remediation"
  }
}

resource "aws_cloudwatch_event_rule" "cloudtrail_disabled" {
  name        = "securityhub-cloudtrail-disabled"
  description = "Trigger SSM automation for disabled CloudTrail"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Title = [{
          prefix = "CloudTrail.1"
        }]
        Compliance = {
          Status = ["FAILED"]
        }
        Workflow = {
          Status = ["NEW", "NOTIFIED"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "cloudtrail_disabled" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_disabled.name
  target_id = "EnableCloudTrail"
  arn       = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:automation-definition/${aws_ssm_document.enable_cloudtrail.name}"
  role_arn  = aws_iam_role.ssm_automation.arn
}

# ===========================
# IAM Role for SSM Automation
# ===========================

resource "aws_iam_role" "ssm_automation" {
  name = "SecurityHubSSMAutomation"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = ["ssm.amazonaws.com", "events.amazonaws.com"]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ssm_automation" {
  name = "SSMAutomationPolicy"
  role = aws_iam_role.ssm_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:StartAutomationExecution",
          "cloudtrail:StartLogging",
          "cloudtrail:UpdateTrail"
        ]
        Resource = "*"
      }
    ]
  })
}

# ===========================
# Remediation Metrics
# ===========================

resource "aws_cloudwatch_log_metric_filter" "remediation_success" {
  name           = "SecurityHubRemediationSuccess"
  log_group_name = "/aws/lambda/SecurityHub-Remediate-*"
  pattern        = "[timestamp, request_id, level=INFO, msg=\"Remediation successful\"]"

  metric_transformation {
    name      = "RemediationSuccessCount"
    namespace = "SecurityHub/Remediation"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "remediation_failure" {
  name           = "SecurityHubRemediationFailure"
  log_group_name = "/aws/lambda/SecurityHub-Remediate-*"
  pattern        = "[timestamp, request_id, level=ERROR, msg=\"Remediation failed\"]"

  metric_transformation {
    name      = "RemediationFailureCount"
    namespace = "SecurityHub/Remediation"
    value     = "1"
  }
}

# Alarm on remediation failures
resource "aws_cloudwatch_metric_alarm" "remediation_failures" {
  alarm_name          = "security-hub-remediation-failures"
  alarm_description   = "Alert on automated remediation failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "RemediationFailureCount"
  namespace           = "SecurityHub/Remediation"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.high_findings.arn]

  tags = {
    Purpose = "Monitor automated remediation"
  }
}

# ===========================
# Outputs
# ===========================

output "remediation_lambda_functions" {
  description = "Lambda functions for automated remediation"
  value = {
    s3_public_access = aws_lambda_function.remediate_s3_public_access.function_name
    s3_encryption    = aws_lambda_function.remediate_s3_encryption.function_name
    sg_open_access   = aws_lambda_function.remediate_sg_open_access.function_name
  }
}

output "ssm_automation_documents" {
  description = "SSM Automation documents"
  value = {
    enable_cloudtrail = aws_ssm_document.enable_cloudtrail.name
  }
}

output "remediation_metrics" {
  description = "CloudWatch metrics for remediation tracking"
  value = {
    success_metric = "RemediationSuccessCount"
    failure_metric = "RemediationFailureCount"
    namespace      = "SecurityHub/Remediation"
  }
}
