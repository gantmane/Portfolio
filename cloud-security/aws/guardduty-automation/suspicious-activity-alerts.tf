# GuardDuty Suspicious Activity Alerts
# Author: Evgeniy Gantman
# Purpose: EventBridge rules for specific GuardDuty finding types
# PCI DSS: Requirement 10.6.3 (Follow up exceptions and anomalies)

# This file creates specific EventBridge rules for high-priority finding types
# Each rule routes to appropriate notification channel based on severity

# ===========================
# Cryptocurrency Mining Detection
# ===========================

resource "aws_cloudwatch_event_rule" "cryptocurrency_mining" {
  name        = "guardduty-cryptocurrency-mining"
  description = "Detect cryptocurrency mining activity"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{
        prefix = "CryptoCurrency:"
      }]
    }
  })

  tags = {
    FindingCategory = "Cryptocurrency"
    Severity        = "Critical"
    AutoResponse    = "Isolate"
  }
}

resource "aws_cloudwatch_event_target" "cryptocurrency_mining_critical" {
  rule      = aws_cloudwatch_event_rule.cryptocurrency_mining.name
  target_id = "CriticalAlert"
  arn       = aws_sns_topic.guardduty_critical.arn

  input_transformer {
    input_paths = {
      account      = "$.detail.accountId"
      region       = "$.detail.region"
      type         = "$.detail.type"
      instanceId   = "$.detail.resource.instanceDetails.instanceId"
      severity     = "$.detail.severity"
    }

    input_template = <<EOF
{
  "alert": "🚨 CRYPTOCURRENCY MINING DETECTED",
  "severity": "CRITICAL",
  "finding_type": "<type>",
  "account": "<account>",
  "region": "<region>",
  "instance_id": "<instanceId>",
  "severity_score": "<severity>",
  "action_required": "IMMEDIATE - Instance will be automatically isolated",
  "investigation": "Check recent processes, network connections, and SSH access logs"
}
EOF
  }
}

# Lambda target for automated isolation
resource "aws_cloudwatch_event_target" "cryptocurrency_mining_lambda" {
  rule      = aws_cloudwatch_event_rule.cryptocurrency_mining.name
  target_id = "AutomatedResponse"
  arn       = aws_lambda_function.automated_response.arn
}

# ===========================
# Backdoor and Command & Control
# ===========================

resource "aws_cloudwatch_event_rule" "backdoor_c2" {
  name        = "guardduty-backdoor-c2-activity"
  description = "Detect backdoor and command-and-control communication"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor:" },
        { prefix = "Trojan:" }
      ]
    }
  })

  tags = {
    FindingCategory = "Backdoor"
    Severity        = "Critical"
    AutoResponse    = "Isolate"
  }
}

resource "aws_cloudwatch_event_target" "backdoor_c2_critical" {
  rule      = aws_cloudwatch_event_rule.backdoor_c2.name
  target_id = "CriticalAlert"
  arn       = aws_sns_topic.guardduty_critical.arn

  input_transformer {
    input_paths = {
      account    = "$.detail.accountId"
      type       = "$.detail.type"
      instanceId = "$.detail.resource.instanceDetails.instanceId"
      remoteIp   = "$.detail.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4"
    }

    input_template = <<EOF
{
  "alert": "🚨 BACKDOOR / C2 COMMUNICATION DETECTED",
  "severity": "CRITICAL",
  "finding_type": "<type>",
  "account": "<account>",
  "instance_id": "<instanceId>",
  "remote_ip": "<remoteIp>",
  "action_required": "IMMEDIATE - Instance isolated, forensic snapshot created",
  "investigation": "Malware detected. Full forensic analysis required."
}
EOF
  }
}

resource "aws_cloudwatch_event_target" "backdoor_c2_lambda" {
  rule      = aws_cloudwatch_event_rule.backdoor_c2.name
  target_id = "AutomatedResponse"
  arn       = aws_lambda_function.automated_response.arn
}

# ===========================
# Unauthorized Access
# ===========================

resource "aws_cloudwatch_event_rule" "unauthorized_access" {
  name        = "guardduty-unauthorized-access"
  description = "Detect unauthorized access attempts"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{
        prefix = "UnauthorizedAccess:"
      }]
      severity = [{
        numeric = [">", 7.0]
      }]
    }
  })

  tags = {
    FindingCategory = "UnauthorizedAccess"
    Severity        = "High"
  }
}

resource "aws_cloudwatch_event_target" "unauthorized_access_high" {
  rule      = aws_cloudwatch_event_rule.unauthorized_access.name
  target_id = "HighAlert"
  arn       = aws_sns_topic.guardduty_high.arn

  input_transformer {
    input_paths = {
      account    = "$.detail.accountId"
      type       = "$.detail.type"
      resource   = "$.detail.resource.resourceType"
      sourceIp   = "$.detail.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4"
    }

    input_template = <<EOF
{
  "alert": "Unauthorized Access Attempt",
  "severity": "HIGH",
  "finding_type": "<type>",
  "account": "<account>",
  "resource_type": "<resource>",
  "source_ip": "<sourceIp>",
  "action_required": "Review access logs and consider credential rotation"
}
EOF
  }
}

# ===========================
# SSH Brute Force Attacks
# ===========================

resource "aws_cloudwatch_event_rule" "ssh_brute_force" {
  name        = "guardduty-ssh-brute-force"
  description = "Detect SSH brute force attacks"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "UnauthorizedAccess:EC2/SSHBruteForce"
      ]
    }
  })

  tags = {
    FindingCategory = "BruteForce"
    Severity        = "High"
  }
}

resource "aws_cloudwatch_event_target" "ssh_brute_force_high" {
  rule      = aws_cloudwatch_event_rule.ssh_brute_force.name
  target_id = "HighAlert"
  arn       = aws_sns_topic.guardduty_high.arn

  input_transformer {
    input_paths = {
      account    = "$.detail.accountId"
      instanceId = "$.detail.resource.instanceDetails.instanceId"
      sourceIp   = "$.detail.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4"
      country    = "$.detail.service.action.networkConnectionAction.remoteIpDetails.country.countryName"
    }

    input_template = <<EOF
{
  "alert": "SSH Brute Force Attack",
  "severity": "HIGH",
  "instance_id": "<instanceId>",
  "account": "<account>",
  "attacker_ip": "<sourceIp>",
  "attacker_country": "<country>",
  "action_required": "Restrict SSH access to corporate IP ranges only",
  "recommendation": "Enable MFA for SSH, use AWS Systems Manager Session Manager"
}
EOF
  }
}

# ===========================
# Port Scanning / Reconnaissance
# ===========================

resource "aws_cloudwatch_event_rule" "port_scanning" {
  name        = "guardduty-port-scanning"
  description = "Detect port scanning and reconnaissance activity"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Recon:EC2/" }
      ]
    }
  })

  tags = {
    FindingCategory = "Reconnaissance"
    Severity        = "Medium"
  }
}

resource "aws_cloudwatch_event_target" "port_scanning_kinesis" {
  rule      = aws_cloudwatch_event_rule.port_scanning.name
  target_id = "SendToSIEM"
  arn       = aws_kinesis_stream.guardduty_findings.arn
  role_arn  = aws_iam_role.eventbridge_to_kinesis.arn
}

# ===========================
# IAM Credential Compromise
# ===========================

resource "aws_cloudwatch_event_rule" "iam_credential_compromise" {
  name        = "guardduty-iam-credential-compromise"
  description = "Detect potential IAM credential compromise"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        "Stealth:IAMUser/CloudTrailLoggingDisabled"
      ]
    }
  })

  tags = {
    FindingCategory = "CredentialCompromise"
    Severity        = "Critical"
    AutoResponse    = "DisableKey"
  }
}

resource "aws_cloudwatch_event_target" "iam_compromise_critical" {
  rule      = aws_cloudwatch_event_rule.iam_credential_compromise.name
  target_id = "CriticalAlert"
  arn       = aws_sns_topic.guardduty_critical.arn

  input_transformer {
    input_paths = {
      account       = "$.detail.accountId"
      type          = "$.detail.type"
      userName      = "$.detail.resource.accessKeyDetails.userName"
      accessKeyId   = "$.detail.resource.accessKeyDetails.accessKeyId"
      principalId   = "$.detail.resource.accessKeyDetails.principalId"
    }

    input_template = <<EOF
{
  "alert": "🚨 IAM CREDENTIAL COMPROMISE",
  "severity": "CRITICAL",
  "finding_type": "<type>",
  "account": "<account>",
  "user_name": "<userName>",
  "access_key_id": "<accessKeyId>",
  "principal_id": "<principalId>",
  "action_required": "Access key will be automatically disabled",
  "investigation": "Review CloudTrail for unauthorized API calls, rotate all credentials"
}
EOF
  }
}

resource "aws_cloudwatch_event_target" "iam_compromise_lambda" {
  rule      = aws_cloudwatch_event_rule.iam_credential_compromise.name
  target_id = "AutomatedResponse"
  arn       = aws_lambda_function.automated_response.arn
}

# ===========================
# Data Exfiltration
# ===========================

resource "aws_cloudwatch_event_rule" "data_exfiltration" {
  name        = "guardduty-data-exfiltration"
  description = "Detect potential data exfiltration"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Trojan:EC2/DNSDataExfiltration",
        "UnauthorizedAccess:S3/MaliciousIPCaller"
      ]
    }
  })

  tags = {
    FindingCategory = "DataExfiltration"
    Severity        = "Critical"
  }
}

resource "aws_cloudwatch_event_target" "data_exfiltration_critical" {
  rule      = aws_cloudwatch_event_rule.data_exfiltration.name
  target_id = "CriticalAlert"
  arn       = aws_sns_topic.guardduty_critical.arn

  input_transformer {
    input_paths = {
      account  = "$.detail.accountId"
      type     = "$.detail.type"
      resource = "$.detail.resource.resourceType"
    }

    input_template = <<EOF
{
  "alert": "🚨 POTENTIAL DATA EXFILTRATION",
  "severity": "CRITICAL",
  "finding_type": "<type>",
  "account": "<account>",
  "resource_type": "<resource>",
  "action_required": "IMMEDIATE - Investigate data access patterns, review VPC Flow Logs",
  "investigation": "Possible data theft in progress"
}
EOF
  }
}

# ===========================
# Privilege Escalation
# ===========================

resource "aws_cloudwatch_event_rule" "privilege_escalation" {
  name        = "guardduty-privilege-escalation"
  description = "Detect privilege escalation attempts"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{
        prefix = "PrivilegeEscalation:"
      }]
    }
  })

  tags = {
    FindingCategory = "PrivilegeEscalation"
    Severity        = "High"
  }
}

resource "aws_cloudwatch_event_target" "privilege_escalation_high" {
  rule      = aws_cloudwatch_event_rule.privilege_escalation.name
  target_id = "HighAlert"
  arn       = aws_sns_topic.guardduty_high.arn

  input_transformer {
    input_paths = {
      account  = "$.detail.accountId"
      type     = "$.detail.type"
      userName = "$.detail.resource.accessKeyDetails.userName"
    }

    input_template = <<EOF
{
  "alert": "Privilege Escalation Attempt",
  "severity": "HIGH",
  "finding_type": "<type>",
  "account": "<account>",
  "user": "<userName>",
  "action_required": "Review IAM permissions and recent API calls",
  "investigation": "Check for unusual role assumptions or policy modifications"
}
EOF
  }
}

# ===========================
# Lambda Function for Automated Response
# ===========================

# Automated response Lambda (processes critical findings)
resource "aws_lambda_function" "automated_response" {
  filename      = "lambda_automated_response.zip"  # Placeholder
  function_name = "GuardDuty-Automated-Response"
  role          = aws_iam_role.automated_response_lambda.arn
  handler       = "guardduty_findings_processor.lambda_handler"
  runtime       = "python3.11"
  timeout       = 300

  environment {
    variables = {
      DRY_RUN = "false"
    }
  }

  tags = {
    Name    = "guardduty-automated-response"
    Purpose = "Automated incident response to critical findings"
  }
}

resource "aws_iam_role" "automated_response_lambda" {
  name = "GuardDutyAutomatedResponseLambda"

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

resource "aws_iam_role_policy" "automated_response_lambda" {
  name = "AutomatedResponsePolicy"
  role = aws_iam_role.automated_response_lambda.id

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
        Sid    = "EC2Isolation"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:CreateSecurityGroup",
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateTags",
          "ec2:CreateSnapshot",
          "ec2:DescribeSnapshots"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMKeyRotation"
        Effect = "Allow"
        Action = [
          "iam:UpdateAccessKey",
          "iam:GetUser",
          "iam:ListAccessKeys"
        ]
        Resource = "*"
      },
      {
        Sid    = "GuardDutyAccess"
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ArchiveFindings"
        ]
        Resource = "*"
      },
      {
        Sid    = "SNSPublish"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.guardduty_critical.arn
      }
    ]
  })
}

# Lambda permissions for EventBridge invocations
resource "aws_lambda_permission" "automated_response_cryptocurrency" {
  statement_id  = "AllowCryptocurrencyRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.automated_response.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cryptocurrency_mining.arn
}

resource "aws_lambda_permission" "automated_response_backdoor" {
  statement_id  = "AllowBackdoorRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.automated_response.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.backdoor_c2.arn
}

resource "aws_lambda_permission" "automated_response_iam" {
  statement_id  = "AllowIAMRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.automated_response.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_credential_compromise.arn
}

# ===========================
# Outputs
# ===========================

output "eventbridge_rules" {
  description = "EventBridge rules for GuardDuty findings"
  value = {
    cryptocurrency_mining = aws_cloudwatch_event_rule.cryptocurrency_mining.name
    backdoor_c2           = aws_cloudwatch_event_rule.backdoor_c2.name
    unauthorized_access   = aws_cloudwatch_event_rule.unauthorized_access.name
    ssh_brute_force       = aws_cloudwatch_event_rule.ssh_brute_force.name
    port_scanning         = aws_cloudwatch_event_rule.port_scanning.name
    iam_compromise        = aws_cloudwatch_event_rule.iam_credential_compromise.name
    data_exfiltration     = aws_cloudwatch_event_rule.data_exfiltration.name
    privilege_escalation  = aws_cloudwatch_event_rule.privilege_escalation.name
  }
}

output "automated_response_function" {
  description = "Lambda function for automated incident response"
  value       = aws_lambda_function.automated_response.function_name
}

output "alert_routing_summary" {
  description = "Alert routing configuration"
  value = {
    critical_findings = "PagerDuty via SNS + Automated Isolation"
    high_findings     = "Slack via SNS Lambda"
    medium_findings   = "SIEM (Wazuh) via Kinesis"
    automated_actions = ["EC2 isolation", "Forensic snapshot", "IAM key disable"]
  }
}
