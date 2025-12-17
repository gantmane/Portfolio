# Custom Security Hub Insights
# Author: Evgeniy Gantman
# Purpose: Custom queries and dashboards for security operations
# PCI DSS: Requirement 10.6 (Review logs for anomalies)

# ===========================
# Critical and High Findings by Account
# ===========================

resource "aws_securityhub_insight" "critical_high_by_account" {
  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
  }

  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "HIGH"
    }
  }

  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "AwsAccountId"

  name = "Critical and High Findings by Account"
}

# ===========================
# Unresolved Findings Over 30 Days
# ===========================

resource "aws_securityhub_insight" "aged_findings" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  filters {
    updated_at {
      date_range {
        unit  = "DAYS"
        value = 30
      }
    }
  }

  group_by_attribute = "ResourceId"

  name = "Unresolved Findings Over 30 Days"
}

# ===========================
# Failed CIS Checks
# ===========================

resource "aws_securityhub_insight" "failed_cis_checks" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }
  }

  filters {
    product_name {
      comparison = "EQUALS"
      value      = "Security Hub"
    }
  }

  filters {
    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark"
    }
  }

  group_by_attribute = "GeneratorId"

  name = "Failed CIS Benchmark Checks"
}

# ===========================
# PCI DSS Non-Compliant Resources
# ===========================

resource "aws_securityhub_insight" "pci_dss_non_compliant" {
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }
  }

  filters {
    generator_id {
      comparison = "PREFIX"
      value      = "arn:aws:securityhub:::ruleset/pci-dss"
    }
  }

  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "ResourceId"

  name = "PCI DSS Non-Compliant Resources"
}

# ===========================
# Resources with Multiple Critical Findings
# ===========================

resource "aws_securityhub_insight" "multi_critical_resources" {
  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
  }

  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "ResourceId"

  name = "Resources with Multiple Critical Findings"
}

# ===========================
# Findings by Resource Type
# ===========================

resource "aws_securityhub_insight" "findings_by_resource_type" {
  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "ResourceType"

  name = "Active Findings by Resource Type"
}

# ===========================
# GuardDuty Findings Integration
# ===========================

resource "aws_securityhub_insight" "guardduty_findings" {
  filters {
    product_name {
      comparison = "EQUALS"
      value      = "GuardDuty"
    }
  }

  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "Type"

  name = "Active GuardDuty Findings by Type"
}

# ===========================
# Inspector Vulnerability Findings
# ===========================

resource "aws_securityhub_insight" "inspector_vulnerabilities" {
  filters {
    product_name {
      comparison = "EQUALS"
      value      = "Inspector"
    }
  }

  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
  }

  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "HIGH"
    }
  }

  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "ResourceId"

  name = "Critical/High Inspector Vulnerabilities"
}

# ===========================
# S3 Security Findings
# ===========================

resource "aws_securityhub_insight" "s3_security_findings" {
  filters {
    resource_type {
      comparison = "EQUALS"
      value      = "AwsS3Bucket"
    }
  }

  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }
  }

  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "ResourceId"

  name = "S3 Buckets with Security Issues"
}

# ===========================
# IAM Security Findings
# ===========================

resource "aws_securityhub_insight" "iam_security_findings" {
  filters {
    resource_type {
      comparison = "PREFIX"
      value      = "AwsIam"
    }
  }

  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }
  }

  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "Type"

  name = "IAM Security Findings by Type"
}

# ===========================
# EC2 Instance Security Findings
# ===========================

resource "aws_securityhub_insight" "ec2_security_findings" {
  filters {
    resource_type {
      comparison = "EQUALS"
      value      = "AwsEc2Instance"
    }
  }

  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "HIGH"
    }
  }

  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
  }

  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "ResourceId"

  name = "EC2 Instances with Critical/High Findings"
}

# ===========================
# RDS Security Findings
# ===========================

resource "aws_securityhub_insight" "rds_security_findings" {
  filters {
    resource_type {
      comparison = "PREFIX"
      value      = "AwsRds"
    }
  }

  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }
  }

  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "Type"

  name = "RDS Database Security Findings"
}

# ===========================
# New Findings in Last 7 Days
# ===========================

resource "aws_securityhub_insight" "new_findings_7days" {
  filters {
    created_at {
      date_range {
        unit  = "DAYS"
        value = 7
      }
    }
  }

  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "SeverityLabel"

  name = "New Findings in Last 7 Days"
}

# ===========================
# Suppressed Findings Requiring Review
# ===========================

resource "aws_securityhub_insight" "suppressed_findings_review" {
  filters {
    workflow_status {
      comparison = "EQUALS"
      value      = "SUPPRESSED"
    }
  }

  filters {
    updated_at {
      date_range {
        unit  = "DAYS"
        value = 90
      }
    }
  }

  group_by_attribute = "ResourceId"

  name = "Suppressed Findings (90+ Days - Review Required)"
}

# ===========================
# Network Security Findings
# ===========================

resource "aws_securityhub_insight" "network_security_findings" {
  filters {
    resource_type {
      comparison = "PREFIX"
      value      = "AwsEc2SecurityGroup"
    }
  }

  filters {
    resource_type {
      comparison = "PREFIX"
      value      = "AwsEc2NetworkAcl"
    }
  }

  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }
  }

  filters {
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "Type"

  name = "Network Security Configuration Findings"
}

# ===========================
# Outputs
# ===========================

output "custom_insights" {
  description = "Custom Security Hub insights created"
  value = {
    critical_high_by_account         = aws_securityhub_insight.critical_high_by_account.name
    aged_findings                    = aws_securityhub_insight.aged_findings.name
    failed_cis_checks                = aws_securityhub_insight.failed_cis_checks.name
    pci_dss_non_compliant            = aws_securityhub_insight.pci_dss_non_compliant.name
    multi_critical_resources         = aws_securityhub_insight.multi_critical_resources.name
    findings_by_resource_type        = aws_securityhub_insight.findings_by_resource_type.name
    guardduty_findings               = aws_securityhub_insight.guardduty_findings.name
    inspector_vulnerabilities        = aws_securityhub_insight.inspector_vulnerabilities.name
    s3_security_findings             = aws_securityhub_insight.s3_security_findings.name
    iam_security_findings            = aws_securityhub_insight.iam_security_findings.name
    ec2_security_findings            = aws_securityhub_insight.ec2_security_findings.name
    rds_security_findings            = aws_securityhub_insight.rds_security_findings.name
    new_findings_7days               = aws_securityhub_insight.new_findings_7days.name
    suppressed_findings_review       = aws_securityhub_insight.suppressed_findings_review.name
    network_security_findings        = aws_securityhub_insight.network_security_findings.name
  }
}
