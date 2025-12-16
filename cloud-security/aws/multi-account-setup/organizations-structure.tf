# AWS Organizations Structure - Multi-Account Setup
# Author: Evgeniy Gantman
# Purpose: Define organizational structure with 15+ accounts
# PCI DSS: Requirements 1, 2, 7, 10, 12

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# AWS Organization
resource "aws_organizations_organization" "main" {
  feature_set = "ALL"

  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "sso.amazonaws.com",
    "access-analyzer.amazonaws.com",
  ]

  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
    "TAG_POLICY",
    "BACKUP_POLICY",
  ]
}

# Root Organizational Unit (automatically created)
data "aws_organizations_organization" "current" {
  depends_on = [aws_organizations_organization.main]
}

# ===========================
# Organizational Units (OUs)
# ===========================

# Security OU - For security and compliance accounts
resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = data.aws_organizations_organization.current.roots[0].id

  tags = {
    Purpose     = "Security and Compliance"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# Production OU - For production workloads
resource "aws_organizations_organizational_unit" "production" {
  name      = "Production"
  parent_id = data.aws_organizations_organization.current.roots[0].id

  tags = {
    Purpose     = "Production Workloads"
    Environment = "production"
    ManagedBy   = "terraform"
    PCIScope    = "yes"
  }
}

# Development OU - For development and staging
resource "aws_organizations_organizational_unit" "development" {
  name      = "Development"
  parent_id = data.aws_organizations_organization.current.roots[0].id

  tags = {
    Purpose     = "Development and Staging"
    Environment = "development"
    ManagedBy   = "terraform"
  }
}

# Sandbox OU - For experimentation and testing
resource "aws_organizations_organizational_unit" "sandbox" {
  name      = "Sandbox"
  parent_id = data.aws_organizations_organization.current.roots[0].id

  tags = {
    Purpose     = "Sandbox and Experimentation"
    Environment = "sandbox"
    ManagedBy   = "terraform"
  }
}

# ===========================
# Security OU Accounts
# ===========================

resource "aws_organizations_account" "log_archive" {
  name      = "ExampleCorp-Log-Archive"
  email     = "aws-log-archive@example.com"
  parent_id = aws_organizations_organizational_unit.security.id

  role_name = "OrganizationAccountAccessRole"

  tags = {
    Purpose     = "Centralized Log Archive"
    Environment = "security"
    PCIScope    = "yes"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_account" "security_audit" {
  name      = "ExampleCorp-Security-Audit"
  email     = "aws-security-audit@example.com"
  parent_id = aws_organizations_organizational_unit.security.id

  role_name = "OrganizationAccountAccessRole"

  tags = {
    Purpose     = "Security Auditing and Compliance"
    Environment = "security"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_account" "security_tooling" {
  name      = "ExampleCorp-Security-Tooling"
  email     = "aws-security-tooling@example.com"
  parent_id = aws_organizations_organizational_unit.security.id

  role_name = "OrganizationAccountAccessRole"

  tags = {
    Purpose     = "Security Tools (SIEM, Vulnerability Scanning)"
    Environment = "security"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ===========================
# Production OU Accounts
# ===========================

resource "aws_organizations_account" "prod_app" {
  name      = "ExamplePay-Production-App"
  email     = "aws-prod-app@examplepay.com"
  parent_id = aws_organizations_organizational_unit.production.id

  role_name = "OrganizationAccountAccessRole"

  tags = {
    Purpose     = "Production Application Services"
    Environment = "production"
    Application = "payment-gateway"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_account" "prod_data" {
  name      = "ExamplePay-Production-Data"
  email     = "aws-prod-data@examplepay.com"
  parent_id = aws_organizations_organizational_unit.production.id

  role_name = "OrganizationAccountAccessRole"

  tags = {
    Purpose     = "Production Databases and Analytics"
    Environment = "production"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Cardholder Data Environment (CDE) - PCI DSS Requirement 1
resource "aws_organizations_account" "cde" {
  name      = "ExamplePay-CDE"
  email     = "aws-cde@examplepay.com"
  parent_id = aws_organizations_organizational_unit.production.id

  role_name = "OrganizationAccountAccessRole"

  tags = {
    Purpose     = "Cardholder Data Environment (PCI DSS)"
    Environment = "production"
    PCIScope    = "in-scope"
    DataClass   = "pci-cardholder-data"
    Compliance  = "pci-dss-4.0"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ===========================
# Development OU Accounts
# ===========================

resource "aws_organizations_account" "dev_app" {
  name      = "ExamplePay-Development-App"
  email     = "aws-dev-app@examplepay.com"
  parent_id = aws_organizations_organizational_unit.development.id

  role_name = "OrganizationAccountAccessRole"

  tags = {
    Purpose     = "Development Application Services"
    Environment = "development"
  }
}

resource "aws_organizations_account" "dev_data" {
  name      = "ExamplePay-Development-Data"
  email     = "aws-dev-data@examplepay.com"
  parent_id = aws_organizations_organizational_unit.development.id

  role_name = "OrganizationAccountAccessRole"

  tags = {
    Purpose     = "Development Databases"
    Environment = "development"
  }
}

resource "aws_organizations_account" "staging" {
  name      = "ExamplePay-Staging"
  email     = "aws-staging@examplepay.com"
  parent_id = aws_organizations_organizational_unit.development.id

  role_name = "OrganizationAccountAccessRole"

  tags = {
    Purpose     = "Staging Environment for Pre-Production Testing"
    Environment = "staging"
  }
}

# ===========================
# Sandbox OU Accounts
# ===========================

resource "aws_organizations_account" "sandbox_01" {
  name      = "ExampleCorp-Sandbox-01"
  email     = "aws-sandbox-01@example.com"
  parent_id = aws_organizations_organizational_unit.sandbox.id

  role_name = "OrganizationAccountAccessRole"

  tags = {
    Purpose     = "Sandbox for POCs and Experiments"
    Environment = "sandbox"
  }
}

resource "aws_organizations_account" "sandbox_02" {
  name      = "ExampleCorp-Sandbox-02"
  email     = "aws-sandbox-02@example.com"
  parent_id = aws_organizations_organizational_unit.sandbox.id

  role_name = "OrganizationAccountAccessRole"

  tags = {
    Purpose     = "Sandbox for Training and Testing"
    Environment = "sandbox"
  }
}

# ===========================
# Outputs
# ===========================

output "organization_id" {
  description = "AWS Organization ID"
  value       = aws_organizations_organization.main.id
}

output "organization_arn" {
  description = "AWS Organization ARN"
  value       = aws_organizations_organization.main.arn
}

output "security_ou_id" {
  description = "Security OU ID"
  value       = aws_organizations_organizational_unit.security.id
}

output "production_ou_id" {
  description = "Production OU ID"
  value       = aws_organizations_organizational_unit.production.id
}

output "development_ou_id" {
  description = "Development OU ID"
  value       = aws_organizations_organizational_unit.development.id
}

output "sandbox_ou_id" {
  description = "Sandbox OU ID"
  value       = aws_organizations_organizational_unit.sandbox.id
}

output "log_archive_account_id" {
  description = "Log Archive account ID"
  value       = aws_organizations_account.log_archive.id
}

output "cde_account_id" {
  description = "CDE account ID (PCI DSS in-scope)"
  value       = aws_organizations_account.cde.id
}

output "account_ids" {
  description = "Map of all account names to IDs"
  value = {
    log_archive       = aws_organizations_account.log_archive.id
    security_audit    = aws_organizations_account.security_audit.id
    security_tooling  = aws_organizations_account.security_tooling.id
    prod_app          = aws_organizations_account.prod_app.id
    prod_data         = aws_organizations_account.prod_data.id
    cde               = aws_organizations_account.cde.id
    dev_app           = aws_organizations_account.dev_app.id
    dev_data          = aws_organizations_account.dev_data.id
    staging           = aws_organizations_account.staging.id
    sandbox_01        = aws_organizations_account.sandbox_01.id
    sandbox_02        = aws_organizations_account.sandbox_02.id
  }
}
