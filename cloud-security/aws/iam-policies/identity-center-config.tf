# IAM Identity Center (SSO) Configuration
# Author: Evgeniy Gantman
# Purpose: Configure IAM Identity Center permission sets and account assignments
# PCI DSS: Requirement 7 (Access Control), Requirement 8 (Authentication)

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Get IAM Identity Center instance
data "aws_ssoadmin_instances" "main" {}

# ===========================
# Permission Sets
# ===========================

# Administrator Permission Set
resource "aws_ssoadmin_permission_set" "administrator" {
  name             = "AdministratorAccess"
  description      = "Full administrative access (requires MFA)"
  instance_arn     = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  session_duration = "PT8H" # 8 hours

  tags = {
    Purpose = "Administrative Access"
    Risk    = "High"
  }
}

resource "aws_ssoadmin_managed_policy_attachment" "administrator" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.administrator.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Developer Permission Set
resource "aws_ssoadmin_permission_set" "developer" {
  name             = "DeveloperAccess"
  description      = "Developer access for non-production environments"
  instance_arn     = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  session_duration = "PT10H" # 10 hours

  tags = {
    Purpose = "Development"
  }
}

resource "aws_ssoadmin_customer_managed_policy_attachment" "developer" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.developer.arn

  customer_managed_policy_reference {
    name = "DeveloperPolicy"
    path = "/"
  }
}

# DevOps Engineer Permission Set
resource "aws_ssoadmin_permission_set" "devops" {
  name             = "DevOpsEngineer"
  description      = "DevOps engineer access for infrastructure and deployments"
  instance_arn     = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  session_duration = "PT8H"

  tags = {
    Purpose = "DevOps Engineering"
  }
}

resource "aws_ssoadmin_customer_managed_policy_attachment" "devops" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.devops.arn

  customer_managed_policy_reference {
    name = "DevOpsPolicy"
    path = "/"
  }
}

# ReadOnly Permission Set
resource "aws_ssoadmin_permission_set" "readonly" {
  name             = "ReadOnlyAccess"
  description      = "Read-only access for auditors and compliance teams"
  instance_arn     = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  session_duration = "PT4H"

  tags = {
    Purpose = "Auditing and Compliance"
  }
}

resource "aws_ssoadmin_customer_managed_policy_attachment" "readonly" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.readonly.arn

  customer_managed_policy_reference {
    name = "ReadOnlyPolicy"
    path = "/"
  }
}

# CDE Administrator Permission Set (PCI DSS)
resource "aws_ssoadmin_permission_set" "cde_admin" {
  name             = "CDEAdministrator"
  description      = "Administrator access for Cardholder Data Environment (PCI DSS)"
  instance_arn     = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  session_duration = "PT4H" # Limited to 4 hours for CDE

  tags = {
    Purpose  = "CDE Administration"
    PCIScope = "yes"
    Risk     = "Critical"
  }
}

resource "aws_ssoadmin_customer_managed_policy_attachment" "cde_admin" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.cde_admin.arn

  customer_managed_policy_reference {
    name = "CDEAdminPolicy"
    path = "/"
  }
}

# ===========================
# Account Assignments
# ===========================

variable "account_ids" {
  description = "Map of account names to IDs"
  type        = map(string)
  default = {
    prod_app = "222233334444"
    cde      = "444455556666"
    dev_app  = "333344445555"
  }
}

variable "sso_groups" {
  description = "Map of SSO group IDs"
  type        = map(string)
  default = {
    administrators = "xxxxxxxxx"
    developers     = "yyyyyyyyy"
    devops         = "zzzzzzzzz"
    auditors       = "aaaaaaaaa"
  }
}

# Assign ReadOnly to all accounts for auditors
resource "aws_ssoadmin_account_assignment" "auditors_readonly" {
  for_each = var.account_ids

  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.readonly.arn

  principal_id   = var.sso_groups["auditors"]
  principal_type = "GROUP"

  target_id   = each.value
  target_type = "AWS_ACCOUNT"
}

# Assign Developer access to dev account
resource "aws_ssoadmin_account_assignment" "developers_dev" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.developer.arn

  principal_id   = var.sso_groups["developers"]
  principal_type = "GROUP"

  target_id   = var.account_ids["dev_app"]
  target_type = "AWS_ACCOUNT"
}

# Assign DevOps to production (non-CDE)
resource "aws_ssoadmin_account_assignment" "devops_prod" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.devops.arn

  principal_id   = var.sso_groups["devops"]
  principal_type = "GROUP"

  target_id   = var.account_ids["prod_app"]
  target_type = "AWS_ACCOUNT"
}

# Assign CDE Admin to CDE account (limited group)
resource "aws_ssoadmin_account_assignment" "cde_admin" {
  instance_arn       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  permission_set_arn = aws_ssoadmin_permission_set.cde_admin.arn

  principal_id   = var.sso_groups["administrators"]
  principal_type = "GROUP"

  target_id   = var.account_ids["cde"]
  target_type = "AWS_ACCOUNT"
}

# ===========================
# Outputs
# ===========================

output "permission_set_arns" {
  description = "Map of permission set names to ARNs"
  value = {
    administrator = aws_ssoadmin_permission_set.administrator.arn
    developer     = aws_ssoadmin_permission_set.developer.arn
    devops        = aws_ssoadmin_permission_set.devops.arn
    readonly      = aws_ssoadmin_permission_set.readonly.arn
    cde_admin     = aws_ssoadmin_permission_set.cde_admin.arn
  }
}

output "sso_instance_arn" {
  description = "IAM Identity Center instance ARN"
  value       = tolist(data.aws_ssoadmin_instances.main.arns)[0]
}
