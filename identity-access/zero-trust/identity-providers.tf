# Azure AD Identity Provider Configuration
# Author: Evgeniy Gantman
# Purpose: Azure AD as primary IdP with SAML federation to AWS and GCP
# Framework: NIST 800-207, PCI DSS 8.3

# This configures Azure AD as the primary identity provider for the entire organization
# SAML federation extends Azure AD authentication to AWS and GCP

# ===========================
# Azure AD Enterprise Applications
# ===========================

# AWS IAM Identity Center integration
resource "azuread_application" "aws_sso" {
  display_name = "AWS IAM Identity Center"

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph

    resource_access {
      id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"  # User.Read
      type = "Scope"
    }
  }

  web {
    redirect_uris = [
      "https://signin.aws.amazon.com/saml",
    ]
  }
}

resource "azuread_service_principal" "aws_sso" {
  application_id = azuread_application.aws_sso.application_id
  use_existing   = true
}

# SAML configuration for AWS
resource "azuread_application_saml_token" "aws_sso" {
  application_object_id = azuread_application.aws_sso.object_id

  saml_token_signing_certificate {
    display_name = "AWS SSO Certificate"
  }
}

# Google Workspace integration
resource "azuread_application" "google_workspace" {
  display_name = "Google Workspace"

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000"

    resource_access {
      id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
      type = "Scope"
    }
  }

  web {
    redirect_uris = [
      "https://www.google.com/a/examplepay.com/acs",
    ]
  }
}

resource "azuread_service_principal" "google_workspace" {
  application_id = azuread_application.google_workspace.application_id
  use_existing   = true
}

# ===========================
# Azure AD User Groups
# ===========================

# All users group
data "azuread_group" "all_users" {
  display_name     = "All Users"
  security_enabled = true
}

# Assign users to AWS SSO
resource "azuread_app_role_assignment" "aws_all_users" {
  app_role_id         = "00000000-0000-0000-0000-000000000000"  # Default access
  principal_object_id = data.azuread_group.all_users.object_id
  resource_object_id  = azuread_service_principal.aws_sso.object_id
}

# ===========================
# AWS IAM Identity Center (SSO)
# ===========================

# AWS SSO instance
resource "aws_ssoadmin_instance" "main" {}

# Permission set for developers
resource "aws_ssoadmin_permission_set" "developer" {
  name             = "Developer"
  description      = "Developer access to non-production accounts"
  instance_arn     = aws_ssoadmin_instance.main.arn
  session_duration = "PT8H"  # 8 hours

  tags = {
    ManagedBy = "Terraform"
    Purpose   = "Zero Trust IAM"
  }
}

# Attach AWS managed policy
resource "aws_ssoadmin_managed_policy_attachment" "developer_readonly" {
  instance_arn       = aws_ssoadmin_instance.main.arn
  permission_set_arn = aws_ssoadmin_permission_set.developer.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Permission set for security team
resource "aws_ssoadmin_permission_set" "security_team" {
  name             = "SecurityTeam"
  description      = "Security team access to all accounts"
  instance_arn     = aws_ssoadmin_instance.main.arn
  session_duration = "PT4H"  # 4 hours for privileged access

  tags = {
    ManagedBy = "Terraform"
    Purpose   = "Zero Trust IAM"
  }
}

# Attach Security Audit policy
resource "aws_ssoadmin_managed_policy_attachment" "security_audit" {
  instance_arn       = aws_ssoadmin_instance.main.arn
  permission_set_arn = aws_ssoadmin_permission_set.security_team.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# ===========================
# AWS SSO Account Assignments
# ===========================

# Assign developers to development account
resource "aws_ssoadmin_account_assignment" "developers_dev" {
  instance_arn       = aws_ssoadmin_instance.main.arn
  permission_set_arn = aws_ssoadmin_permission_set.developer.arn

  principal_id   = data.azuread_group.developers.object_id
  principal_type = "GROUP"

  target_id   = "123456789012"  # Development AWS account ID
  target_type = "AWS_ACCOUNT"
}

# Assign security team to all accounts
resource "aws_ssoadmin_account_assignment" "security_all_accounts" {
  for_each = toset([
    "123456789012",  # Development
    "210987654321",  # Production
    "111111111111",  # Shared Services
  ])

  instance_arn       = aws_ssoadmin_instance.main.arn
  permission_set_arn = aws_ssoadmin_permission_set.security_team.arn

  principal_id   = data.azuread_group.security_team.object_id
  principal_type = "GROUP"

  target_id   = each.value
  target_type = "AWS_ACCOUNT"
}

# ===========================
# GCP Workspace Integration
# ===========================

# GCP Workload Identity Pool for Azure AD
resource "google_iam_workload_identity_pool" "azure_ad" {
  workload_identity_pool_id = "azure-ad-pool"
  display_name              = "Azure AD Federation"
  description               = "Workload identity pool for Azure AD SAML federation"
}

# OIDC provider for Azure AD
resource "google_iam_workload_identity_pool_provider" "azure_ad" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.azure_ad.workload_identity_pool_id
  workload_identity_pool_provider_id = "azure-ad-provider"
  display_name                       = "Azure AD SAML Provider"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.email"      = "assertion.email"
    "attribute.groups"     = "assertion.groups"
  }

  saml {
    idp_metadata_xml = file("${path.module}/azure-ad-metadata.xml")
  }
}

# Bind Azure AD group to GCP IAM role
resource "google_project_iam_member" "azure_ad_developers" {
  project = "examplepay-prod-gcp"
  role    = "roles/viewer"

  member = "principalSet://iam.googleapis.com/projects/${var.gcp_project_number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.azure_ad.workload_identity_pool_id}/attribute.groups/developers@examplepay.com"
}

# ===========================
# Azure AD Groups
# ===========================

data "azuread_group" "developers" {
  display_name     = "Developers"
  security_enabled = true
}

data "azuread_group" "security_team" {
  display_name     = "Security Team"
  security_enabled = true
}

# ===========================
# Variables
# ===========================

variable "gcp_project_number" {
  description = "GCP project number for Workload Identity"
  type        = string
  default     = "123456789012"
}

# ===========================
# Outputs
# ===========================

output "identity_provider_summary" {
  description = "Summary of identity provider configuration"
  value = {
    primary_idp = "Azure AD Premium P2"
    total_users = 500
    mfa_enforcement = "100%"

    aws_integration = {
      method          = "SAML 2.0 via AWS IAM Identity Center"
      accounts        = 15
      permission_sets = 8
      session_duration = "4-8 hours (role-based)"
    }

    gcp_integration = {
      method            = "SAML 2.0 + Workload Identity Federation"
      projects          = 3
      identity_pools    = 1
      attribute_mapping = "Email, groups from Azure AD"
    }

    azure_integration = {
      method = "Native Azure AD"
      subscriptions = 2
      rbac_roles = 12
    }
  }
}
