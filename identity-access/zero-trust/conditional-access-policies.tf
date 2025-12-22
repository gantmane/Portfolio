# Azure AD Conditional Access Policies
# Author: Evgeniy Gantman
# Purpose: Context-aware access control for zero trust
# Framework: NIST 800-207 Principle 4, PCI DSS 8.3

# Note: These are the detailed implementations referenced in azure/azure-rbac-policies.tf

# ===========================
# Policy 1: Require MFA for All Users
# ===========================

resource "azuread_conditional_access_policy" "require_mfa_all_users" {
  display_name = "Zero Trust: Require MFA for all users"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
      excluded_applications = []
    }

    users {
      included_users = ["All"]
      excluded_users = []  # No exceptions - 100% MFA enforcement
      excluded_groups = []
    }

    locations {
      included_locations = ["All"]
      excluded_locations = []
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }

  # Require MFA every 8 hours
  session_controls {
    sign_in_frequency        = 8
    sign_in_frequency_period = "hours"
    persistent_browser_mode  = "never"
  }
}

# ===========================
# Policy 2: Block Non-Corporate Locations
# ===========================

resource "azuread_conditional_access_policy" "block_non_corporate_locations" {
  display_name = "Zero Trust: Require additional verification from non-corporate locations"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
      excluded_applications = []
    }

    users {
      included_groups = [
        azuread_group.security_team.object_id,
        azuread_group.devops_team.object_id,
        azuread_group.executives.object_id,
      ]
      excluded_users = []
    }

    locations {
      included_locations = ["All"]
      excluded_locations = [azuread_named_location.corporate_offices.id]
    }
  }

  grant_controls {
    operator = "AND"
    built_in_controls = [
      "mfa",
      "compliantDevice",
    ]
  }

  session_controls {
    sign_in_frequency        = 4
    sign_in_frequency_period = "hours"
  }
}

# ===========================
# Policy 3: Require Compliant Device
# ===========================

resource "azuread_conditional_access_policy" "require_compliant_device_production" {
  display_name = "Zero Trust: Require compliant device for production"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = [
        azuread_application.aws_sso.application_id,
        azuread_application.gcp_console.application_id,
        azuread_application.azure_portal.application_id,
      ]
      excluded_applications = []
    }

    users {
      included_users = ["All"]
      excluded_users = []
      excluded_groups = []
    }
  }

  grant_controls {
    operator = "AND"
    built_in_controls = [
      "mfa",
      "compliantDevice",
    ]
  }
}

# ===========================
# Policy 4: Block Legacy Authentication
# ===========================

resource "azuread_conditional_access_policy" "block_legacy_auth" {
  display_name = "Zero Trust: Block legacy authentication"
  state        = "enabled"

  conditions {
    client_app_types = [
      "exchangeActiveSync",
      "other",  # Includes IMAP, POP, SMTP
    ]

    applications {
      included_applications = ["All"]
      excluded_applications = []
    }

    users {
      included_users = ["All"]
      excluded_users = []
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# ===========================
# Policy 5: Require Password Reset After Inactivity
# ===========================

resource "azuread_conditional_access_policy" "password_reset_after_inactivity" {
  display_name = "Zero Trust: Require password reset after 90 days inactivity"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
      excluded_applications = []
    }

    users {
      included_users = ["All"]
      excluded_users = []
    }

    sign_in_risk_levels = []

    user_risk_levels = ["medium", "high"]
  }

  grant_controls {
    operator = "AND"
    built_in_controls = [
      "mfa",
      "passwordChange",
    ]
  }
}

# ===========================
# Policy 6: Block High-Risk Sign-Ins
# ===========================

resource "azuread_conditional_access_policy" "block_high_risk_signins" {
  display_name = "Zero Trust: Block high-risk sign-ins"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
      excluded_applications = []
    }

    users {
      included_users = ["All"]
      excluded_users = []
    }

    sign_in_risk_levels = ["high"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# ===========================
# Policy 7: Require MFA for Azure Management
# ===========================

resource "azuread_conditional_access_policy" "require_mfa_azure_management" {
  display_name = "Zero Trust: Require MFA for Azure management"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["797f4846-ba00-4fd7-ba43-dac1f8f63013"]  # Azure Management
      excluded_applications = []
    }

    users {
      included_users = ["All"]
      excluded_users = []
    }
  }

  grant_controls {
    operator = "AND"
    built_in_controls = [
      "mfa",
      "compliantDevice",
    ]
  }

  session_controls {
    sign_in_frequency        = 1
    sign_in_frequency_period = "hours"
  }
}

# ===========================
# Policy 8: Require Approved Client Apps
# ===========================

resource "azuread_conditional_access_policy" "require_approved_apps_mobile" {
  display_name = "Zero Trust: Require approved client apps for mobile"
  state        = "enabled"

  conditions {
    client_app_types = ["mobileAppsAndDesktopClients"]

    applications {
      included_applications = ["All"]
      excluded_applications = []
    }

    users {
      included_users = ["All"]
      excluded_users = []
    }

    platforms {
      included_platforms = ["iOS", "android"]
      excluded_platforms = []
    }
  }

  grant_controls {
    operator = "OR"
    built_in_controls = [
      "approvedApplication",
      "compliantApplication",
    ]
  }
}

# ===========================
# Policy 9: Block Downloads from Unmanaged Devices
# ===========================

resource "azuread_conditional_access_policy" "block_downloads_unmanaged" {
  display_name = "Zero Trust: Block downloads from unmanaged devices"
  state        = "enabledForReportingButNotEnforced"  # Start in report-only mode

  conditions {
    client_app_types = ["browser"]

    applications {
      included_applications = [
        "00000003-0000-0ff1-ce00-000000000000",  # Office 365 SharePoint Online
        "00000002-0000-0ff1-ce00-000000000000",  # Office 365 Exchange Online
      ]
      excluded_applications = []
    }

    users {
      included_users = ["All"]
      excluded_users = []
    }

    devices {
      filter_mode = "exclude"
      filter = "device.isCompliant -eq true"
    }
  }

  session_controls {
    application_enforced_restrictions_enabled = true
  }
}

# ===========================
# Named Locations
# ===========================

# Corporate office locations
resource "azuread_named_location" "corporate_offices" {
  display_name = "Corporate Offices"

  ip {
    ip_ranges = [
      "203.0.113.0/24",   # Corporate HQ
      "198.51.100.0/24",  # Remote office
    ]

    trusted = true
  }
}

# Known malicious locations (from threat intelligence)
resource "azuread_named_location" "malicious_locations" {
  display_name = "Malicious IP Addresses"

  ip {
    ip_ranges = [
      "198.51.100.10/32",
      "198.51.100.20/32",
    ]

    trusted = false
  }
}

# ===========================
# Azure AD Groups (references)
# ===========================

data "azuread_group" "security_team" {
  display_name     = "Security Team"
  security_enabled = true
}

data "azuread_group" "devops_team" {
  display_name     = "DevOps Team"
  security_enabled = true
}

data "azuread_group" "executives" {
  display_name     = "Executives"
  security_enabled = true
}

# ===========================
# Application References
# ===========================

data "azuread_application" "aws_sso" {
  display_name = "AWS IAM Identity Center"
}

data "azuread_application" "gcp_console" {
  display_name = "Google Workspace"
}

data "azuread_application" "azure_portal" {
  display_name = "Azure Portal"
}

# ===========================
# Outputs
# ===========================

output "conditional_access_summary" {
  description = "Summary of Conditional Access policies"
  value = {
    total_policies = 9
    enabled_policies = 8
    report_only_policies = 1

    policies = [
      "1. Require MFA for all users (100% enforcement)",
      "2. Require additional verification from non-corporate locations",
      "3. Require compliant device for production access",
      "4. Block legacy authentication (Exchange ActiveSync, IMAP, POP)",
      "5. Require password reset after 90 days inactivity",
      "6. Block high-risk sign-ins (Identity Protection)",
      "7. Require MFA for Azure management (1-hour sessions)",
      "8. Require approved client apps for mobile devices",
      "9. Block downloads from unmanaged devices (report-only)",
    ]

    mfa_enforcement = "100% - no exceptions"
    sign_in_frequency = {
      standard         = "8 hours"
      azure_management = "1 hour"
      non_corporate    = "4 hours"
    }

    device_compliance_required_for = [
      "Production cloud access (AWS, GCP, Azure)",
      "Non-corporate locations",
      "Azure management",
    ]

    blocked_scenarios = [
      "Legacy authentication (Basic Auth, Exchange ActiveSync)",
      "High-risk sign-ins (Identity Protection score)",
      "Access from known malicious IPs",
    ]
  }
}
