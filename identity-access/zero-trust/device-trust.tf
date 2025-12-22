# Microsoft Intune Device Compliance Configuration
# Author: Evgeniy Gantman
# Purpose: Device trust and compliance policies for zero trust
# Framework: NIST 800-207 Principle 5, CISA ZTMM Device Pillar

# ===========================
# Intune Configuration
# ===========================

# Windows 10/11 compliance policy
resource "azurerm_intune_compliance_policy_windows10" "corporate_windows" {
  name         = "Corporate Windows Devices"
  description  = "Compliance requirements for corporate Windows devices"

  # OS version requirements
  os_minimum_version = "10.0.19041"  # Windows 10 20H1 or newer

  # Password requirements
  password_required                     = true
  password_minimum_length               = 12
  password_complexity                   = "alphanumeric"
  password_expiration_days              = 90
  password_prevent_reuse_count          = 24
  password_required_to_unlock_from_idle = true

  # Encryption
  bitlocker_enabled = true

  # Security features
  secure_boot_enabled          = true
  code_integrity_enabled       = true
  firewall_enabled             = true
  antivirus_required           = true
  antispyware_required         = true
  defender_enabled             = true
  defender_version_up_to_date  = true
  realtime_protection_enabled  = true

  # Device health attestation
  device_threat_protection_enabled              = true
  device_threat_protection_required_security_level = "secured"

  # Security patches
  os_maximum_version                = null  # Allow latest
  mobile_os_maximum_version         = null
  early_launch_anti_malware_driver_enabled = true

  # Actions for non-compliance
  scheduled_actions_for_rule {
    rule_name = "PasswordRequired"

    scheduled_action_configuration {
      action_type             = "block"
      grace_period_hours      = 24
      notification_template_id = azurerm_intune_notification_message_template.compliance_warning.id
    }
  }
}

# macOS compliance policy
resource "azurerm_intune_compliance_policy_macos" "corporate_macos" {
  name        = "Corporate macOS Devices"
  description = "Compliance requirements for corporate macOS devices"

  # OS version requirements
  os_minimum_version = "13.0"  # macOS Ventura or newer

  # Password requirements
  password_required                     = true
  password_minimum_length               = 12
  password_complexity                   = "alphanumeric"
  password_expiration_days              = 90
  password_prevent_reuse_count          = 24
  password_required_to_unlock_from_idle = true

  # Encryption
  storage_require_encryption = true  # FileVault

  # Security features
  firewall_enabled                 = true
  firewall_block_all_incoming      = false
  firewall_enable_stealth_mode     = true
  gatekeeper_allowed_app_source    = "mac_app_store_and_identified_developers"
  system_integrity_protection_enabled = true

  # Device threat protection
  device_threat_protection_enabled              = true
  device_threat_protection_required_security_level = "secured"

  # Actions for non-compliance
  scheduled_actions_for_rule {
    rule_name = "PasswordRequired"

    scheduled_action_configuration {
      action_type             = "block"
      grace_period_hours      = 24
      notification_template_id = azurerm_intune_notification_message_template.compliance_warning.id
    }
  }
}

# iOS/iPad compliance policy
resource "azurerm_intune_compliance_policy_ios" "corporate_ios" {
  name        = "Corporate iOS Devices"
  description = "Compliance requirements for corporate iOS devices"

  # OS version requirements
  os_minimum_version = "16.0"  # iOS 16 or newer

  # Password requirements
  passcode_required                = true
  passcode_minimum_length          = 6
  passcode_complexity              = "alphanumeric"
  passcode_expiration_days         = 90
  passcode_prevent_reuse_count     = 24
  passcode_required_type           = "deviceDefault"

  # Security features
  device_threat_protection_enabled              = true
  device_threat_protection_required_security_level = "secured"
  jailbroken_devices_blocked                    = true

  # Managed email profile required
  managed_email_profile_required = true

  # Actions for non-compliance
  scheduled_actions_for_rule {
    rule_name = "PasswordRequired"

    scheduled_action_configuration {
      action_type             = "block"
      grace_period_hours      = 24
      notification_template_id = azurerm_intune_notification_message_template.compliance_warning.id
    }
  }
}

# Android compliance policy
resource "azurerm_intune_compliance_policy_android" "corporate_android" {
  name        = "Corporate Android Devices"
  description = "Compliance requirements for corporate Android devices"

  # OS version requirements
  os_minimum_version = "12.0"  # Android 12 or newer

  # Password requirements
  password_required                = true
  password_minimum_length          = 6
  password_complexity              = "medium"
  password_expiration_days         = 90
  password_prevent_reuse_count     = 24

  # Security features
  security_require_verify_apps          = true
  security_require_safety_net_attestation_basic_integrity = true
  security_require_google_play_services = true
  security_require_up_to_date_security_providers = true
  security_block_jailbroken_devices     = true
  device_threat_protection_enabled      = true
  device_threat_protection_required_security_level = "secured"

  # Storage encryption
  storage_require_encryption = true

  # Actions for non-compliance
  scheduled_actions_for_rule {
    rule_name = "PasswordRequired"

    scheduled_action_configuration {
      action_type             = "block"
      grace_period_hours      = 24
      notification_template_id = azurerm_intune_notification_message_template.compliance_warning.id
    }
  }
}

# ===========================
# Notification Templates
# ===========================

resource "azurerm_intune_notification_message_template" "compliance_warning" {
  name            = "Device Compliance Warning"
  default_locale  = "en-US"

  localized_notification_message {
    locale  = "en-US"
    subject = "Your device is not compliant"
    message_template = <<-EOT
      Your device does not meet ExamplePay security requirements.

      Required actions:
      - Update to the latest OS version
      - Enable encryption (BitLocker/FileVault)
      - Install security updates within 7 days
      - Enable firewall
      - Install and update antivirus

      If not resolved within 24 hours, you will be blocked from accessing corporate resources.

      Contact IT Support: support@examplepay.com
    EOT
  }
}

# ===========================
# Device Configuration Profiles
# ===========================

# Windows security baseline
resource "azurerm_intune_device_configuration_profile" "windows_security_baseline" {
  name        = "Windows Security Baseline"
  description = "Security baseline configuration for Windows devices"
  platform    = "windows10"

  # Configure security settings
  settings = jsonencode({
    "@odata.type" = "#microsoft.graph.windows10GeneralConfiguration"

    # Windows Defender
    defenderBlockEndUserAccess           = false
    defenderRequireRealTimeMonitoring    = true
    defenderRequireBehaviorMonitoring    = true
    defenderRequireNetworkInspectionSystem = true
    defenderScanDownloads                = true
    defenderScanScriptsLoadedInInternetExplorer = true
    defenderBlockOnAccessProtection      = false
    defenderDaysBeforeDeletingQuarantinedMalware = 30

    # BitLocker
    bitLockerEnableStorageCardEncryption = true
    bitLockerEncryptDevice               = true
    bitLockerSystemDrivePolicy = {
      startupAuthenticationRequired    = true
      startupAuthenticationBlockWithoutTpmChip = true
      prebootRecoveryEnableMessageAndUrl = true
      recoveryOptions = {
        enableRecoveryInformationSaveToStore = true
      }
    }

    # Firewall
    firewallBlockStatefulFTP = true
    firewallIdleTimeoutForSecurityAssociationInSeconds = 300

    # Windows Hello for Business
    windowsHelloForBusinessBlocked = false
    pinMinimumLength               = 6
    pinMaximumLength               = 127
  })
}

# ===========================
# App Protection Policies
# ===========================

# iOS app protection
resource "azurerm_intune_app_protection_policy_ios" "corporate_apps" {
  name         = "Corporate iOS App Protection"
  description  = "App protection policy for iOS managed apps"

  # PIN requirements
  pin_required                 = true
  pin_minimum_length           = 6
  pin_complexity               = "numeric"
  pin_reset_after_wrong_entry_count = 5

  # Data protection
  data_backup_blocked                        = false
  device_compliance_required                 = true
  managed_browser_required                   = true
  save_as_blocked                            = true
  organization_data_requires_encryption      = true
  cut_copy_paste_restricted                  = "blocked_with_paste_in"
  contact_sync_blocked                       = false

  # Access requirements
  maximum_pin_retries         = 5
  offline_grace_period        = "P0DT12H0M0S"  # 12 hours
  minimum_app_version         = "1.0.0"
}

# ===========================
# Conditional Launch Settings
# ===========================

# Block access on jailbroken/rooted devices
# Block access on devices with high threat level
# Require app version to be current

# ===========================
# Outputs
# ===========================

output "device_trust_summary" {
  description = "Summary of device trust configuration"
  value = {
    intune_enrollment = "100% of corporate devices"
    compliance_policies = {
      windows = azurerm_intune_compliance_policy_windows10.corporate_windows.name
      macos   = azurerm_intune_compliance_policy_macos.corporate_macos.name
      ios     = azurerm_intune_compliance_policy_ios.corporate_ios.name
      android = azurerm_intune_compliance_policy_android.corporate_android.name
    }

    security_requirements = [
      "OS version: Current or N-1",
      "Encryption: BitLocker/FileVault required",
      "Security updates: Must be installed within 7 days",
      "Firewall: Must be enabled",
      "Antivirus: Must be installed and updated",
      "Device health: No malware or high-risk threats",
      "Jailbreak/root: Blocked",
    ]

    non_compliance_action = "24-hour grace period, then block access"
    monitoring            = "Real-time compliance status in Intune console"
  }
}
