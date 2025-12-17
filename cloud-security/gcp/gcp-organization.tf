# GCP Organization and Project Structure
# Author: Evgeniy Gantman
# Purpose: Multi-cloud architecture with GCP as secondary cloud
# PCI DSS: Requirement 2.2 (Configuration standards)

# GCP Organization provides:
# - Centralized policy enforcement
# - Hierarchical resource management
# - Unified billing and IAM
# - Folder-based isolation

# ===========================
# Organization Configuration
# ===========================

# Get organization data
data "google_organization" "org" {
  domain = var.organization_domain
}

# ===========================
# Folder Structure
# ===========================

# Top-level folders for environment separation
resource "google_folder" "production" {
  display_name = "Production"
  parent       = data.google_organization.org.name
}

resource "google_folder" "development" {
  display_name = "Development"
  parent       = data.google_organization.org.name
}

resource "google_folder" "shared_services" {
  display_name = "Shared Services"
  parent       = data.google_organization.org.name
}

# ===========================
# Projects
# ===========================

# Production project
resource "google_project" "production" {
  name            = "ExamplePay Production"
  project_id      = "examplepay-prod-gcp"
  folder_id       = google_folder.production.id
  billing_account = var.billing_account_id

  labels = {
    environment = "production"
    compliance  = "pci-dss"
    cost-center = "engineering"
  }
}

# Development project
resource "google_project" "development" {
  name            = "ExamplePay Development"
  project_id      = "examplepay-dev-gcp"
  folder_id       = google_folder.development.id
  billing_account = var.billing_account_id

  labels = {
    environment = "development"
    cost-center = "engineering"
  }
}

# Shared services project
resource "google_project" "shared_services" {
  name            = "ExamplePay Shared Services"
  project_id      = "examplepay-shared-gcp"
  folder_id       = google_folder.shared_services.id
  billing_account = var.billing_account_id

  labels = {
    environment = "shared"
    purpose     = "ci-cd-logging-monitoring"
    cost-center = "engineering"
  }
}

# ===========================
# Enable APIs
# ===========================

# Enable required APIs for production project
resource "google_project_service" "production_apis" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
    "cloudkms.googleapis.com",
    "securitycenter.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
  ])

  project = google_project.production.project_id
  service = each.value

  disable_on_destroy = false
}

# Enable required APIs for development project
resource "google_project_service" "development_apis" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
  ])

  project = google_project.development.project_id
  service = each.value

  disable_on_destroy = false
}

# Enable required APIs for shared services
resource "google_project_service" "shared_apis" {
  for_each = toset([
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "cloudkms.googleapis.com",
  ])

  project = google_project.shared_services.project_id
  service = each.value

  disable_on_destroy = false
}

# ===========================
# Organization Policies
# ===========================

# Require OS Login for all compute instances
resource "google_organization_policy" "require_os_login" {
  org_id     = data.google_organization.org.org_id
  constraint = "compute.requireOsLogin"

  boolean_policy {
    enforced = true
  }
}

# Require Shielded VMs (secure boot, vTPM, integrity monitoring)
resource "google_organization_policy" "require_shielded_vm" {
  org_id     = data.google_organization.org.org_id
  constraint = "compute.requireShieldedVm"

  boolean_policy {
    enforced = true
  }
}

# Disable serial port access (security risk)
resource "google_organization_policy" "disable_serial_port" {
  org_id     = data.google_organization.org.org_id
  constraint = "compute.disableSerialPortAccess"

  boolean_policy {
    enforced = true
  }
}

# Disable nested virtualization (security risk)
resource "google_organization_policy" "disable_nested_virtualization" {
  org_id     = data.google_organization.org.org_id
  constraint = "compute.disableNestedVirtualization"

  boolean_policy {
    enforced = true
  }
}

# Restrict VPC peering to prevent unauthorized data access
resource "google_organization_policy" "restrict_vpc_peering" {
  org_id     = data.google_organization.org.org_id
  constraint = "compute.restrictVpcPeering"

  list_policy {
    allow {
      values = [
        "projects/${google_project.production.project_id}",
        "projects/${google_project.shared_services.project_id}",
      ]
    }
  }
}

# Disable service account key creation (use Workload Identity instead)
resource "google_organization_policy" "disable_sa_key_creation" {
  org_id     = data.google_organization.org.org_id
  constraint = "iam.disableServiceAccountKeyCreation"

  boolean_policy {
    enforced = true
  }
}

# Restrict allowed IAM policy member domains (corporate only)
resource "google_organization_policy" "allowed_policy_member_domains" {
  org_id     = data.google_organization.org.org_id
  constraint = "iam.allowedPolicyMemberDomains"

  list_policy {
    allow {
      values = [
        "examplepay.com",
        "C01234567",  # Google Workspace customer ID
      ]
    }
  }
}

# Enforce uniform bucket-level access (disable ACLs)
resource "google_organization_policy" "uniform_bucket_access" {
  org_id     = data.google_organization.org.org_id
  constraint = "storage.uniformBucketLevelAccess"

  boolean_policy {
    enforced = true
  }
}

# Restrict resource locations (data residency)
resource "google_organization_policy" "restrict_resource_locations" {
  org_id     = data.google_organization.org.org_id
  constraint = "gcp.resourceLocations"

  list_policy {
    allow {
      values = [
        "in:us-locations",  # US regions only (PCI DSS data residency)
      ]
    }
  }
}

# ===========================
# Budget Alerts
# ===========================

# Budget alert for production project
resource "google_billing_budget" "production" {
  billing_account = var.billing_account_id
  display_name    = "Production Project Budget"

  budget_filter {
    projects = ["projects/${google_project.production.number}"]
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = "500"  # $500/month budget
    }
  }

  threshold_rules {
    threshold_percent = 0.5  # Alert at 50%
  }

  threshold_rules {
    threshold_percent = 0.9  # Alert at 90%
  }

  threshold_rules {
    threshold_percent = 1.0  # Alert at 100%
  }

  all_updates_rule {
    pubsub_topic = google_pubsub_topic.budget_alerts.id
  }
}

# Pub/Sub topic for budget alerts
resource "google_pubsub_topic" "budget_alerts" {
  project = google_project.shared_services.project_id
  name    = "budget-alerts"

  labels = {
    purpose = "budget-alerting"
  }

  depends_on = [google_project_service.shared_apis]
}

# ===========================
# Audit Logging
# ===========================

# Organization-level audit logging configuration
resource "google_organization_iam_audit_config" "org_audit" {
  org_id  = data.google_organization.org.org_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# ===========================
# Essential Contacts
# ===========================

# Essential contacts for security notifications
resource "google_essential_contacts_contact" "security" {
  parent                              = data.google_organization.org.name
  email                               = "security@example.com"
  language_tag                        = "en-US"
  notification_category_subscriptions = ["SECURITY", "SUSPENSION"]
}

resource "google_essential_contacts_contact" "technical" {
  parent                              = data.google_organization.org.name
  email                               = "devops@example.com"
  language_tag                        = "en-US"
  notification_category_subscriptions = ["TECHNICAL"]
}

# ===========================
# Variables
# ===========================

variable "organization_domain" {
  description = "GCP Organization domain"
  type        = string
  default     = "examplepay.com"
}

variable "billing_account_id" {
  description = "GCP Billing Account ID"
  type        = string
}

# ===========================
# Outputs
# ===========================

output "organization_id" {
  description = "GCP Organization ID"
  value       = data.google_organization.org.org_id
}

output "projects" {
  description = "Created GCP projects"
  value = {
    production      = google_project.production.project_id
    development     = google_project.development.project_id
    shared_services = google_project.shared_services.project_id
  }
}

output "folders" {
  description = "Created folders"
  value = {
    production      = google_folder.production.id
    development     = google_folder.development.id
    shared_services = google_folder.shared_services.id
  }
}

output "organization_policies" {
  description = "Enforced organization policies"
  value = [
    "compute.requireOsLogin",
    "compute.requireShieldedVm",
    "compute.disableSerialPortAccess",
    "compute.disableNestedVirtualization",
    "compute.restrictVpcPeering",
    "iam.disableServiceAccountKeyCreation",
    "iam.allowedPolicyMemberDomains",
    "storage.uniformBucketLevelAccess",
    "gcp.resourceLocations (US only)",
  ]
}

output "gcp_organization_summary" {
  description = "Summary of GCP organization configuration"
  value = {
    domain           = var.organization_domain
    projects         = 3
    folders          = 3
    org_policies     = 9
    budget_limit     = "$500/month per project"
    audit_logging    = "Enabled for all services"
    data_residency   = "US regions only"
    security_contact = "security@example.com"
  }
}
