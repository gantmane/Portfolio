# GCP Security Command Center Configuration
# Author: Evgeniy Gantman
# Purpose: Centralized security monitoring and threat detection
# PCI DSS: Requirement 11.4 (Intrusion detection), Requirement 10.6 (Log review)

# Security Command Center provides:
# - Asset Discovery (inventory of all GCP resources)
# - Security Health Analytics (built-in security checks)
# - Event Threat Detection (anomaly detection)
# - Container Threat Detection (GKE security scanning)
# - Web Security Scanner (vulnerability scanning)

# ===========================
# Security Command Center Activation
# ===========================

# Note: Security Command Center must be activated via Console or gcloud CLI first
# gcloud services enable securitycenter.googleapis.com --project=org-123456789012

# Enable Security Command Center API
resource "google_project_service" "security_command_center" {
  project = google_project.production.project_id
  service = "securitycenter.googleapis.com"

  disable_on_destroy = false
}

# ===========================
# Security Health Analytics
# ===========================

# Security Health Analytics Custom Module (example: detect public buckets)
resource "google_scc_organization_custom_module" "public_bucket_detection" {
  organization = data.google_organization.org.org_id
  display_name = "Detect Public Cloud Storage Buckets"

  enablement_state = "ENABLED"

  custom_config {
    predicate {
      expression = <<-EOT
        resource.type == "storage.googleapis.com/Bucket" &&
        (resource.iamPolicy.bindings.exists(b, b.members.exists(m, m == "allUsers" || m == "allAuthenticatedUsers")))
      EOT

      title       = "Public Cloud Storage Bucket"
      description = "Detects Cloud Storage buckets with public access"

      recommendation = "Remove allUsers and allAuthenticatedUsers from IAM bindings"
    }

    resource_selector {
      resource_types = ["storage.googleapis.com/Bucket"]
    }

    severity = "HIGH"
  }
}

# Custom module for detecting compute instances without OS Login
resource "google_scc_organization_custom_module" "no_os_login" {
  organization = data.google_organization.org.org_id
  display_name = "Detect Compute Instances Without OS Login"

  enablement_state = "ENABLED"

  custom_config {
    predicate {
      expression = <<-EOT
        resource.type == "compute.googleapis.com/Instance" &&
        (!has(resource.metadata.items) ||
         !resource.metadata.items.exists(i, i.key == "enable-oslogin" && i.value == "TRUE"))
      EOT

      title       = "Compute Instance Without OS Login"
      description = "Detects compute instances that do not have OS Login enabled"

      recommendation = "Enable OS Login: gcloud compute instances add-metadata INSTANCE --metadata enable-oslogin=TRUE"
    }

    resource_selector {
      resource_types = ["compute.googleapis.com/Instance"]
    }

    severity = "MEDIUM"
  }
}

# ===========================
# Event Threat Detection
# ===========================

# Event Threat Detection is enabled automatically with Security Command Center Standard tier
# It detects:
# - Malware
# - Cryptomining
# - Data exfiltration
# - Brute force attempts
# - Phishing attempts

# ===========================
# Security Findings Notifications
# ===========================

# Pub/Sub topic for security findings
resource "google_pubsub_topic" "security_findings" {
  project = google_project.shared_services.project_id
  name    = "security-findings"

  labels = {
    purpose = "security-command-center-notifications"
  }
}

# Notification config for critical findings
resource "google_scc_notification_config" "critical_findings" {
  org_id       = data.google_organization.org.org_id
  config_id    = "critical-findings-notification"
  description  = "Notify on critical security findings"
  pubsub_topic = google_pubsub_topic.security_findings.id

  streaming_config {
    filter = "severity=\"CRITICAL\" AND state=\"ACTIVE\""
  }
}

# Notification config for high findings
resource "google_scc_notification_config" "high_findings" {
  org_id       = data.google_organization.org.org_id
  config_id    = "high-findings-notification"
  description  = "Notify on high severity security findings"
  pubsub_topic = google_pubsub_topic.security_findings.id

  streaming_config {
    filter = "severity=\"HIGH\" AND state=\"ACTIVE\""
  }
}

# ===========================
# Cloud Function for Finding Processing
# ===========================

# Cloud Function to process security findings and forward to Wazuh SIEM
resource "google_cloudfunctions_function" "process_security_findings" {
  project     = google_project.shared_services.project_id
  name        = "process-security-findings"
  description = "Process Security Command Center findings and forward to SIEM"
  runtime     = "python311"
  region      = "us-central1"

  available_memory_mb   = 256
  source_archive_bucket = google_storage_bucket.cloud_functions.name
  source_archive_object = "process-security-findings.zip"  # Placeholder
  entry_point           = "process_finding"

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.security_findings.id
  }

  environment_variables = {
    WAZUH_ENDPOINT = "https://wazuh.example.com/api"
    SEVERITY_THRESHOLD = "HIGH"
  }

  labels = {
    purpose = "siem-integration"
  }
}

# S3 bucket for Cloud Functions source code
resource "google_storage_bucket" "cloud_functions" {
  project  = google_project.shared_services.project_id
  name     = "examplepay-cloud-functions-${google_project.shared_services.number}"
  location = "US"

  uniform_bucket_level_access = true

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 90
    }
  }
}

# ===========================
# Container Threat Detection
# ===========================

# Container Threat Detection is automatically enabled for GKE clusters
# It detects:
# - Container escape attempts
# - Privilege escalation
# - Suspicious binary execution
# - Reverse shell creation

# ===========================
# Web Security Scanner
# ===========================

# Web Security Scanner configuration (for public web applications)
resource "google_security_scanner_scan_config" "production_web_app" {
  project     = google_project.production.project_id
  display_name = "Production Web Application Scan"

  starting_urls = ["https://www.examplepay.com/"]

  authentication {
    google_account {
      username = "scanner@examplepay.com"
      password = var.web_scanner_password
    }
  }

  # Scan schedule (weekly)
  schedule {
    schedule_time = "2024-01-01T02:00:00Z"
    interval_duration_days = 7
  }

  # Maximum QPS (queries per second)
  max_qps = 5

  # User agent for scanner
  user_agent = "CHROME_LINUX"

  # Export to Security Command Center
  export_to_security_command_center = "ENABLED"
}

# ===========================
# Security Findings Dashboard
# ===========================

# Cloud Monitoring dashboard for Security Command Center metrics
resource "google_monitoring_dashboard" "security_findings" {
  project        = google_project.shared_services.project_id
  dashboard_json = jsonencode({
    displayName = "Security Command Center Findings"
    mosaicLayout = {
      columns = 12
      tiles = [
        {
          width  = 6
          height = 4
          widget = {
            title = "Active Findings by Severity"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "resource.type=\"organization\""
                  }
                }
              }]
            }
          }
        },
        {
          width  = 6
          height = 4
          widget = {
            title = "Findings by Category"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "resource.type=\"organization\""
                  }
                }
              }]
            }
          }
        }
      ]
    }
  })
}

# ===========================
# Automated Remediation
# ===========================

# Example: Automated remediation for public buckets
# Cloud Function triggered by finding notification

resource "google_cloudfunctions_function" "remediate_public_bucket" {
  project     = google_project.shared_services.project_id
  name        = "remediate-public-bucket"
  description = "Automatically remove public access from Cloud Storage buckets"
  runtime     = "python311"
  region      = "us-central1"

  available_memory_mb   = 256
  source_archive_bucket = google_storage_bucket.cloud_functions.name
  source_archive_object = "remediate-public-bucket.zip"  # Placeholder
  entry_point           = "remediate"

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.security_findings.id
  }

  environment_variables = {
    DRY_RUN = "false"
  }

  labels = {
    purpose = "automated-remediation"
  }
}

# ===========================
# Security Findings Export
# ===========================

# Export findings to BigQuery for long-term analysis
resource "google_bigquery_dataset" "security_findings" {
  project    = google_project.shared_services.project_id
  dataset_id = "security_findings"
  location   = "US"

  default_table_expiration_ms = 7 * 365 * 24 * 60 * 60 * 1000  # 7 years

  labels = {
    purpose    = "security-findings-storage"
    compliance = "pci-dss-retention"
  }
}

# ===========================
# Variables
# ===========================

variable "web_scanner_password" {
  description = "Password for Web Security Scanner authentication"
  type        = string
  sensitive   = true
}

# ===========================
# Outputs
# ===========================

output "security_command_center_summary" {
  description = "Summary of Security Command Center configuration"
  value = {
    tier                       = "Standard (free)"
    asset_discovery            = "Enabled"
    security_health_analytics  = "Enabled (custom modules: 2)"
    event_threat_detection     = "Enabled"
    container_threat_detection = "Enabled for GKE"
    web_security_scanner       = "Enabled (weekly scans)"

    notifications = {
      critical_findings = "Pub/Sub + Cloud Function → Wazuh"
      high_findings     = "Pub/Sub + Cloud Function → Wazuh"
    }

    automated_remediation = [
      "Public bucket access removal",
    ]

    findings_retention = "7 years in BigQuery"
  }
}

output "detection_categories" {
  description = "Security findings detection categories"
  value = [
    "Malware",
    "Cryptomining",
    "Data exfiltration",
    "Brute force attempts",
    "Phishing",
    "Public resource exposure",
    "IAM misconfigurations",
    "Firewall misconfigurations",
    "Encryption disabled",
    "Logging disabled",
    "Container vulnerabilities",
    "Web application vulnerabilities",
  ]
}

output "integration_with_wazuh" {
  description = "Integration flow with Wazuh SIEM"
  value = {
    flow = "Security Command Center → Pub/Sub → Cloud Function → Wazuh API"
    correlation = "Cross-reference with AWS GuardDuty findings in unified SIEM"
    retention = "7 years (PCI DSS compliance)"
    alerting = "Critical/High findings trigger PagerDuty via Wazuh"
  }
}
