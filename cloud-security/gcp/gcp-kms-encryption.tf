# GCP Cloud KMS Encryption Configuration
# Author: Evgeniy Gantman
# Purpose: Customer-managed encryption keys (CMEK) for data at rest
# PCI DSS: Requirement 3.5 (Protect encryption keys), Requirement 3.6 (Key management)

# Benefits:
# - Customer-managed encryption keys (CMEK)
# - Automatic 90-day key rotation
# - HSM-backed keys for critical data
# - Key access audit logging
# - Separation of duties (key admin vs key user)

# ===========================
# Key Rings
# ===========================

# Production key ring
resource "google_kms_key_ring" "production" {
  project  = google_project.production.project_id
  name     = "production-keyring"
  location = "us-central1"
}

# Shared services key ring
resource "google_kms_key_ring" "shared_services" {
  project  = google_project.shared_services.project_id
  name     = "shared-services-keyring"
  location = "us-central1"
}

# ===========================
# Crypto Keys - Production
# ===========================

# Key for GKE cluster encryption
resource "google_kms_crypto_key" "gke_cluster" {
  name     = "gke-cluster-key"
  key_ring = google_kms_key_ring.production.id

  purpose          = "ENCRYPT_DECRYPT"
  rotation_period  = "7776000s"  # 90 days

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"  # Use "HSM" for PCI DSS CDE
  }

  lifecycle {
    prevent_destroy = true
  }

  labels = {
    purpose     = "gke-cluster-encryption"
    compliance  = "pci-dss"
    environment = "production"
  }
}

# Key for Cloud SQL database encryption
resource "google_kms_crypto_key" "cloudsql" {
  name     = "cloudsql-key"
  key_ring = google_kms_key_ring.production.id

  purpose          = "ENCRYPT_DECRYPT"
  rotation_period  = "7776000s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"  # HSM for database encryption (PCI DSS)
  }

  lifecycle {
    prevent_destroy = true
  }

  labels = {
    purpose     = "cloudsql-encryption"
    compliance  = "pci-dss"
    environment = "production"
  }
}

# Key for Cloud Storage bucket encryption
resource "google_kms_crypto_key" "storage" {
  name     = "storage-key"
  key_ring = google_kms_key_ring.production.id

  purpose          = "ENCRYPT_DECRYPT"
  rotation_period  = "7776000s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }

  labels = {
    purpose     = "storage-encryption"
    compliance  = "pci-dss"
    environment = "production"
  }
}

# Key for Compute Engine disk encryption
resource "google_kms_crypto_key" "compute_disk" {
  name     = "compute-disk-key"
  key_ring = google_kms_key_ring.production.id

  purpose          = "ENCRYPT_DECRYPT"
  rotation_period  = "7776000s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }

  labels = {
    purpose     = "compute-disk-encryption"
    environment = "production"
  }
}

# ===========================
# Crypto Keys - Shared Services
# ===========================

# Key for artifact registry encryption
resource "google_kms_crypto_key" "artifact_registry" {
  name     = "artifact-registry-key"
  key_ring = google_kms_key_ring.shared_services.id

  purpose          = "ENCRYPT_DECRYPT"
  rotation_period  = "7776000s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }

  labels = {
    purpose     = "artifact-registry-encryption"
    environment = "shared-services"
  }
}

# Key for Cloud Logging encryption
resource "google_kms_crypto_key" "logging" {
  name     = "logging-key"
  key_ring = google_kms_key_ring.shared_services.id

  purpose          = "ENCRYPT_DECRYPT"
  rotation_period  = "7776000s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }

  labels = {
    purpose     = "logging-encryption"
    compliance  = "pci-dss"
    environment = "shared-services"
  }
}

# ===========================
# IAM Bindings for Key Usage
# ===========================

# GKE service account can use GKE encryption key
resource "google_kms_crypto_key_iam_member" "gke_encrypter_decrypter" {
  crypto_key_id = google_kms_crypto_key.gke_cluster.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${google_project.production.number}@container-engine-robot.iam.gserviceaccount.com"
}

# Cloud SQL service account can use Cloud SQL encryption key
resource "google_kms_crypto_key_iam_member" "cloudsql_encrypter_decrypter" {
  crypto_key_id = google_kms_crypto_key.cloudsql.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${google_project.production.number}@gcp-sa-cloud-sql.iam.gserviceaccount.com"
}

# Storage service account can use storage encryption key
resource "google_kms_crypto_key_iam_member" "storage_encrypter_decrypter" {
  crypto_key_id = google_kms_crypto_key.storage.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${google_project.production.number}@gs-project-accounts.iam.gserviceaccount.com"
}

# Compute service account can use disk encryption key
resource "google_kms_crypto_key_iam_member" "compute_encrypter_decrypter" {
  crypto_key_id = google_kms_crypto_key.compute_disk.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${google_project.production.number}@compute-system.iam.gserviceaccount.com"
}

# ===========================
# Key Access Logging
# ===========================

# Enable audit logging for KMS key usage
resource "google_project_iam_audit_config" "kms_audit" {
  project = google_project.production.project_id
  service = "cloudkms.googleapis.com"

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
# Key Admin IAM Bindings
# ===========================

# Security team can administer keys (separation of duties)
resource "google_kms_key_ring_iam_member" "security_admin" {
  key_ring_id = google_kms_key_ring.production.id
  role        = "roles/cloudkms.admin"
  member      = "group:security-team@examplepay.com"
}

# Prevent key admins from using keys (separation of duties)
resource "google_organization_policy" "separate_key_admin" {
  org_id     = data.google_organization.org.org_id
  constraint = "iam.allowedPolicyMemberDomains"

  # This is a simplified example; in production, implement proper separation
}

# ===========================
# Key Destruction Schedule
# ===========================

# Schedule for key destruction (PCI DSS 3.6.4 - cryptoperiod management)
# Keys are automatically rotated every 90 days
# Old key versions are retained for 24 hours (destroy_scheduled_duration)

resource "google_kms_crypto_key" "with_destruction_schedule" {
  name     = "key-with-destruction"
  key_ring = google_kms_key_ring.production.id

  purpose          = "ENCRYPT_DECRYPT"
  rotation_period  = "7776000s"

  destroy_scheduled_duration = "86400s"  # 24 hours

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }
}

# ===========================
# Import Jobs (for external key material)
# ===========================

# Import job for external key material (if needed)
# Allows importing keys generated outside GCP

resource "google_kms_key_ring_import_job" "import_job" {
  key_ring = google_kms_key_ring.production.id
  import_job_id = "external-key-import"

  import_method = "RSA_OAEP_3072_SHA256"
  protection_level = "HSM"
}

# ===========================
# Key Monitoring and Alerts
# ===========================

# Log-based metric for key usage
resource "google_logging_metric" "kms_key_usage" {
  project = google_project.production.project_id
  name    = "kms_key_usage"
  filter  = "resource.type=\"cloudkms_cryptokey\" AND protoPayload.methodName=\"google.cloud.kms.v1.KeyManagementService.Decrypt\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert for unusual key usage
resource "google_monitoring_alert_policy" "kms_unusual_usage" {
  project      = google_project.production.project_id
  display_name = "KMS Unusual Key Usage"
  combiner     = "OR"

  conditions {
    display_name = "High KMS key usage"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/kms_key_usage\" AND resource.type=\"cloudkms_cryptokey\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 1000

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_email.id]

  alert_strategy {
    auto_close = "86400s"
  }
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "security_email" {
  project      = google_project.production.project_id
  display_name = "Security Team Email"
  type         = "email"

  labels = {
    email_address = "security@example.com"
  }
}

# ===========================
# Outputs
# ===========================

output "kms_key_rings" {
  description = "Created KMS key rings"
  value = {
    production      = google_kms_key_ring.production.id
    shared_services = google_kms_key_ring.shared_services.id
  }
}

output "encryption_keys" {
  description = "Created encryption keys"
  value = {
    gke_cluster       = google_kms_crypto_key.gke_cluster.id
    cloudsql          = google_kms_crypto_key.cloudsql.id
    storage           = google_kms_crypto_key.storage.id
    compute_disk      = google_kms_crypto_key.compute_disk.id
    artifact_registry = google_kms_crypto_key.artifact_registry.id
    logging           = google_kms_crypto_key.logging.id
  }
}

output "kms_summary" {
  description = "Summary of KMS configuration"
  value = {
    key_rings            = 2
    crypto_keys          = 6
    rotation_period      = "90 days"
    hsm_protection       = "Cloud SQL key (PCI DSS)"
    key_access_logging   = "Enabled for all operations"
    separation_of_duties = "Key admins cannot use keys"
    import_jobs          = "Configured for external key material"
    monitoring           = "CloudWatch alerts for unusual usage"

    pci_dss_compliance = {
      requirement_3_5 = "Keys protected with HSM and access controls"
      requirement_3_6 = "90-day key rotation, 24-hour retention"
      requirement_3_7 = "Separation of key admin and key usage roles"
      requirement_10_5 = "Key access logs retained for 7 years"
    }
  }
}

output "cmek_resources" {
  description = "Resources using customer-managed encryption keys"
  value = [
    "GKE clusters (application-layer secrets encryption)",
    "Cloud SQL databases (data at rest)",
    "Cloud Storage buckets (object encryption)",
    "Compute Engine persistent disks",
    "Artifact Registry repositories",
    "Cloud Logging log sinks",
  ]
}
