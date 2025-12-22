# Workload Identity Configuration
# Author: Evgeniy Gantman
# Purpose: Service account authentication across AWS, GCP, Azure
# Framework: NIST 800-207 Principle 6, PCI DSS 8.6

# ===========================
# AWS IAM Roles for Service Accounts (IRSA)
# ===========================

# OIDC provider for EKS cluster
resource "aws_iam_openid_connect_provider" "eks_oidc" {
  url = data.aws_eks_cluster.main.identity[0].oidc[0].issuer

  client_id_list = [
    "sts.amazonaws.com",
  ]

  thumbprint_list = [
    data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint,
  ]

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
    Purpose     = "Zero Trust Workload Identity"
  }
}

# IAM role for frontend service account
resource "aws_iam_role" "frontend_sa" {
  name = "eks-frontend-service-account"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.eks_oidc.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(aws_iam_openid_connect_provider.eks_oidc.url, "https://", "")}:sub" = "system:serviceaccount:production:frontend-sa"
          "${replace(aws_iam_openid_connect_provider.eks_oidc.url, "https://", "")}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  tags = {
    ServiceAccount = "frontend-sa"
    Namespace      = "production"
    ManagedBy      = "Terraform"
  }
}

# IAM policy for frontend (read S3 assets)
resource "aws_iam_role_policy_attachment" "frontend_s3_readonly" {
  role       = aws_iam_role.frontend_sa.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# IAM role for backend service account
resource "aws_iam_role" "backend_sa" {
  name = "eks-backend-service-account"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.eks_oidc.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(aws_iam_openid_connect_provider.eks_oidc.url, "https://", "")}:sub" = "system:serviceaccount:production:backend-sa"
        }
      }
    }]
  })
}

# IAM policy for backend (access Secrets Manager, KMS, DynamoDB)
resource "aws_iam_role_policy" "backend_permissions" {
  role = aws_iam_role.backend_sa.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
        ]
        Resource = [
          "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/*",
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
        ]
        Resource = [
          "arn:aws:kms:us-east-1:123456789012:key/*",
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:Query",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
        ]
        Resource = [
          "arn:aws:dynamodb:us-east-1:123456789012:table/production-*",
        ]
      },
    ]
  })
}

# ===========================
# Kubernetes Service Accounts
# ===========================

# Frontend service account
resource "kubernetes_service_account" "frontend" {
  metadata {
    name      = "frontend-sa"
    namespace = "production"

    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.frontend_sa.arn
    }
  }
}

# Backend service account
resource "kubernetes_service_account" "backend" {
  metadata {
    name      = "backend-sa"
    namespace = "production"

    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.backend_sa.arn
    }
  }
}

# ===========================
# GCP Workload Identity
# ===========================

# GCP service account for frontend
resource "google_service_account" "frontend_sa" {
  account_id   = "frontend-sa"
  display_name = "Frontend Service Account"
  project      = "examplepay-prod-gcp"
}

# Bind Kubernetes SA to GCP SA
resource "google_service_account_iam_binding" "frontend_workload_identity" {
  service_account_id = google_service_account.frontend_sa.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:examplepay-prod-gcp.svc.id.goog[production/frontend-sa]",
  ]
}

# Grant GCS read permissions to frontend
resource "google_project_iam_member" "frontend_gcs_viewer" {
  project = "examplepay-prod-gcp"
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.frontend_sa.email}"
}

# GCP service account for backend
resource "google_service_account" "backend_sa" {
  account_id   = "backend-sa"
  display_name = "Backend Service Account"
  project      = "examplepay-prod-gcp"
}

# Bind Kubernetes SA to GCP SA
resource "google_service_account_iam_binding" "backend_workload_identity" {
  service_account_id = google_service_account.backend_sa.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "serviceAccount:examplepay-prod-gcp.svc.id.goog[production/backend-sa]",
  ]
}

# Grant Secret Manager access to backend
resource "google_project_iam_member" "backend_secret_accessor" {
  project = "examplepay-prod-gcp"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.backend_sa.email}"
}

# ===========================
# Azure Managed Identities
# ===========================

# User-assigned managed identity for frontend
resource "azurerm_user_assigned_identity" "frontend" {
  name                = "frontend-identity"
  resource_group_name = "rg-examplepay-production"
  location            = "eastus"

  tags = {
    ServiceAccount = "frontend-sa"
    Namespace      = "production"
    ManagedBy      = "Terraform"
  }
}

# Grant Blob Storage read permissions to frontend
resource "azurerm_role_assignment" "frontend_blob_reader" {
  scope                = azurerm_storage_account.assets.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.frontend.principal_id
}

# User-assigned managed identity for backend
resource "azurerm_user_assigned_identity" "backend" {
  name                = "backend-identity"
  resource_group_name = "rg-examplepay-production"
  location            = "eastus"

  tags = {
    ServiceAccount = "backend-sa"
    Namespace      = "production"
    ManagedBy      = "Terraform"
  }
}

# Grant Key Vault access to backend
resource "azurerm_key_vault_access_policy" "backend_secrets" {
  key_vault_id = azurerm_key_vault.production.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.backend.principal_id

  secret_permissions = [
    "Get",
    "List",
  ]
}

# ===========================
# Data Sources
# ===========================

data "aws_eks_cluster" "main" {
  name = "examplepay-prod-eks"
}

data "tls_certificate" "eks_oidc" {
  url = data.aws_eks_cluster.main.identity[0].oidc[0].issuer
}

data "azurerm_storage_account" "assets" {
  name                = "stexamplepassets"
  resource_group_name = "rg-examplepay-production"
}

data "azurerm_key_vault" "production" {
  name                = "kv-examplepay-prod"
  resource_group_name = "rg-examplepay-production"
}

# ===========================
# Outputs
# ===========================

output "workload_identity_summary" {
  description = "Summary of workload identity configuration"
  value = {
    aws_irsa = {
      oidc_provider     = aws_iam_openid_connect_provider.eks_oidc.url
      service_accounts  = 2
      iam_roles         = 2
      no_access_keys    = true
      authentication    = "OIDC token from EKS"
    }

    gcp_workload_identity = {
      service_accounts = 2
      gsa_bindings     = 2
      no_service_keys  = true
      authentication   = "OIDC token from GKE"
    }

    azure_managed_identity = {
      identities       = 2
      rbac_assignments = 2
      no_credentials   = true
      authentication   = "Managed identity token from AKS"
    }

    security_benefits = [
      "Zero service account keys or long-lived credentials",
      "Automatic token rotation",
      "Fine-grained IAM permissions per service account",
      "Audit trail of all service-to-service calls",
      "Supports Istio mTLS for additional layer",
    ]
  }
}
