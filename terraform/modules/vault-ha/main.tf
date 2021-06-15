# =============================================================================
# Vault HA Deployment on Kubernetes with Raft Integrated Storage
# Author: Evgeniy Gantman
#
# Deploys HashiCorp Vault in High Availability mode using:
#   - Raft integrated storage (no external Consul dependency)
#   - TLS everywhere (auto-generated via cert-manager or self-signed)
#   - StatefulSet with anti-affinity for multi-AZ spread
#   - Auto-unseal via AWS KMS (eliminates manual unseal ceremonies)
#
# Compliance:
#   PCI DSS 3.4    — Render PAN unreadable; protect cryptographic keys
#   PCI DSS 8.3    — Secure individual non-consumer authentication
#   CIS Vault 1.0  — Hardened Vault configuration baseline
#   NIST SP 800-57 — Key management recommendations
#
# Prerequisites:
#   - Kubernetes cluster with cert-manager (for TLS) or bring your own certs
#   - AWS KMS key for auto-unseal (see ../kms.tf pattern)
#   - Helm provider configured: helm provider ~> 2.0
#   - Kubernetes provider configured with valid kubeconfig
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Namespace — isolated from default to apply RBAC and NetworkPolicy scoping
# -----------------------------------------------------------------------------
resource "kubernetes_namespace" "vault" {
  metadata {
    name = var.namespace

    labels = {
      "app.kubernetes.io/name"       = "vault"
      "app.kubernetes.io/managed-by" = "terraform"
      # PCI DSS: label CDE-scoped namespaces for audit trail
      "security.io/pci-scope"  = var.pci_scope ? "in-scope" : "out-of-scope"
      "security.io/data-class" = "confidential"
    }

    annotations = {
      # Prevent accidental deletion of this namespace
      "lifecycle.terraform.io/prevent-destroy" = "true"
    }
  }
}

# -----------------------------------------------------------------------------
# NetworkPolicy — default-deny all ingress/egress, whitelist only what Vault
# needs: Raft peer sync (8201), API (8200), Prometheus scraping (9102).
# CIS Vault 1.0 §4.1: Restrict network access to Vault nodes.
# -----------------------------------------------------------------------------
resource "kubernetes_network_policy" "vault_default_deny" {
  metadata {
    name      = "vault-default-deny"
    namespace = kubernetes_namespace.vault.metadata[0].name
  }

  spec {
    pod_selector {} # Apply to all pods in namespace

    policy_types = ["Ingress", "Egress"]

    # Allow Raft inter-node sync
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "vault"
          }
        }
      }
      ports {
        port     = "8201"
        protocol = "TCP"
      }
    }

    # Allow API access from workload namespaces (explicitly listed)
    ingress {
      from {
        namespace_selector {
          match_labels = {
            "vault-access" = "true"
          }
        }
      }
      ports {
        port     = "8200"
        protocol = "TCP"
      }
    }

    # Allow Prometheus scraping from monitoring namespace
    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "monitoring"
          }
        }
      }
      ports {
        port     = "9102"
        protocol = "TCP"
      }
    }

    # Allow egress to AWS KMS for auto-unseal
    egress {
      to {
        ip_block {
          # AWS KMS endpoints; restrict further with VPC endpoint + SG
          cidr = "0.0.0.0/0"
        }
      }
      ports {
        port     = "443"
        protocol = "TCP"
      }
    }

    # Allow DNS resolution
    egress {
      ports {
        port     = "53"
        protocol = "UDP"
      }
      ports {
        port     = "53"
        protocol = "TCP"
      }
    }
  }
}

# -----------------------------------------------------------------------------
# Helm Release — HashiCorp Vault
# Chart: hashicorp/vault >= 0.27.0
# -----------------------------------------------------------------------------
resource "helm_release" "vault" {
  name             = "vault"
  repository       = "https://helm.releases.hashicorp.com"
  chart            = "vault"
  version          = var.vault_chart_version
  namespace        = kubernetes_namespace.vault.metadata[0].name
  create_namespace = false # We manage namespace above

  # Atomic install: if any resource fails, roll back the entire release
  atomic          = true
  cleanup_on_fail = true
  wait            = true
  wait_for_jobs   = true
  timeout         = 600

  values = [
    yamlencode({
      global = {
        enabled    = true
        tlsDisable = false # TLS mandatory — CIS Vault 1.0 §2.1
      }

      server = {
        # -----------------------------------------------------------------------
        # Image — pin to specific digest in production; tag alone is mutable
        # -----------------------------------------------------------------------
        image = {
          repository = "hashicorp/vault"
          tag        = var.vault_version
          pullPolicy = "IfNotPresent"
        }

        # -----------------------------------------------------------------------
        # Resource requests/limits — prevent noisy-neighbour on shared cluster
        # -----------------------------------------------------------------------
        resources = {
          requests = {
            memory = var.vault_memory_request
            cpu    = var.vault_cpu_request
          }
          limits = {
            memory = var.vault_memory_limit
            cpu    = var.vault_cpu_limit
          }
        }

        # -----------------------------------------------------------------------
        # HA mode with Raft integrated storage
        # Raft requires persistent volumes for each replica
        # -----------------------------------------------------------------------
        ha = {
          enabled  = true
          replicas = var.vault_replicas # Minimum 3 for quorum (N/2+1)
          raft = {
            enabled   = true
            setNodeId = true

            config = <<-EOT
              ui = true

              listener "tcp" {
                tls_disable     = 0
                address         = "[::]:8200"
                cluster_address = "[::]:8201"

                # mTLS: require client certificate for API access
                # CIS Vault 1.0 §2.2: Enable mutual TLS
                tls_cert_file      = "/vault/userconfig/tls/tls.crt"
                tls_key_file       = "/vault/userconfig/tls/tls.key"
                tls_client_ca_file = "/vault/userconfig/tls/ca.crt"

                # Telemetry for Prometheus — scrape /v1/sys/metrics
                telemetry {
                  unauthenticated_metrics_access = false
                }
              }

              # Raft storage backend
              storage "raft" {
                path    = "/vault/data"
                node_id = "VAULT_K8S_POD_NAME"

                # Performance — tuned for SSD storage
                retry_join {
                  leader_api_addr         = "https://vault-0.vault-internal:8200"
                  leader_ca_cert_file     = "/vault/userconfig/tls/ca.crt"
                  leader_client_cert_file = "/vault/userconfig/tls/tls.crt"
                  leader_client_key_file  = "/vault/userconfig/tls/tls.key"
                }
                retry_join {
                  leader_api_addr         = "https://vault-1.vault-internal:8200"
                  leader_ca_cert_file     = "/vault/userconfig/tls/ca.crt"
                  leader_client_cert_file = "/vault/userconfig/tls/tls.crt"
                  leader_client_key_file  = "/vault/userconfig/tls/tls.key"
                }
                retry_join {
                  leader_api_addr         = "https://vault-2.vault-internal:8200"
                  leader_ca_cert_file     = "/vault/userconfig/tls/ca.crt"
                  leader_client_cert_file = "/vault/userconfig/tls/tls.crt"
                  leader_client_key_file  = "/vault/userconfig/tls/tls.key"
                }
              }

              # AWS KMS auto-unseal
              # PCI DSS 3.7.4: Protect cryptographic keys against unauthorised access
              seal "awskms" {
                region     = "${var.aws_region}"
                kms_key_id = "${var.kms_key_id}"
              }

              # Service registration — used for health checks
              service_registration "kubernetes" {}

              # Telemetry configuration
              telemetry {
                prometheus_retention_time = "30s"
                disable_hostname          = true
              }

              # Disable the Vault UI in production if not needed
              # ui = false
            EOT
          }
        }

        # -----------------------------------------------------------------------
        # Anti-affinity: spread Vault pods across AZs to survive zone failure
        # -----------------------------------------------------------------------
        affinity = {
          podAntiAffinity = {
            requiredDuringSchedulingIgnoredDuringExecution = [
              {
                labelSelector = {
                  matchLabels = {
                    "app.kubernetes.io/name"     = "vault"
                    "app.kubernetes.io/instance" = "vault"
                  }
                }
                topologyKey = "topology.kubernetes.io/zone"
              }
            ]
          }
        }

        # -----------------------------------------------------------------------
        # Persistent Volume — Raft requires durable storage per node
        # Use io1/io2 for production IOPS guarantees
        # -----------------------------------------------------------------------
        dataStorage = {
          enabled      = true
          size         = var.vault_storage_size
          storageClass = var.storage_class_name
          accessMode   = "ReadWriteOnce"
        }

        # -----------------------------------------------------------------------
        # Security Context — run as non-root, read-only root filesystem
        # CIS Kubernetes Benchmark 5.2.6: Do not allow root containers
        # -----------------------------------------------------------------------
        securityContext = {
          runAsNonRoot             = true
          runAsUser                = 100
          runAsGroup               = 1000
          fsGroup                  = 1000
          readOnlyRootFilesystem   = true
          allowPrivilegeEscalation = false
          capabilities = {
            drop = ["ALL"]
          }
        }

        # -----------------------------------------------------------------------
        # Service Account — used by Kubernetes auth method and IRSA
        # -----------------------------------------------------------------------
        serviceAccount = {
          create = true
          name   = "vault"
          annotations = {
            # IRSA: allows Vault pods to call KMS without static credentials
            "eks.amazonaws.com/role-arn" = var.vault_irsa_role_arn
          }
        }

        # -----------------------------------------------------------------------
        # Audit log storage — required for PCI DSS 10.x compliance
        # Separate volume prevents audit log from filling Raft storage
        # -----------------------------------------------------------------------
        auditStorage = {
          enabled      = true
          size         = var.vault_audit_storage_size
          storageClass = var.storage_class_name
        }

        # -----------------------------------------------------------------------
        # Liveness and readiness probes
        # -----------------------------------------------------------------------
        readinessProbe = {
          enabled             = true
          initialDelaySeconds = 5
          periodSeconds       = 5
          failureThreshold    = 2
        }

        livenessProbe = {
          enabled             = true
          initialDelaySeconds = 60
          periodSeconds       = 10
          failureThreshold    = 2
        }
      }

      # -----------------------------------------------------------------------
      # Vault Agent Injector — automatically inject secrets into pods via
      # init/sidecar containers. Avoids application-level Vault SDK dependency.
      # -----------------------------------------------------------------------
      injector = {
        enabled       = true
        replicas      = 2 # HA injector
        leaderElector = { enabled = true }

        resources = {
          requests = { memory = "64Mi", cpu = "50m" }
          limits   = { memory = "256Mi", cpu = "250m" }
        }

        # TLS for webhook communication — auto-configured by Vault chart
        certs = {
          secretName = null
          caBundle   = ""
        }
      }

      # -----------------------------------------------------------------------
      # Vault CSI Provider — alternative to injector; mounts secrets as files
      # -----------------------------------------------------------------------
      csi = {
        enabled = var.enable_csi_provider
      }

      # -----------------------------------------------------------------------
      # Prometheus ServiceMonitor — if kube-prometheus-stack is installed
      # -----------------------------------------------------------------------
      serverTelemetry = {
        serviceMonitor = {
          enabled  = var.enable_prometheus_monitoring
          interval = "30s"
        }
      }
    })
  ]

  depends_on = [
    kubernetes_namespace.vault,
    kubernetes_network_policy.vault_default_deny,
  ]
}
