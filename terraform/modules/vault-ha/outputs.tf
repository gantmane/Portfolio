# =============================================================================
# Vault HA Module — Outputs
# Author: Evgeniy Gantman
# =============================================================================

output "namespace" {
  description = "Kubernetes namespace where Vault is deployed."
  value       = kubernetes_namespace.vault.metadata[0].name
}

output "release_name" {
  description = "Helm release name for the Vault deployment."
  value       = helm_release.vault.name
}

output "release_status" {
  description = "Helm release status (deployed, failed, etc.)."
  value       = helm_release.vault.status
}

output "vault_internal_endpoint" {
  description = "Internal Vault API endpoint (cluster-internal DNS). Use for pod-to-Vault communication within the cluster."
  value       = "https://vault.${kubernetes_namespace.vault.metadata[0].name}.svc.cluster.local:8200"
}

output "vault_active_service" {
  description = "Kubernetes service name that routes to the active Vault leader."
  value       = "vault-active.${kubernetes_namespace.vault.metadata[0].name}.svc.cluster.local"
}

output "vault_standby_service" {
  description = "Kubernetes service name that routes to Vault standby replicas (read requests)."
  value       = "vault-standby.${kubernetes_namespace.vault.metadata[0].name}.svc.cluster.local"
}

output "vault_version" {
  description = "Vault container image version deployed."
  value       = var.vault_version
}

output "vault_chart_version" {
  description = "Helm chart version used for the deployment."
  value       = var.vault_chart_version
}

output "network_policy_name" {
  description = "Name of the NetworkPolicy enforcing default-deny on the Vault namespace."
  value       = kubernetes_network_policy.vault_default_deny.metadata[0].name
}
