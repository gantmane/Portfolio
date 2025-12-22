# Azure AKS Cluster Module
# Compliance: PCI DSS 2.2, CIS Azure 8.1

variable "cluster_name" {
  description = "AKS cluster name"
  type        = string
}

variable "resource_group_name" {
  description = "Resource group name"
  type        = string
}

variable "location" {
  description = "Azure location"
  type        = string
}

variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.28"
}

variable "vnet_subnet_id" {
  description = "VNet subnet ID"
  type        = string
}

variable "enable_azure_policy" {
  description = "Enable Azure Policy for Kubernetes"
  type        = bool
  default     = true
}

resource "azurerm_kubernetes_cluster" "main" {
  name                = var.cluster_name
  location            = var.location
  resource_group_name = var.resource_group_name
  dns_prefix          = var.cluster_name
  kubernetes_version  = var.kubernetes_version

  default_node_pool {
    name                = "default"
    node_count          = 3
    vm_size             = "Standard_D2s_v3"
    vnet_subnet_id      = var.vnet_subnet_id
    enable_auto_scaling = true
    min_count           = 2
    max_count           = 10
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "calico"
  }

  azure_policy_enabled = var.enable_azure_policy

  tags = {
    Name      = var.cluster_name
    ManagedBy = "Terraform"
  }
}

output "cluster_id" {
  description = "AKS cluster ID"
  value       = azurerm_kubernetes_cluster.main.id
}

output "kube_config" {
  description = "Kubeconfig"
  value       = azurerm_kubernetes_cluster.main.kube_config_raw
  sensitive   = true
}
