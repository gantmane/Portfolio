# =============================================================================
# EKS Security Module — Input Variables
# Author: Evgeniy Gantman
# =============================================================================

variable "cluster_name" {
  type        = string
  description = "EKS cluster name. Used as prefix for all resource names and in KMS key policies."

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,99}$", var.cluster_name))
    error_message = "cluster_name must be lowercase alphanumeric with hyphens, max 100 characters."
  }
}

variable "kubernetes_version" {
  type        = string
  description = "Kubernetes version for the EKS cluster. Pin to a specific version — upgrade requires planning. Check EKS release notes for breaking changes."
  default     = "1.29"

  validation {
    condition     = can(regex("^1\\.[2-9][0-9]$", var.kubernetes_version))
    error_message = "kubernetes_version must be in format '1.XX' (e.g., 1.29, 1.30)."
  }
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "List of private subnet IDs for worker nodes and cluster ENIs. Use subnets in at least 3 AZs for HA. Do not use public subnets for nodes."

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "At least 2 private subnets required for HA. 3 recommended for multi-AZ spread."
  }
}

variable "service_cidr" {
  type        = string
  description = "CIDR for Kubernetes services (ClusterIP range). Must not overlap with VPC CIDR or pod CIDR. Default 172.20.0.0/16 works for most VPCs."
  default     = "172.20.0.0/16"
}

variable "enable_public_endpoint" {
  type        = bool
  description = "Enable the EKS public API endpoint. Set false for PCI CDE environments. Requires VPN or AWS PrivateLink for kubectl access."
  default     = false
}

variable "public_access_cidrs" {
  type        = list(string)
  description = "CIDRs allowed to access the public API endpoint. Only used when enable_public_endpoint = true. Restrict to corporate IP ranges."
  default     = []
}

variable "node_instance_types" {
  type        = list(string)
  description = "EC2 instance types for the managed node group. List multiple for capacity diversity. Avoid burstable types (t-series) for production workloads."
  default     = ["m6i.xlarge", "m6a.xlarge"]
}

variable "node_desired_count" {
  type        = number
  description = "Initial desired number of worker nodes."
  default     = 3

  validation {
    condition     = var.node_desired_count >= 1
    error_message = "node_desired_count must be at least 1."
  }
}

variable "node_min_count" {
  type        = number
  description = "Minimum number of worker nodes for autoscaler."
  default     = 3

  validation {
    condition     = var.node_min_count >= 2
    error_message = "node_min_count must be at least 2 for availability."
  }
}

variable "node_max_count" {
  type        = number
  description = "Maximum number of worker nodes for autoscaler."
  default     = 10
}

variable "node_disk_size" {
  type        = number
  description = "Root EBS volume size in GB for worker nodes. Must accommodate OS, container images, and emptyDir volumes. 50GB minimum; 100GB recommended."
  default     = 100

  validation {
    condition     = var.node_disk_size >= 50
    error_message = "node_disk_size must be at least 50 GB to prevent disk pressure issues."
  }
}

variable "node_labels" {
  type        = map(string)
  description = "Additional Kubernetes labels to apply to all nodes in this group. Use for node selectors and affinity rules."
  default     = {}
}

variable "use_spot_instances" {
  type        = bool
  description = "Use EC2 Spot instances for worker nodes. Cost-effective for dev/staging. NOT recommended for production PCI CDE workloads — spot interruptions can cause outages."
  default     = false
}

variable "node_iam_permission_boundary_arn" {
  type        = string
  description = "ARN of an IAM permission boundary policy to attach to the node role. Prevents privilege escalation via added policies. Recommended in multi-team accounts."
  default     = null
}

# Add-on versions
variable "coredns_version" {
  type        = string
  description = "CoreDNS add-on version. Check EKS release notes for version compatibility with cluster Kubernetes version."
  default     = "v1.11.1-eksbuild.4"
}

variable "kube_proxy_version" {
  type        = string
  description = "kube-proxy add-on version."
  default     = "v1.29.0-eksbuild.1"
}

variable "vpc_cni_version" {
  type        = string
  description = "Amazon VPC CNI add-on version. Must support SecurityGroupsForPods if using pod-level SGs."
  default     = "v1.16.0-eksbuild.1"
}

variable "ebs_csi_version" {
  type        = string
  description = "Amazon EBS CSI driver add-on version."
  default     = "v1.28.0-eksbuild.1"
}

variable "pod_identity_version" {
  type        = string
  description = "EKS Pod Identity agent add-on version."
  default     = "v1.2.0-eksbuild.1"
}

variable "kms_key_arn" {
  type        = string
  description = "ARN of the AWS KMS key used to encrypt Kubernetes Secrets (envelope encryption) and EBS root volumes. PCI DSS 3.4: strong cryptography for stored sensitive data. Key must grant kms:Encrypt, kms:Decrypt, kms:GenerateDataKey, kms:DescribeKey to the cluster and node IAM roles."
  sensitive   = true

  validation {
    condition = (
      can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$", var.kms_key_arn)) ||
      can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:alias/.+$", var.kms_key_arn))
    )
    error_message = "kms_key_arn must be a valid KMS key ARN (arn:aws:kms:REGION:ACCOUNT:key/UUID) or alias ARN."
  }
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to all AWS resources. Required keys: environment, team. Recommended: cost-center, data-classification."
  default     = {}

  validation {
    condition = (
      contains(keys(var.tags), "environment") &&
      contains(keys(var.tags), "team")
    )
    error_message = "Tags map must include 'environment' and 'team' keys."
  }
}
