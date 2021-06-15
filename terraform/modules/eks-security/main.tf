# =============================================================================
# EKS Security Configurations — Hardened Cluster
# Author: Evgeniy Gantman
#
# Configures a production-hardened EKS cluster with:
#   - Private API endpoint (no public exposure)
#   - Envelope encryption for Kubernetes secrets via AWS KMS
#   - OIDC provider for IRSA (no static credentials in pods)
#   - EKS Managed Node Groups with IMDSv2 (no unauthenticated metadata)
#   - CloudWatch logging for all control-plane log types
#   - Cluster access via aws-auth ConfigMap with least-privilege IAM
#
# Compliance:
#   PCI DSS 1.3.2  — Restrict inbound/outbound traffic to CDE components
#   PCI DSS 2.2.7  — Encrypt all non-console administrative access
#   PCI DSS 3.4    — Protect stored Kubernetes secrets with strong cryptography
#   PCI DSS 10.2   — Log access to Kubernetes API and control plane
#   CIS EKS 1.4    — Hardened EKS benchmark
#   NIST SP 800-190 — Application Container Security Guide
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_partition" "current" {}

# -----------------------------------------------------------------------------
# EKS Cluster — hardened configuration
# CIS EKS 1.4 §1.1: Enable API server audit logging
# CIS EKS 1.4 §2.1: Enable secrets encryption
# -----------------------------------------------------------------------------
resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  version  = var.kubernetes_version
  role_arn = aws_iam_role.cluster.arn

  # -----------------------------------------------------------------------
  # VPC configuration — private subnets only for worker nodes
  # Public subnets only needed if using public NLB for ingress
  # PCI DSS 1.3.2: restrict network access to minimum necessary
  # -----------------------------------------------------------------------
  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_public_access  = var.enable_public_endpoint # false in production CDE
    endpoint_private_access = true
    public_access_cidrs     = var.public_access_cidrs # empty list when endpoint_public_access=false
    security_group_ids      = [aws_security_group.cluster.id]
  }

  # -----------------------------------------------------------------------
  # Envelope encryption for Kubernetes Secrets
  # Without this, secrets in etcd are base64 encoded (NOT encrypted)
  # KMS wraps the etcd encryption key — two-envelope model
  # PCI DSS 3.4: strong cryptography for stored sensitive authentication data
  # CIS EKS 1.4 §2.1: enable secrets encryption
  # -----------------------------------------------------------------------
  encryption_config {
    provider {
      key_arn = var.kms_key_arn
    }
    resources = ["secrets"] # Encrypts Kubernetes Secret objects in etcd
  }

  # -----------------------------------------------------------------------
  # Control plane logging — all log types required for PCI DSS 10.x
  # api          — all API server requests (who called what)
  # audit        — K8s audit log (who created/modified which resource)
  # authenticator — IAM authenticator requests
  # controllerManager — scheduler and controller decisions
  # scheduler    — pod scheduling decisions
  # -----------------------------------------------------------------------
  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler",
  ]

  kubernetes_network_config {
    # Service CIDR — non-overlapping with VPC and pod CIDR
    service_ipv4_cidr = var.service_cidr

    # IPv4 only; dual-stack if needed (requires additional planning)
    ip_family = "ipv4"
  }

  # Upgrade cluster without disruption using managed upgrades
  upgrade_policy {
    support_type = "STANDARD"
  }

  tags = merge(var.tags, {
    Name = var.cluster_name
  })

  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
    aws_cloudwatch_log_group.eks_cluster,
  ]

  lifecycle {
    # Prevent accidental cluster deletion — must be explicitly targeted
    prevent_destroy = true

    # Ignore manual changes to AWS-managed labels
    ignore_changes = [tags["kubernetes.io/cluster/${var.cluster_name}"]]
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Log Group for EKS control plane logs
# Retention set to 1 year to meet PCI DSS 10.5.1 requirement
# Log Group encrypted with KMS — PCI DSS 3.4
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "eks_cluster" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = 365 # PCI DSS 10.5.1: retain logs for at least 12 months

  kms_key_id = var.kms_key_arn # Encrypt log data at rest

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-control-plane-logs"
  })
}

# -----------------------------------------------------------------------------
# OIDC Provider — enables IRSA (IAM Roles for Service Accounts)
# Pods assume IAM roles via OIDC federation instead of using instance profiles
# This eliminates the "confused deputy" problem of node-level IAM roles
# CIS EKS 1.4 §5.1: prefer IRSA over instance IAM roles
# -----------------------------------------------------------------------------
data "tls_certificate" "eks_oidc" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-oidc-provider"
  })
}

# -----------------------------------------------------------------------------
# EKS Managed Node Group — hardened worker nodes
# Managed node groups handle AMI updates, drain/cordoning during upgrades
# -----------------------------------------------------------------------------
resource "aws_eks_node_group" "main" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.cluster_name}-workers"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.private_subnet_ids

  # Pin to EKS-optimized AL2 AMI — custom AMI requires separate hardening pipeline
  ami_type       = "AL2_x86_64"
  instance_types = var.node_instance_types
  capacity_type  = var.use_spot_instances ? "SPOT" : "ON_DEMAND"
  disk_size      = var.node_disk_size

  scaling_config {
    desired_size = var.node_desired_count
    min_size     = var.node_min_count
    max_size     = var.node_max_count
  }

  update_config {
    # Percent of nodes that can be unavailable during updates
    # 33% means 1 of 3 nodes rolls at a time — maintains cluster capacity
    max_unavailable_percentage = 33
  }

  # -----------------------------------------------------------------------
  # Launch Template for security hardening
  # - IMDSv2 required (prevents SSRF-to-metadata attacks)
  # - Encrypted EBS root volume
  # - Security groups: only allow traffic from cluster SG
  # -----------------------------------------------------------------------
  launch_template {
    id      = aws_launch_template.node.id
    version = aws_launch_template.node.latest_version
  }

  labels = merge(var.node_labels, {
    "eks.amazonaws.com/nodegroup" = "${var.cluster_name}-workers"
    "node-type"                   = "application"
  })

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-worker-node"
    # Required for cluster autoscaler to discover node groups
    "k8s.io/cluster-autoscaler/enabled"             = "true"
    "k8s.io/cluster-autoscaler/${var.cluster_name}" = "owned"
  })

  depends_on = [
    aws_iam_role_policy_attachment.node_worker_policy,
    aws_iam_role_policy_attachment.node_ecr_policy,
    aws_iam_role_policy_attachment.node_cni_policy,
  ]

  lifecycle {
    # Prevent terraform destroy from removing nodes while workloads run
    # Use `terraform state rm` + manual drain for intentional removal
    ignore_changes = [scaling_config[0].desired_size]
  }
}

# -----------------------------------------------------------------------------
# Launch Template — security hardening for EKS worker nodes
# -----------------------------------------------------------------------------
resource "aws_launch_template" "node" {
  name_prefix = "${var.cluster_name}-node-"
  description = "Hardened launch template for ${var.cluster_name} worker nodes"

  # -----------------------------------------------------------------------
  # IMDSv2 — mandatory; prevents SSRF attacks from reaching instance metadata
  # SSRF → IMDSv1 is a common attack path for credential theft in cloud
  # CIS EKS 1.4 §5.4: require IMDSv2 on all EC2 worker nodes
  # -----------------------------------------------------------------------
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2: session-oriented tokens required
    http_put_response_hop_limit = 1          # Limit hop count; prevents container SSRF
    instance_metadata_tags      = "disabled" # Do not expose EC2 tags via IMDS
  }

  # -----------------------------------------------------------------------
  # Root EBS volume — encrypted with KMS
  # PCI DSS 3.4: protect stored data with strong cryptography
  # -----------------------------------------------------------------------
  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = var.node_disk_size
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.kms_key_arn
      delete_on_termination = true

      # IOPS and throughput for gp3 (baseline 3000 IOPS, 125 MB/s)
      iops       = 3000
      throughput = 125
    }
  }

  # Attach node security group (defined in security-groups.tf)
  vpc_security_group_ids = [aws_security_group.node.id]

  # Disable public IP — all nodes in private subnets
  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.node.id]
    delete_on_termination       = true
  }

  # Monitoring — enable detailed CloudWatch monitoring for worker nodes
  monitoring {
    enabled = true
  }

  # User data — minimal; EKS bootstrap handles kubelet registration
  # Additional hardening is applied via SSM documents or custom AMI
  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -euo pipefail

    # CIS EKS 1.4 §4.1: Configure kubelet to use read-only port=0 (disable)
    # EKS bootstrap.sh handles this via --kubelet-extra-args
    /etc/eks/bootstrap.sh ${var.cluster_name} \
      --kubelet-extra-args \
      '--read-only-port=0 --event-qps=0 --anonymous-auth=false --protect-kernel-defaults=true'

    # Restrict /tmp to prevent code execution from world-writable dirs
    mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null || true
  EOF
  )

  tags = merge(var.tags, {
    Name = "${var.cluster_name}-node-template"
  })

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name = "${var.cluster_name}-worker"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(var.tags, {
      Name = "${var.cluster_name}-worker-root-volume"
    })
  }

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------------------------------------------------------
# EKS Add-ons — managed by AWS, kept up to date
# -----------------------------------------------------------------------------

# CoreDNS — cluster DNS (required)
resource "aws_eks_addon" "coredns" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "coredns"
  addon_version               = var.coredns_version
  resolve_conflicts_on_update = "OVERWRITE"

  tags = var.tags
}

# kube-proxy — pod network routing (required)
resource "aws_eks_addon" "kube_proxy" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "kube-proxy"
  addon_version               = var.kube_proxy_version
  resolve_conflicts_on_update = "OVERWRITE"

  tags = var.tags
}

# VPC CNI — pod networking; IRSA grants EC2 permissions for ENI management
resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "vpc-cni"
  addon_version               = var.vpc_cni_version
  resolve_conflicts_on_update = "OVERWRITE"
  service_account_role_arn    = aws_iam_role.vpc_cni.arn # IRSA — not node IAM

  # Enable network policy enforcement via VPC CNI
  configuration_values = jsonencode({
    enableNetworkPolicy = "true"
  })

  tags = var.tags
}

# EBS CSI Driver — manages EBS volumes for PVCs; separate IRSA role
resource "aws_eks_addon" "ebs_csi" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "aws-ebs-csi-driver"
  addon_version               = var.ebs_csi_version
  resolve_conflicts_on_update = "OVERWRITE"
  service_account_role_arn    = aws_iam_role.ebs_csi.arn

  tags = var.tags
}

# Pod identity agent — newer alternative to IRSA for EKS Pod Identity
resource "aws_eks_addon" "pod_identity" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "eks-pod-identity-agent"
  addon_version               = var.pod_identity_version
  resolve_conflicts_on_update = "OVERWRITE"

  tags = var.tags
}
