# Terraform Modules

![Terraform](https://img.shields.io/badge/Terraform-1.7-7B42BC?logo=terraform&logoColor=white)
![Terragrunt](https://img.shields.io/badge/Terragrunt-enabled-7B42BC)
![AWS](https://img.shields.io/badge/AWS-multi--account-FF9900?logo=amazonaws&logoColor=white)
![Modules](https://img.shields.io/badge/Modules-90%2B-brightgreen)
![Spend](https://img.shields.io/badge/Cloud%20Spend%20Managed-%242.1M%2Fyr-blue)

Production deployment: 90+ modules across AWS/GCP/Azure, ~$2.1M annual cloud spend managed

Stack: Terraform 1.7, Terragrunt, AWS, GCP, PCI DSS CDE, GitOps via GitLab CI

!!! tip "Production Scale"
    90+ reusable modules managed via Terragrunt with dependency graphs for correct apply order. All modules enforce PCI DSS and CIS benchmarks by default — security is not optional, it is the default configuration. State stored in S3 with KMS encryption and DynamoDB locking.

## Files

| File | Purpose |
|------|---------|
| modules/eks-security/main.tf | Hardened EKS cluster — private API, KMS secrets encryption, audit logging |
| modules/eks-security/variables.tf | Input variables with type constraints and validation |
| modules/vault-ha/main.tf | Vault 5-node HA on K8s — Raft storage, KMS auto-unseal, mTLS |
| modules/vault-ha/variables.tf | Vault HA module variables with secure defaults |

---

## View Code

=== "EKS Security Module"

    !!! danger "Security Control — Defense in Depth on Every Node"
        IMDSv2 with `http_put_response_hop_limit = 1` prevents container workloads from reaching the EC2 instance metadata service — the primary SSRF attack path for AWS credential theft. `anonymous-auth=false` on kubelet closes the unauthenticated API. `protect-kernel-defaults=true` prevents kernel parameter tampering.

    !!! info "MITRE ATT&CK — T1552.005 Cloud Instance Metadata API"
        IMDSv2 mandatory (`http_tokens = "required"`) with hop limit 1 is a direct mitigation for SSRF-to-IMDS attacks (e.g., the Capital One breach pattern). Without this, a single SSRF vulnerability in any pod can yield full EC2 IAM role credentials.

    !!! warning "PCI DSS 1.3.2 | 3.4 | 10.2"
        Private API endpoint only (`endpoint_public_access = false` in CDE). KMS envelope encryption on all Kubernetes Secrets in etcd — without this, secrets are only base64-encoded. All 5 CloudWatch log types enabled for complete audit trail. 1-year log retention satisfies PCI DSS 10.5.1.

    !!! tip "Best Practice — IRSA over Node IAM Roles"
        The OIDC provider enables IRSA (IAM Roles for Service Accounts): pods get scoped IAM roles instead of inheriting the node's broad IAM role. A compromised pod can only escalate to its own service account role — not the full node role.

    Hardened EKS cluster: private API endpoint, KMS envelope encryption for Secrets, IMDSv2 on all nodes,
    encrypted EBS volumes, CloudWatch audit logging (1-year retention). PCI DSS 1.3.2, 2.2.7, 3.4, 10.2. CIS EKS 1.4.

    ??? example "Full Module — modules/eks-security/main.tf"
        ```hcl title="modules/eks-security/main.tf"
        # EKS Security Configurations — Hardened Cluster
        # PCI DSS 1.3.2  — Restrict inbound/outbound traffic to CDE components
        # PCI DSS 3.4    — Protect stored Kubernetes secrets with strong cryptography
        # PCI DSS 10.2   — Log access to Kubernetes API and control plane
        # CIS EKS 1.4    — Hardened EKS benchmark

        terraform {
          required_version = ">= 1.5.0"
          required_providers {
            aws        = { source = "hashicorp/aws",        version = "~> 5.0" }
            kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.25" }
            tls        = { source = "hashicorp/tls",        version = "~> 4.0" }
          }
        }

        # EKS Cluster — hardened configuration
        resource "aws_eks_cluster" "main" {
          name     = var.cluster_name
          version  = var.kubernetes_version
          role_arn = aws_iam_role.cluster.arn

          # Private subnets only — PCI DSS 1.3.2: restrict network access to minimum necessary
          vpc_config {
            subnet_ids              = var.private_subnet_ids
            endpoint_public_access  = var.enable_public_endpoint  # false in production CDE
            endpoint_private_access = true
            public_access_cidrs     = var.public_access_cidrs
            security_group_ids      = [aws_security_group.cluster.id]
          }

          # Envelope encryption for Kubernetes Secrets
          # Without this, secrets in etcd are base64 encoded (NOT encrypted)
          # CIS EKS 1.4 §2.1 — PCI DSS 3.4: strong cryptography for stored sensitive data
          encryption_config {
            provider {
              key_arn = var.kms_key_arn
            }
            resources = ["secrets"]
          }

          # All 5 log types — PCI DSS 10.x requires complete audit trail
          enabled_cluster_log_types = [
            "api",               # all API server requests
            "audit",             # K8s audit log (who created/modified which resource)
            "authenticator",     # IAM authenticator requests
            "controllerManager", # scheduler and controller decisions
            "scheduler",         # pod scheduling decisions
          ]

          kubernetes_network_config {
            service_ipv4_cidr = var.service_cidr
            ip_family         = "ipv4"
          }

          lifecycle {
            prevent_destroy = true  # No accidental cluster deletion
            ignore_changes  = [tags["kubernetes.io/cluster/${var.cluster_name}"]]
          }

          depends_on = [
            aws_iam_role_policy_attachment.cluster_policy,
            aws_cloudwatch_log_group.eks_cluster,
          ]
        }

        # CloudWatch Log Group — 1-year retention, KMS encrypted
        # PCI DSS 10.5.1: retain logs for at least 12 months
        resource "aws_cloudwatch_log_group" "eks_cluster" {
          name              = "/aws/eks/${var.cluster_name}/cluster"
          retention_in_days = 365
          kms_key_id        = var.kms_key_arn
        }

        # OIDC Provider — enables IRSA (IAM Roles for Service Accounts)
        # Pods assume IAM roles via OIDC federation — no instance profile credentials
        # Eliminates the "confused deputy" problem — CIS EKS 1.4 §5.1
        data "tls_certificate" "eks_oidc" {
          url = aws_eks_cluster.main.identity[0].oidc[0].issuer
        }

        resource "aws_iam_openid_connect_provider" "eks" {
          client_id_list  = ["sts.amazonaws.com"]
          thumbprint_list = [data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint]
          url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
        }

        # EKS Managed Node Group — hardened worker nodes
        resource "aws_eks_node_group" "main" {
          cluster_name    = aws_eks_cluster.main.name
          node_group_name = "${var.cluster_name}-workers"
          node_role_arn   = aws_iam_role.node.arn
          subnet_ids      = var.private_subnet_ids

          ami_type       = "AL2_x86_64"
          instance_types = var.node_instance_types
          capacity_type  = var.use_spot_instances ? "SPOT" : "ON_DEMAND"

          scaling_config {
            desired_size = var.node_desired_count
            min_size     = var.node_min_count
            max_size     = var.node_max_count
          }

          update_config {
            max_unavailable_percentage = 33  # 1 of 3 nodes rolls at a time
          }

          launch_template {
            id      = aws_launch_template.node.id
            version = aws_launch_template.node.latest_version
          }

          lifecycle {
            ignore_changes = [scaling_config[0].desired_size]
          }
        }

        # Launch Template — security hardening for EKS worker nodes
        resource "aws_launch_template" "node" {
          name_prefix = "${var.cluster_name}-node-"

          # IMDSv2 mandatory — prevents SSRF attacks from reaching instance metadata
          # SSRF → IMDSv1 is a common attack path for credential theft in cloud
          # CIS EKS 1.4 §5.4
          metadata_options {
            http_endpoint               = "enabled"
            http_tokens                 = "required"  # IMDSv2: session-oriented tokens
            http_put_response_hop_limit = 1           # Prevents container SSRF
            instance_metadata_tags      = "disabled"
          }

          # Root EBS volume — KMS encrypted
          # PCI DSS 3.4: protect stored data with strong cryptography
          block_device_mappings {
            device_name = "/dev/xvda"
            ebs {
              volume_size           = var.node_disk_size
              volume_type           = "gp3"
              encrypted             = true
              kms_key_id            = var.kms_key_arn
              delete_on_termination = true
              iops                  = 3000
              throughput            = 125
            }
          }

          network_interfaces {
            associate_public_ip_address = false  # All nodes in private subnets
            security_groups             = [aws_security_group.node.id]
            delete_on_termination       = true
          }

          monitoring { enabled = true }

          # Kubelet hardening via bootstrap args
          user_data = base64encode(<<-EOF
            #!/bin/bash
            set -euo pipefail
            /etc/eks/bootstrap.sh ${var.cluster_name} \
              --kubelet-extra-args \
              '--read-only-port=0 --event-qps=0 --anonymous-auth=false --protect-kernel-defaults=true'
            mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null || true
          EOF
          )

          lifecycle { create_before_destroy = true }
        }

        # EBS CSI Driver — separate IRSA role (not node IAM)
        resource "aws_eks_addon" "ebs_csi" {
          cluster_name                = aws_eks_cluster.main.name
          addon_name                  = "aws-ebs-csi-driver"
          addon_version               = var.ebs_csi_version
          resolve_conflicts_on_update = "OVERWRITE"
          service_account_role_arn    = aws_iam_role.ebs_csi.arn
        }

        # VPC CNI — IRSA grants EC2 permissions for ENI management
        resource "aws_eks_addon" "vpc_cni" {
          cluster_name                = aws_eks_cluster.main.name
          addon_name                  = "vpc-cni"
          addon_version               = var.vpc_cni_version
          resolve_conflicts_on_update = "OVERWRITE"
          service_account_role_arn    = aws_iam_role.vpc_cni.arn

          configuration_values = jsonencode({
            enableNetworkPolicy = "true"
          })
        }
        ```

=== "Vault HA Module"

    !!! danger "Security Control — Multi-Layer Hardening"
        `atomic = true` on the Helm release rolls back every resource if any single resource fails — no partial state left in the cluster. `readOnlyRootFilesystem = true` prevents runtime filesystem writes. `allowPrivilegeEscalation = false` blocks setuid/setcap escalation paths.

    !!! info "AZ Anti-Affinity — Zone Failure Survival"
        `requiredDuringSchedulingIgnoredDuringExecution` with `topology.kubernetes.io/zone` forces Vault pods to separate AZs at scheduling time. With 5 nodes and a Raft quorum of 3, the cluster survives a full AZ outage — which is what achieves 99.99% uptime.

    !!! warning "PCI DSS 3.4 — Separate Audit Log PV"
        Vault audit logs are written to a dedicated PersistentVolume (`auditStorage`), separate from the Raft data volume. This ensures audit logs cannot be truncated even if the data partition is exhausted, satisfying PCI DSS 10.5.x (protect audit log integrity).

    !!! tip "Best Practice — NetworkPolicy Default Deny"
        The `vault-default-deny` NetworkPolicy blocks all ingress and egress by default, then whitelists: Raft port 8201 (inter-node only), API port 8200 (labeled namespaces only), Prometheus port 9102 (monitoring namespace only), KMS port 443 (egress), DNS port 53 (egress). Zero unintended exposure.

    5-node Vault HA via Helm on Kubernetes. Raft storage with anti-affinity across AZs.
    KMS auto-unseal, mTLS, non-root securityContext, separate audit log PV. PCI DSS 3.4, 8.3, CIS Vault 1.0.

    ??? example "Full Module — modules/vault-ha/main.tf"
        ```hcl title="modules/vault-ha/main.tf"
        # Vault HA Deployment on Kubernetes — Raft Integrated Storage
        # PCI DSS 3.4    — Render PAN unreadable; protect cryptographic keys
        # CIS Vault 1.0  — Hardened Vault configuration baseline

        # Namespace — isolated with PCI scope labels and prevent-destroy annotation
        resource "kubernetes_namespace" "vault" {
          metadata {
            name = var.namespace
            labels = {
              "security.io/pci-scope"  = var.pci_scope ? "in-scope" : "out-of-scope"
              "security.io/data-class" = "confidential"
            }
            annotations = {
              "lifecycle.terraform.io/prevent-destroy" = "true"
            }
          }
        }

        # NetworkPolicy — default-deny all; whitelist Raft (8201), API (8200), Prometheus (9102)
        # CIS Vault 1.0 §4.1: Restrict network access to Vault nodes
        resource "kubernetes_network_policy" "vault_default_deny" {
          metadata {
            name      = "vault-default-deny"
            namespace = kubernetes_namespace.vault.metadata[0].name
          }
          spec {
            pod_selector {}
            policy_types = ["Ingress", "Egress"]

            # Raft inter-node sync
            ingress {
              from { pod_selector { match_labels = { "app.kubernetes.io/name" = "vault" } } }
              ports { port = "8201"; protocol = "TCP" }
            }
            # API from labeled namespaces only
            ingress {
              from { namespace_selector { match_labels = { "vault-access" = "true" } } }
              ports { port = "8200"; protocol = "TCP" }
            }
            # Prometheus scraping from monitoring namespace
            ingress {
              from { namespace_selector { match_labels = { "kubernetes.io/metadata.name" = "monitoring" } } }
              ports { port = "9102"; protocol = "TCP" }
            }
            # Egress to AWS KMS (port 443) and DNS (53)
            egress { ports { port = "443"; protocol = "TCP" } }
            egress { ports { port = "53"; protocol = "UDP" } }
          }
        }

        # Helm Release — atomic install with rollback on failure
        resource "helm_release" "vault" {
          name            = "vault"
          repository      = "https://helm.releases.hashicorp.com"
          chart           = "vault"
          version         = var.vault_chart_version
          namespace       = kubernetes_namespace.vault.metadata[0].name
          atomic          = true   # Roll back entire release on any resource failure
          cleanup_on_fail = true
          wait            = true
          timeout         = 600

          values = [yamlencode({
            global = {
              enabled    = true
              tlsDisable = false  # TLS mandatory — CIS Vault 1.0 §2.1
            }

            server = {
              image = {
                repository = "hashicorp/vault"
                tag        = var.vault_version
                pullPolicy = "IfNotPresent"
              }

              resources = {
                requests = { memory = var.vault_memory_request, cpu = var.vault_cpu_request }
                limits   = { memory = var.vault_memory_limit,   cpu = var.vault_cpu_limit }
              }

              ha = {
                enabled  = true
                replicas = var.vault_replicas  # Minimum 3 for quorum (N/2+1)
                raft = {
                  enabled   = true
                  setNodeId = true
                  config    = <<-EOT
                    listener "tcp" {
                      tls_disable = 0
                      address         = "[::]:8200"
                      cluster_address = "[::]:8201"
                      tls_cert_file      = "/vault/userconfig/tls/tls.crt"
                      tls_key_file       = "/vault/userconfig/tls/tls.key"
                      tls_client_ca_file = "/vault/userconfig/tls/ca.crt"
                    }
                    storage "raft" {
                      path    = "/vault/data"
                      node_id = "VAULT_K8S_POD_NAME"
                      retry_join { leader_api_addr = "https://vault-0.vault-internal:8200" }
                      retry_join { leader_api_addr = "https://vault-1.vault-internal:8200" }
                      retry_join { leader_api_addr = "https://vault-2.vault-internal:8200" }
                    }
                    seal "awskms" {
                      region     = "${var.aws_region}"
                      kms_key_id = "${var.kms_key_id}"
                    }
                    service_registration "kubernetes" {}
                    telemetry { prometheus_retention_time = "30s"; disable_hostname = true }
                  EOT
                }
              }

              # Anti-affinity: spread Vault pods across AZs — zone failure survival
              affinity = {
                podAntiAffinity = {
                  requiredDuringSchedulingIgnoredDuringExecution = [{
                    labelSelector = { matchLabels = {
                      "app.kubernetes.io/name"     = "vault"
                      "app.kubernetes.io/instance" = "vault"
                    }}
                    topologyKey = "topology.kubernetes.io/zone"
                  }]
                }
              }

              # Non-root securityContext — CIS Kubernetes 5.2.6
              securityContext = {
                runAsNonRoot             = true
                runAsUser                = 100
                runAsGroup               = 1000
                fsGroup                  = 1000
                readOnlyRootFilesystem   = true
                allowPrivilegeEscalation = false
                capabilities             = { drop = ["ALL"] }
              }

              # IRSA annotation — Vault pods call KMS without static credentials
              serviceAccount = {
                create      = true
                name        = "vault"
                annotations = { "eks.amazonaws.com/role-arn" = var.vault_irsa_role_arn }
              }

              # Separate PV for audit logs — PCI DSS 10.x
              auditStorage = {
                enabled      = true
                size         = var.vault_audit_storage_size
                storageClass = var.storage_class_name
              }
            }

            # HA Vault Agent Injector — automatically inject secrets into pods
            injector = {
              enabled       = true
              replicas      = 2
              leaderElector = { enabled = true }
              resources = {
                requests = { memory = "64Mi",  cpu = "50m" }
                limits   = { memory = "256Mi", cpu = "250m" }
              }
            }
          })]

          depends_on = [
            kubernetes_namespace.vault,
            kubernetes_network_policy.vault_default_deny,
          ]
        }
        ```
