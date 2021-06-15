# =============================================================================
# EKS Security Module — Outputs
# Author: Evgeniy Gantman
# =============================================================================

output "cluster_name" {
  description = "EKS cluster name."
  value       = aws_eks_cluster.main.name
}

output "cluster_arn" {
  description = "ARN of the EKS cluster."
  value       = aws_eks_cluster.main.arn
}

output "cluster_endpoint" {
  description = "API server endpoint for the EKS cluster."
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_certificate_authority_data" {
  description = "Base64-encoded CA certificate for the cluster. Pass to kubeconfig."
  value       = aws_eks_cluster.main.certificate_authority[0].data
  sensitive   = true
}

output "cluster_version" {
  description = "Kubernetes version running on the cluster."
  value       = aws_eks_cluster.main.version
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster control plane."
  value       = aws_security_group.cluster.id
}

output "node_security_group_id" {
  description = "Security group ID attached to the EKS worker nodes."
  value       = aws_security_group.node.id
}

output "node_role_arn" {
  description = "IAM Role ARN used by the EKS managed node group."
  value       = aws_iam_role.node.arn
}

output "cluster_role_arn" {
  description = "IAM Role ARN used by the EKS cluster control plane."
  value       = aws_iam_role.cluster.arn
}

output "oidc_provider_arn" {
  description = "ARN of the OIDC identity provider — used to create IRSA roles."
  value       = aws_iam_openid_connect_provider.eks.arn
}

output "oidc_provider_url" {
  description = "URL of the OIDC provider (without https://) — used in IRSA trust policies."
  value       = replace(aws_iam_openid_connect_provider.eks.url, "https://", "")
}

output "node_group_arn" {
  description = "ARN of the managed node group."
  value       = aws_eks_node_group.main.arn
}

output "cloudwatch_log_group_name" {
  description = "CloudWatch log group name for EKS control plane logs."
  value       = aws_cloudwatch_log_group.eks_cluster.name
}
