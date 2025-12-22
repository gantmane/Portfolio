# KMS Key with Automatic Rotation Module
# Compliance: PCI DSS 3.6 (90-day rotation)

variable "key_alias" {
  description = "Alias for the KMS key"
  type        = string
}

variable "key_description" {
  description = "Description of the KMS key"
  type        = string
  default     = "Customer managed encryption key"
}

variable "enable_key_rotation" {
  description = "Enable automatic key rotation"
  type        = bool
  default     = true
}

variable "deletion_window_in_days" {
  description = "Key deletion window"
  type        = number
  default     = 30
}

resource "aws_kms_key" "main" {
  description             = var.key_description
  deletion_window_in_days = var.deletion_window_in_days
  enable_key_rotation     = var.enable_key_rotation

  tags = {
    Name      = var.key_alias
    ManagedBy = "Terraform"
  }
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.key_alias}"
  target_key_id = aws_kms_key.main.key_id
}

output "key_id" {
  description = "KMS key ID"
  value       = aws_kms_key.main.key_id
}

output "key_arn" {
  description = "KMS key ARN"
  value       = aws_kms_key.main.arn
}

output "key_alias" {
  description = "KMS key alias"
  value       = aws_kms_alias.main.name
}
