# AWS Encrypted RDS Module
# Compliance: PCI DSS 3.4, PCI DSS 3.5

variable "identifier" {
  description = "RDS instance identifier"
  type        = string
}

variable "engine" {
  description = "Database engine"
  type        = string
  default     = "postgres"
}

variable "engine_version" {
  description = "Database engine version"
  type        = string
  default     = "15.3"
}

variable "instance_class" {
  description = "Instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "allocated_storage" {
  description = "Allocated storage in GB"
  type        = number
  default     = 100
}

variable "storage_encrypted" {
  description = "Enable encryption"
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "KMS key ID"
  type        = string
  default     = null
}

variable "multi_az" {
  description = "Enable Multi-AZ"
  type        = bool
  default     = true
}

variable "backup_retention_period" {
  description = "Backup retention period in days"
  type        = number
  default     = 2555  # 7 years for PCI DSS
}

variable "deletion_protection" {
  description = "Enable deletion protection"
  type        = bool
  default     = true
}

resource "aws_db_instance" "main" {
  identifier     = var.identifier
  engine         = var.engine
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  storage_encrypted     = var.storage_encrypted
  kms_key_id            = var.kms_key_id

  multi_az = var.multi_az

  backup_retention_period = var.backup_retention_period
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  deletion_protection = var.deletion_protection
  skip_final_snapshot = false
  final_snapshot_identifier = "${var.identifier}-final-snapshot"

  enabled_cloudwatch_logs_exports = ["postgresql"]

  tags = {
    Name      = var.identifier
    ManagedBy = "Terraform"
  }
}

output "endpoint" {
  description = "RDS endpoint"
  value       = aws_db_instance.main.endpoint
}

output "arn" {
  description = "RDS ARN"
  value       = aws_db_instance.main.arn
}
