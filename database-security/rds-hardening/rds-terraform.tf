# Hardened RDS PostgreSQL Instance
# Author: Evgeniy Gantman
# PCI DSS Compliant Configuration

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# KMS Key for RDS Encryption
resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "rds-encryption-key"
    Environment = "production"
    Compliance  = "PCI-DSS"
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/rds-encryption"
  target_key_id = aws_kms_key.rds.key_id
}

# DB Subnet Group (Private Subnets)
resource "aws_db_subnet_group" "main" {
  name       = "examplepay-db-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "ExamplePay DB Subnet Group"
  }
}

# Security Group for RDS
resource "aws_security_group" "rds" {
  name        = "examplepay-rds-sg"
  description = "Security group for RDS instances"
  vpc_id      = var.vpc_id

  # PostgreSQL access only from application subnets
  ingress {
    description     = "PostgreSQL from application tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.application_security_group_id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "examplepay-rds-sg"
  }
}

# Parameter Group with Security Hardening
resource "aws_db_parameter_group" "postgres_hardened" {
  name   = "examplepay-postgres15-hardened"
  family = "postgres15"

  # Force SSL connections
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  # Enable query logging
  parameter {
    name  = "log_statement"
    value = "ddl"  # Log DDL statements
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"  # Log queries >1 second
  }

  # Connection limits
  parameter {
    name  = "max_connections"
    value = "200"
  }

  # Enable auto_explain for slow queries
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements,auto_explain"
  }

  parameter {
    name  = "auto_explain.log_min_duration"
    value = "1000"
  }

  tags = {
    Name = "postgres-hardened"
  }
}

# IAM Role for Enhanced Monitoring
resource "aws_iam_role" "rds_monitoring" {
  name = "examplepay-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "monitoring.rds.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# RDS Instance - Hardened PostgreSQL
resource "aws_db_instance" "postgres_main" {
  identifier = "examplepay-postgres-prod"

  # Engine
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.r6g.xlarge"
  allocated_storage    = 100
  storage_type         = "gp3"
  storage_encrypted    = true
  kms_key_id           = aws_kms_key.rds.arn

  # Database Configuration
  db_name  = "examplepay_production"
  username = "dbadmin"
  manage_master_user_password = true  # AWS manages password in Secrets Manager

  # Network
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false
  port                   = 5432

  # High Availability
  multi_az               = true
  availability_zone      = "us-east-1a"

  # Backup & Maintenance
  backup_retention_period   = 35  # PCI DSS requirement
  backup_window             = "03:00-04:00"  # UTC
  maintenance_window        = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot     = true
  delete_automated_backups  = false
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "examplepay-postgres-final-snapshot"

  # Monitoring
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  monitoring_interval             = 60  # Enhanced monitoring (1 min)
  monitoring_role_arn             = aws_iam_role.rds_monitoring.arn
  performance_insights_enabled    = true
  performance_insights_retention_period = 7

  # Security
  iam_database_authentication_enabled = true
  parameter_group_name                = aws_db_parameter_group.postgres_hardened.name
  auto_minor_version_upgrade          = true

  # Tags
  tags = {
    Name            = "ExamplePay Production DB"
    Environment     = "production"
    Compliance      = "PCI-DSS"
    BackupSchedule  = "daily"
    CostCenter      = "engineering"
    Owner           = "devops@example.com"
    Encryption      = "KMS"
  }
}

# CloudWatch Alarm - High CPU
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "rds-high-cpu-${aws_db_instance.postgres_main.identifier}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "RDS CPU utilization above 80%"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.postgres_main.id
  }
}

# CloudWatch Alarm - Low Storage
resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "rds-low-storage-${aws_db_instance.postgres_main.identifier}"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 10737418240  # 10 GB in bytes
  alarm_description   = "RDS free storage below 10 GB"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.postgres_main.id
  }
}

# Outputs
output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.postgres_main.endpoint
  sensitive   = true
}

output "rds_arn" {
  description = "RDS instance ARN"
  value       = aws_db_instance.postgres_main.arn
}

output "kms_key_id" {
  description = "KMS key ID for RDS encryption"
  value       = aws_kms_key.rds.id
}

# Variables
variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for RDS"
  type        = list(string)
}

variable "application_security_group_id" {
  description = "Security group ID of application tier"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms"
  type        = string
}
