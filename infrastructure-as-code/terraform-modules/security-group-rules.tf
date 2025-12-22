# Security Group Rules Module
# Standardized rule sets for common use cases

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "rule_set" {
  description = "Rule set: web, database, internal"
  type        = string
  validation {
    condition     = contains(["web", "database", "internal"], var.rule_set)
    error_message = "Must be: web, database, or internal"
  }
}

variable "allowed_cidr_blocks" {
  description = "Allowed CIDR blocks"
  type        = list(string)
  default     = []
}

locals {
  web_ports = [
    { from_port = 443, to_port = 443, protocol = "tcp" },
    { from_port = 80, to_port = 80, protocol = "tcp" }
  ]

  database_ports = {
    postgres = { from_port = 5432, to_port = 5432, protocol = "tcp" }
    mysql    = { from_port = 3306, to_port = 3306, protocol = "tcp" }
  }
}

resource "aws_security_group" "main" {
  name_prefix = "${var.rule_set}-sg-"
  vpc_id      = var.vpc_id

  tags = {
    Name      = "${var.rule_set}-security-group"
    ManagedBy = "Terraform"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "web_ingress" {
  for_each = var.rule_set == "web" ? { for idx, port in local.web_ports : idx => port } : {}

  type              = "ingress"
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  protocol          = each.value.protocol
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.main.id
}

resource "aws_security_group_rule" "egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.main.id
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.main.id
}
