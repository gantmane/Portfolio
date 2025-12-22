# IAM Role with Least Privilege Policy Module

variable "role_name" {
  description = "Name of the IAM role"
  type        = string
}

variable "assume_role_service" {
  description = "AWS service that can assume this role"
  type        = string
  default     = "ec2.amazonaws.com"
}

variable "policy_actions" {
  description = "List of IAM policy actions"
  type        = list(string)
}

variable "policy_resources" {
  description = "List of resource ARNs"
  type        = list(string)
}

resource "aws_iam_role" "main" {
  name = var.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = var.assume_role_service
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name      = var.role_name
    ManagedBy = "Terraform"
  }
}

resource "aws_iam_role_policy" "main" {
  name = "${var.role_name}-policy"
  role = aws_iam_role.main.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = var.policy_actions
      Resource = var.policy_resources
    }]
  })
}

output "role_arn" {
  description = "IAM role ARN"
  value       = aws_iam_role.main.arn
}

output "role_name" {
  description = "IAM role name"
  value       = aws_iam_role.main.name
}
