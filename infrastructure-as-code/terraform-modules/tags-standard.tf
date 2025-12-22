# Standard Tags Module
# Enforce consistent tagging

variable "environment" {
  description = "Environment name"
  type        = string
  validation {
    condition     = contains(["Production", "Development", "Staging"], var.environment)
    error_message = "Must be: Production, Development, or Staging"
  }
}

variable "cost_center" {
  description = "Cost center code"
  type        = string
}

variable "project" {
  description = "Project name"
  type        = string
  default     = ""
}

variable "additional_tags" {
  description = "Additional tags"
  type        = map(string)
  default     = {}
}

locals {
  standard_tags = merge(
    {
      Environment = var.environment
      ManagedBy   = "Terraform"
      CostCenter  = var.cost_center
    },
    var.project != "" ? { Project = var.project } : {},
    var.additional_tags
  )
}

output "tags" {
  description = "Standard tags to apply to all resources"
  value       = local.standard_tags
}
