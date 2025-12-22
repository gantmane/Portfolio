# AWS Secure VPC Module
# Author: Evgeniy Gantman
# Purpose: Create secure VPC with private/public subnets
# Compliance: PCI DSS 1.3, CIS AWS 5.1

# =======================
# Variables
# =======================

variable "vpc_name" {
  description = "Name of the VPC"
  type        = string

  validation {
    condition     = length(var.vpc_name) > 0
    error_message = "VPC name cannot be empty."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "Must be a valid IPv4 CIDR block."
  }
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)

  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "Must specify at least 2 availability zones for high availability."
  }
}

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "flow_logs_retention" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.flow_logs_retention)
    error_message = "Must be a valid CloudWatch Logs retention period."
  }
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# =======================
# VPC
# =======================

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(
    var.tags,
    {
      Name      = var.vpc_name
      ManagedBy = "Terraform"
    }
  )
}

# =======================
# Internet Gateway
# =======================

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    var.tags,
    {
      Name      = "${var.vpc_name}-igw"
      ManagedBy = "Terraform"
    }
  )
}

# =======================
# Public Subnets
# =======================

resource "aws_subnet" "public" {
  count = length(var.availability_zones)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false  # Security: don't auto-assign public IPs

  tags = merge(
    var.tags,
    {
      Name      = "${var.vpc_name}-public-${var.availability_zones[count.index]}"
      Type      = "Public"
      ManagedBy = "Terraform"
    }
  )
}

# =======================
# Private Subnets
# =======================

resource "aws_subnet" "private" {
  count = length(var.availability_zones)

  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 100)
  availability_zone = var.availability_zones[count.index]

  tags = merge(
    var.tags,
    {
      Name      = "${var.vpc_name}-private-${var.availability_zones[count.index]}"
      Type      = "Private"
      ManagedBy = "Terraform"
    }
  )
}

# =======================
# Elastic IPs for NAT Gateways
# =======================

resource "aws_eip" "nat" {
  count = length(var.availability_zones)

  domain = "vpc"

  tags = merge(
    var.tags,
    {
      Name      = "${var.vpc_name}-nat-eip-${var.availability_zones[count.index]}"
      ManagedBy = "Terraform"
    }
  )

  depends_on = [aws_internet_gateway.main]
}

# =======================
# NAT Gateways
# =======================

resource "aws_nat_gateway" "main" {
  count = length(var.availability_zones)

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(
    var.tags,
    {
      Name      = "${var.vpc_name}-nat-${var.availability_zones[count.index]}"
      ManagedBy = "Terraform"
    }
  )

  depends_on = [aws_internet_gateway.main]
}

# =======================
# Route Tables
# =======================

# Public route table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    var.tags,
    {
      Name      = "${var.vpc_name}-public-rt"
      Type      = "Public"
      ManagedBy = "Terraform"
    }
  )
}

# Route to internet via IGW
resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

# Associate public subnets with public route table
resource "aws_route_table_association" "public" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private route tables (one per AZ for high availability)
resource "aws_route_table" "private" {
  count = length(var.availability_zones)

  vpc_id = aws_vpc.main.id

  tags = merge(
    var.tags,
    {
      Name      = "${var.vpc_name}-private-rt-${var.availability_zones[count.index]}"
      Type      = "Private"
      ManagedBy = "Terraform"
    }
  )
}

# Route to internet via NAT Gateway
resource "aws_route" "private_internet" {
  count = length(var.availability_zones)

  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[count.index].id
}

# Associate private subnets with private route tables
resource "aws_route_table_association" "private" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# =======================
# VPC Flow Logs
# =======================

resource "aws_flow_log" "main" {
  count = var.enable_flow_logs ? 1 : 0

  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs[0].arn
  log_destination = aws_cloudwatch_log_group.flow_logs[0].arn

  tags = merge(
    var.tags,
    {
      Name      = "${var.vpc_name}-flow-logs"
      ManagedBy = "Terraform"
    }
  )
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name              = "/aws/vpc/${var.vpc_name}/flow-logs"
  retention_in_days = var.flow_logs_retention

  tags = merge(
    var.tags,
    {
      Name      = "${var.vpc_name}-flow-logs"
      ManagedBy = "Terraform"
    }
  )
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name = "${var.vpc_name}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(
    var.tags,
    {
      Name      = "${var.vpc_name}-flow-logs-role"
      ManagedBy = "Terraform"
    }
  )
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name = "${var.vpc_name}-flow-logs-policy"
  role = aws_iam_role.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# =======================
# Outputs
# =======================

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "VPC CIDR block"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "List of public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "nat_gateway_ids" {
  description = "List of NAT Gateway IDs"
  value       = aws_nat_gateway.main[*].id
}

output "internet_gateway_id" {
  description = "Internet Gateway ID"
  value       = aws_internet_gateway.main.id
}

output "flow_logs_log_group" {
  description = "CloudWatch Log Group for VPC Flow Logs"
  value       = var.enable_flow_logs ? aws_cloudwatch_log_group.flow_logs[0].name : null
}
