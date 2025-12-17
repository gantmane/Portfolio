# Multi-Tier VPC Network Architecture
# Author: Evgeniy Gantman
# Purpose: Production VPC with defense-in-depth network segmentation
# PCI DSS: Requirement 1.2 (Network Segmentation), Requirement 1.3 (DMZ)

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ===========================
# Production VPC
# ===========================

resource "aws_vpc" "production" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  # Enable VPC Flow Logs (defined in vpc-flow-logs.tf)
  tags = {
    Name        = "examplepay-production-vpc"
    Environment = "production"
    ManagedBy   = "terraform"
    Purpose     = "Production application hosting"
  }
}

# ===========================
# Internet Gateway (Public tier only)
# ===========================

resource "aws_internet_gateway" "production" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name        = "examplepay-prod-igw"
    Environment = "production"
  }
}

# ===========================
# Public Subnets (DMZ) - PCI DSS Req 1.3.1
# ===========================

# Public subnet in AZ-1 (us-east-1a)
resource "aws_subnet" "public_az1" {
  vpc_id                  = aws_vpc.production.id
  cidr_block              = var.public_subnet_az1_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name        = "examplepay-prod-public-az1"
    Tier        = "public"
    Environment = "production"
    "kubernetes.io/role/elb" = "1"  # For AWS Load Balancer Controller
  }
}

# Public subnet in AZ-2 (us-east-1b)
resource "aws_subnet" "public_az2" {
  vpc_id                  = aws_vpc.production.id
  cidr_block              = var.public_subnet_az2_cidr
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true

  tags = {
    Name        = "examplepay-prod-public-az2"
    Tier        = "public"
    Environment = "production"
    "kubernetes.io/role/elb" = "1"
  }
}

# Public subnet in AZ-3 (us-east-1c)
resource "aws_subnet" "public_az3" {
  vpc_id                  = aws_vpc.production.id
  cidr_block              = var.public_subnet_az3_cidr
  availability_zone       = data.aws_availability_zones.available.names[2]
  map_public_ip_on_launch = true

  tags = {
    Name        = "examplepay-prod-public-az3"
    Tier        = "public"
    Environment = "production"
    "kubernetes.io/role/elb" = "1"
  }
}

# ===========================
# NAT Gateways (for private subnet internet access)
# ===========================

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat_az1" {
  domain = "vpc"

  tags = {
    Name = "examplepay-prod-nat-eip-az1"
  }

  depends_on = [aws_internet_gateway.production]
}

resource "aws_eip" "nat_az2" {
  domain = "vpc"

  tags = {
    Name = "examplepay-prod-nat-eip-az2"
  }

  depends_on = [aws_internet_gateway.production]
}

resource "aws_eip" "nat_az3" {
  domain = "vpc"

  tags = {
    Name = "examplepay-prod-nat-eip-az3"
  }

  depends_on = [aws_internet_gateway.production]
}

# NAT Gateway in each AZ for high availability
resource "aws_nat_gateway" "az1" {
  allocation_id = aws_eip.nat_az1.id
  subnet_id     = aws_subnet.public_az1.id

  tags = {
    Name = "examplepay-prod-nat-az1"
  }
}

resource "aws_nat_gateway" "az2" {
  allocation_id = aws_eip.nat_az2.id
  subnet_id     = aws_subnet.public_az2.id

  tags = {
    Name = "examplepay-prod-nat-az2"
  }
}

resource "aws_nat_gateway" "az3" {
  allocation_id = aws_eip.nat_az3.id
  subnet_id     = aws_subnet.public_az3.id

  tags = {
    Name = "examplepay-prod-nat-az3"
  }
}

# ===========================
# Private Subnets (Application tier)
# ===========================

resource "aws_subnet" "private_az1" {
  vpc_id            = aws_vpc.production.id
  cidr_block        = var.private_subnet_az1_cidr
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name        = "examplepay-prod-private-az1"
    Tier        = "private"
    Environment = "production"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_subnet" "private_az2" {
  vpc_id            = aws_vpc.production.id
  cidr_block        = var.private_subnet_az2_cidr
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name        = "examplepay-prod-private-az2"
    Tier        = "private"
    Environment = "production"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_subnet" "private_az3" {
  vpc_id            = aws_vpc.production.id
  cidr_block        = var.private_subnet_az3_cidr
  availability_zone = data.aws_availability_zones.available.names[2]

  tags = {
    Name        = "examplepay-prod-private-az3"
    Tier        = "private"
    Environment = "production"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# ===========================
# Data Subnets (Database tier)
# ===========================

resource "aws_subnet" "data_az1" {
  vpc_id            = aws_vpc.production.id
  cidr_block        = var.data_subnet_az1_cidr
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name        = "examplepay-prod-data-az1"
    Tier        = "data"
    Environment = "production"
  }
}

resource "aws_subnet" "data_az2" {
  vpc_id            = aws_vpc.production.id
  cidr_block        = var.data_subnet_az2_cidr
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name        = "examplepay-prod-data-az2"
    Tier        = "data"
    Environment = "production"
  }
}

resource "aws_subnet" "data_az3" {
  vpc_id            = aws_vpc.production.id
  cidr_block        = var.data_subnet_az3_cidr
  availability_zone = data.aws_availability_zones.available.names[2]

  tags = {
    Name        = "examplepay-prod-data-az3"
    Tier        = "data"
    Environment = "production"
  }
}

# ===========================
# Management Subnet (Bastion, monitoring tools)
# ===========================

resource "aws_subnet" "management" {
  vpc_id            = aws_vpc.production.id
  cidr_block        = var.management_subnet_cidr
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name        = "examplepay-prod-management"
    Tier        = "management"
    Environment = "production"
  }
}

# ===========================
# Route Tables - Public Tier
# ===========================

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name = "examplepay-prod-public-rt"
    Tier = "public"
  }
}

# Route to Internet Gateway
resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.production.id
}

# Associate public subnets with public route table
resource "aws_route_table_association" "public_az1" {
  subnet_id      = aws_subnet.public_az1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_az2" {
  subnet_id      = aws_subnet.public_az2.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_az3" {
  subnet_id      = aws_subnet.public_az3.id
  route_table_id = aws_route_table.public.id
}

# ===========================
# Route Tables - Private Tier (one per AZ for NAT Gateway HA)
# ===========================

# Private route table for AZ-1
resource "aws_route_table" "private_az1" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name = "examplepay-prod-private-az1-rt"
    Tier = "private"
  }
}

resource "aws_route" "private_az1_nat" {
  route_table_id         = aws_route_table.private_az1.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.az1.id
}

resource "aws_route_table_association" "private_az1" {
  subnet_id      = aws_subnet.private_az1.id
  route_table_id = aws_route_table.private_az1.id
}

# Private route table for AZ-2
resource "aws_route_table" "private_az2" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name = "examplepay-prod-private-az2-rt"
    Tier = "private"
  }
}

resource "aws_route" "private_az2_nat" {
  route_table_id         = aws_route_table.private_az2.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.az2.id
}

resource "aws_route_table_association" "private_az2" {
  subnet_id      = aws_subnet.private_az2.id
  route_table_id = aws_route_table.private_az2.id
}

# Private route table for AZ-3
resource "aws_route_table" "private_az3" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name = "examplepay-prod-private-az3-rt"
    Tier = "private"
  }
}

resource "aws_route" "private_az3_nat" {
  route_table_id         = aws_route_table.private_az3.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.az3.id
}

resource "aws_route_table_association" "private_az3" {
  subnet_id      = aws_subnet.private_az3.id
  route_table_id = aws_route_table.private_az3.id
}

# ===========================
# Route Tables - Data Tier (No internet access)
# ===========================

resource "aws_route_table" "data" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name = "examplepay-prod-data-rt"
    Tier = "data"
  }
}

# No default route - data tier has no internet access
# Only local VPC routes and Transit Gateway routes (if configured)

resource "aws_route_table_association" "data_az1" {
  subnet_id      = aws_subnet.data_az1.id
  route_table_id = aws_route_table.data.id
}

resource "aws_route_table_association" "data_az2" {
  subnet_id      = aws_subnet.data_az2.id
  route_table_id = aws_route_table.data.id
}

resource "aws_route_table_association" "data_az3" {
  subnet_id      = aws_subnet.data_az3.id
  route_table_id = aws_route_table.data.id
}

# ===========================
# Route Tables - Management Tier
# ===========================

resource "aws_route_table" "management" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name = "examplepay-prod-management-rt"
    Tier = "management"
  }
}

resource "aws_route" "management_nat" {
  route_table_id         = aws_route_table.management.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.az1.id
}

resource "aws_route_table_association" "management" {
  subnet_id      = aws_subnet.management.id
  route_table_id = aws_route_table.management.id
}

# ===========================
# Variables
# ===========================

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_az1_cidr" {
  description = "CIDR for public subnet AZ1"
  type        = string
  default     = "10.0.0.0/24"
}

variable "public_subnet_az2_cidr" {
  description = "CIDR for public subnet AZ2"
  type        = string
  default     = "10.0.1.0/24"
}

variable "public_subnet_az3_cidr" {
  description = "CIDR for public subnet AZ3"
  type        = string
  default     = "10.0.2.0/24"
}

variable "private_subnet_az1_cidr" {
  description = "CIDR for private subnet AZ1"
  type        = string
  default     = "10.0.16.0/24"
}

variable "private_subnet_az2_cidr" {
  description = "CIDR for private subnet AZ2"
  type        = string
  default     = "10.0.17.0/24"
}

variable "private_subnet_az3_cidr" {
  description = "CIDR for private subnet AZ3"
  type        = string
  default     = "10.0.18.0/24"
}

variable "data_subnet_az1_cidr" {
  description = "CIDR for data subnet AZ1"
  type        = string
  default     = "10.0.32.0/24"
}

variable "data_subnet_az2_cidr" {
  description = "CIDR for data subnet AZ2"
  type        = string
  default     = "10.0.33.0/24"
}

variable "data_subnet_az3_cidr" {
  description = "CIDR for data subnet AZ3"
  type        = string
  default     = "10.0.34.0/24"
}

variable "management_subnet_cidr" {
  description = "CIDR for management subnet"
  type        = string
  default     = "10.0.48.0/24"
}

# ===========================
# Data Sources
# ===========================

data "aws_availability_zones" "available" {
  state = "available"
}

# ===========================
# Outputs
# ===========================

output "vpc_id" {
  description = "Production VPC ID"
  value       = aws_vpc.production.id
}

output "vpc_cidr" {
  description = "Production VPC CIDR"
  value       = aws_vpc.production.cidr_block
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value = [
    aws_subnet.public_az1.id,
    aws_subnet.public_az2.id,
    aws_subnet.public_az3.id
  ]
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value = [
    aws_subnet.private_az1.id,
    aws_subnet.private_az2.id,
    aws_subnet.private_az3.id
  ]
}

output "data_subnet_ids" {
  description = "Data subnet IDs"
  value = [
    aws_subnet.data_az1.id,
    aws_subnet.data_az2.id,
    aws_subnet.data_az3.id
  ]
}

output "management_subnet_id" {
  description = "Management subnet ID"
  value       = aws_subnet.management.id
}

output "nat_gateway_ips" {
  description = "NAT Gateway public IPs"
  value = [
    aws_eip.nat_az1.public_ip,
    aws_eip.nat_az2.public_ip,
    aws_eip.nat_az3.public_ip
  ]
}
