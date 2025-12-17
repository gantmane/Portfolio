# Layered Security Group Configurations
# Author: Evgeniy Gantman
# Purpose: Defense-in-depth security groups for multi-tier architecture
# PCI DSS: Requirement 1.2.3 (Restrict inbound traffic), Requirement 1.3.2 (Limit to DMZ)

# ===========================
# Public Tier Security Groups
# ===========================

# Application Load Balancer security group (public-facing)
resource "aws_security_group" "alb_public" {
  name_prefix = "examplepay-prod-alb-public-"
  description = "Security group for public-facing Application Load Balancer"
  vpc_id      = aws_vpc.production.id

  # HTTPS from internet (PCI DSS Req: Encrypt cardholder data in transit)
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP (redirect to HTTPS)
  ingress {
    description = "HTTP redirect to HTTPS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Egress to application tier only
  egress {
    description     = "To application tier"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }

  tags = {
    Name        = "examplepay-prod-alb-public-sg"
    Tier        = "public"
    Environment = "production"
    Purpose     = "Public ALB ingress"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Bastion host security group
resource "aws_security_group" "bastion" {
  name_prefix = "examplepay-prod-bastion-"
  description = "Security group for bastion hosts (jump boxes)"
  vpc_id      = aws_vpc.production.id

  # SSH from corporate network only
  ingress {
    description = "SSH from corporate network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.corporate_ip_ranges
  }

  # Egress to private subnets for SSH/RDP
  egress {
    description = "SSH to private instances"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [
      var.private_subnet_az1_cidr,
      var.private_subnet_az2_cidr,
      var.private_subnet_az3_cidr
    ]
  }

  egress {
    description = "HTTPS for package updates"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "examplepay-prod-bastion-sg"
    Tier        = "management"
    Environment = "production"
    Purpose     = "Bastion host access"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ===========================
# Private Tier Security Groups
# ===========================

# Application server security group
resource "aws_security_group" "application" {
  name_prefix = "examplepay-prod-app-"
  description = "Security group for application servers (EKS nodes, EC2 app servers)"
  vpc_id      = aws_vpc.production.id

  # HTTP/HTTPS from ALB
  ingress {
    description     = "HTTP from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_public.id]
  }

  # SSH from bastion only
  ingress {
    description     = "SSH from bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  # Allow application-to-application communication (microservices)
  ingress {
    description = "Inter-app communication"
    from_port   = 8080
    to_port     = 8090
    protocol    = "tcp"
    self        = true
  }

  # Egress to database tier
  egress {
    description     = "PostgreSQL to database tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.database.id]
  }

  egress {
    description     = "Redis to cache tier"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.cache.id]
  }

  # Egress for AWS services via VPC endpoints
  egress {
    description = "HTTPS to VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Egress to internet via NAT (for external API calls)
  egress {
    description = "HTTPS to internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "examplepay-prod-app-sg"
    Tier        = "private"
    Environment = "production"
    Purpose     = "Application servers"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# EKS node security group (additional to application SG)
resource "aws_security_group" "eks_nodes" {
  name_prefix = "examplepay-prod-eks-nodes-"
  description = "Security group for EKS worker nodes"
  vpc_id      = aws_vpc.production.id

  # Allow nodes to communicate with each other
  ingress {
    description = "Node-to-node communication"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  # Allow pods to communicate with control plane
  ingress {
    description     = "Webhook admission controllers"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_control_plane.id]
  }

  # Allow kubelet API from control plane
  ingress {
    description     = "Kubelet API from control plane"
    from_port       = 10250
    to_port         = 10250
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_control_plane.id]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name                                        = "examplepay-prod-eks-nodes-sg"
    Tier                                        = "private"
    Environment                                 = "production"
    "kubernetes.io/cluster/examplepay-prod-eks" = "owned"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# EKS control plane security group
resource "aws_security_group" "eks_control_plane" {
  name_prefix = "examplepay-prod-eks-control-plane-"
  description = "Security group for EKS control plane"
  vpc_id      = aws_vpc.production.id

  # Allow control plane to communicate with worker nodes
  egress {
    description     = "To worker nodes kubelet"
    from_port       = 10250
    to_port         = 10250
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
  }

  egress {
    description     = "To worker nodes webhooks"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
  }

  tags = {
    Name        = "examplepay-prod-eks-control-plane-sg"
    Tier        = "private"
    Environment = "production"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ===========================
# Data Tier Security Groups
# ===========================

# Database security group (RDS)
resource "aws_security_group" "database" {
  name_prefix = "examplepay-prod-database-"
  description = "Security group for RDS databases"
  vpc_id      = aws_vpc.production.id

  # PostgreSQL from application tier only
  ingress {
    description     = "PostgreSQL from application tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }

  # No egress rules - database should not initiate outbound connections
  # (except for AWS-managed operations which use ENIs managed by AWS)

  tags = {
    Name        = "examplepay-prod-database-sg"
    Tier        = "data"
    Environment = "production"
    Purpose     = "RDS database access"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Cache security group (ElastiCache Redis)
resource "aws_security_group" "cache" {
  name_prefix = "examplepay-prod-cache-"
  description = "Security group for ElastiCache Redis"
  vpc_id      = aws_vpc.production.id

  # Redis from application tier only
  ingress {
    description     = "Redis from application tier"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }

  tags = {
    Name        = "examplepay-prod-cache-sg"
    Tier        = "data"
    Environment = "production"
    Purpose     = "ElastiCache Redis access"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ===========================
# VPC Endpoints Security Group
# ===========================

resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "examplepay-prod-vpc-endpoints-"
  description = "Security group for VPC interface endpoints"
  vpc_id      = aws_vpc.production.id

  # HTTPS from private subnets
  ingress {
    description = "HTTPS from private subnets"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [
      var.private_subnet_az1_cidr,
      var.private_subnet_az2_cidr,
      var.private_subnet_az3_cidr,
      var.data_subnet_az1_cidr,
      var.data_subnet_az2_cidr,
      var.data_subnet_az3_cidr
    ]
  }

  tags = {
    Name        = "examplepay-prod-vpc-endpoints-sg"
    Environment = "production"
    Purpose     = "VPC endpoint access"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ===========================
# Default Security Group (Deny all)
# ===========================

# Modify default security group to deny all
# PCI DSS: Default deny policy
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.production.id

  # No ingress rules - deny all inbound by default
  # No egress rules - deny all outbound by default

  tags = {
    Name        = "examplepay-prod-default-sg-deny-all"
    Environment = "production"
    Purpose     = "Default deny - DO NOT USE"
  }
}

# ===========================
# Variables
# ===========================

variable "corporate_ip_ranges" {
  description = "Corporate network IP ranges for bastion access"
  type        = list(string)
  default     = ["192.0.2.0/24"]  # Example Corp office
}

# ===========================
# Outputs
# ===========================

output "security_group_ids" {
  description = "Map of security group names to IDs"
  value = {
    alb_public       = aws_security_group.alb_public.id
    bastion          = aws_security_group.bastion.id
    application      = aws_security_group.application.id
    eks_nodes        = aws_security_group.eks_nodes.id
    eks_control_plane = aws_security_group.eks_control_plane.id
    database         = aws_security_group.database.id
    cache            = aws_security_group.cache.id
    vpc_endpoints    = aws_security_group.vpc_endpoints.id
  }
}
