# AWS Transit Gateway for Multi-VPC Connectivity
# Author: Evgeniy Gantman
# Purpose: Hub-and-spoke network topology for centralized routing and security
# PCI DSS: Requirement 1.2.2 (Restrict connections between untrusted networks and CDE)

# Benefits:
# - Centralized routing for 15+ VPCs
# - No VPC peering mesh complexity
# - Controlled CDE isolation with route filtering
# - Simplified network management
# - Support for future expansion (up to 5000 VPCs per TGW)

# ===========================
# Transit Gateway
# ===========================

resource "aws_ec2_transit_gateway" "main" {
  description                     = "ExamplePay multi-account Transit Gateway"
  amazon_side_asn                 = 64512
  auto_accept_shared_attachments  = "disable"  # Require explicit approval
  default_route_table_association = "disable"  # Custom route tables
  default_route_table_propagation = "disable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "enable"

  tags = {
    Name        = "examplepay-tgw"
    Environment = "organization"
    Purpose     = "Multi-VPC connectivity"
    ManagedBy   = "terraform"
  }
}

# ===========================
# Transit Gateway Attachments
# ===========================

# Production VPC attachment
resource "aws_ec2_transit_gateway_vpc_attachment" "production" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.production.id
  subnet_ids = [
    aws_subnet.private_az1.id,
    aws_subnet.private_az2.id,
    aws_subnet.private_az3.id
  ]

  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  dns_support  = "enable"
  ipv6_support = "disable"

  tags = {
    Name        = "examplepay-prod-tgw-attachment"
    Environment = "production"
  }
}

# Development VPC attachment (example)
resource "aws_ec2_transit_gateway_vpc_attachment" "development" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = var.dev_vpc_id
  subnet_ids         = var.dev_subnet_ids

  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  dns_support  = "enable"
  ipv6_support = "disable"

  tags = {
    Name        = "examplepay-dev-tgw-attachment"
    Environment = "development"
  }
}

# CDE VPC attachment (isolated)
resource "aws_ec2_transit_gateway_vpc_attachment" "cde" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = var.cde_vpc_id
  subnet_ids         = var.cde_subnet_ids

  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  dns_support  = "enable"
  ipv6_support = "disable"

  tags = {
    Name        = "examplepay-cde-tgw-attachment"
    Environment = "cde"
    PCIScope    = "in-scope"
  }
}

# Security VPC attachment (shared services)
resource "aws_ec2_transit_gateway_vpc_attachment" "security" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = var.security_vpc_id
  subnet_ids         = var.security_subnet_ids

  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  dns_support  = "enable"
  ipv6_support = "disable"

  tags = {
    Name        = "examplepay-security-tgw-attachment"
    Environment = "security"
    Purpose     = "SIEM, monitoring, security tools"
  }
}

# ===========================
# Transit Gateway Route Tables
# ===========================

# Production route table (can reach dev, security, but NOT CDE)
resource "aws_ec2_transit_gateway_route_table" "production" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = {
    Name        = "examplepay-prod-tgw-rt"
    Environment = "production"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "production" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.production.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.production.id
}

# Routes for production
resource "aws_ec2_transit_gateway_route" "prod_to_dev" {
  destination_cidr_block         = var.dev_vpc_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.development.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.production.id
}

resource "aws_ec2_transit_gateway_route" "prod_to_security" {
  destination_cidr_block         = var.security_vpc_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.security.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.production.id
}

# Development route table (can reach prod, security, but NOT CDE)
resource "aws_ec2_transit_gateway_route_table" "development" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = {
    Name        = "examplepay-dev-tgw-rt"
    Environment = "development"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "development" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.development.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.development.id
}

resource "aws_ec2_transit_gateway_route" "dev_to_prod" {
  destination_cidr_block         = var.vpc_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.production.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.development.id
}

resource "aws_ec2_transit_gateway_route" "dev_to_security" {
  destination_cidr_block         = var.security_vpc_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.security.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.development.id
}

# CDE route table (ISOLATED - only specific routes to security VPC for monitoring)
# PCI DSS Req 1.2.2: Restrict connections between untrusted networks and CDE
resource "aws_ec2_transit_gateway_route_table" "cde" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = {
    Name        = "examplepay-cde-tgw-rt"
    Environment = "cde"
    PCIScope    = "in-scope"
    Purpose     = "Isolated CDE routing - SIEM only"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "cde" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.cde.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.cde.id
}

# CDE can only reach security VPC (for Wazuh SIEM agents)
resource "aws_ec2_transit_gateway_route" "cde_to_security" {
  destination_cidr_block         = "10.10.100.0/24"  # Specific subnet in security VPC for SIEM
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.security.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.cde.id
}

# Security/Shared Services route table (can reach all VPCs for monitoring)
resource "aws_ec2_transit_gateway_route_table" "security" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id

  tags = {
    Name        = "examplepay-security-tgw-rt"
    Environment = "security"
    Purpose     = "Central monitoring and security services"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "security" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.security.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.security.id
}

# Security can reach all VPCs (for monitoring agents)
resource "aws_ec2_transit_gateway_route" "security_to_prod" {
  destination_cidr_block         = var.vpc_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.production.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.security.id
}

resource "aws_ec2_transit_gateway_route" "security_to_dev" {
  destination_cidr_block         = var.dev_vpc_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.development.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.security.id
}

resource "aws_ec2_transit_gateway_route" "security_to_cde" {
  destination_cidr_block         = var.cde_vpc_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.cde.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.security.id
}

# ===========================
# VPC Route Table Updates for Transit Gateway
# ===========================

# Add route to Transit Gateway in production private subnets
resource "aws_route" "private_az1_to_tgw" {
  route_table_id         = aws_route_table.private_az1.id
  destination_cidr_block = "10.0.0.0/8"  # All internal networks
  transit_gateway_id     = aws_ec2_transit_gateway.main.id
}

resource "aws_route" "private_az2_to_tgw" {
  route_table_id         = aws_route_table.private_az2.id
  destination_cidr_block = "10.0.0.0/8"
  transit_gateway_id     = aws_ec2_transit_gateway.main.id
}

resource "aws_route" "private_az3_to_tgw" {
  route_table_id         = aws_route_table.private_az3.id
  destination_cidr_block = "10.0.0.0/8"
  transit_gateway_id     = aws_ec2_transit_gateway.main.id
}

# ===========================
# Transit Gateway RAM Share (for multi-account)
# ===========================

# Share Transit Gateway with other AWS accounts in organization
resource "aws_ram_resource_share" "tgw" {
  name                      = "examplepay-tgw-share"
  allow_external_principals = false

  tags = {
    Name = "examplepay-tgw-share"
  }
}

resource "aws_ram_resource_association" "tgw" {
  resource_arn       = aws_ec2_transit_gateway.main.arn
  resource_share_arn = aws_ram_resource_share.tgw.arn
}

# Share with organization (all accounts can attach)
resource "aws_ram_principal_association" "tgw_org" {
  principal          = "arn:aws:organizations::111122223333:organization/o-exampleorgid"
  resource_share_arn = aws_ram_resource_share.tgw.arn
}

# ===========================
# CloudWatch Monitoring
# ===========================

# Monitor Transit Gateway bytes processed
resource "aws_cloudwatch_metric_alarm" "tgw_high_traffic" {
  alarm_name          = "tgw-high-traffic-volume"
  alarm_description   = "Alert on unusually high Transit Gateway traffic"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BytesOut"
  namespace           = "AWS/TransitGateway"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10737418240"  # 10 GB in 5 minutes
  treat_missing_data  = "notBreaching"

  dimensions = {
    TransitGateway = aws_ec2_transit_gateway.main.id
  }

  alarm_actions = [
    "arn:aws:sns:us-east-1:${data.aws_caller_identity.current.account_id}:security-alerts"
  ]

  tags = {
    Severity = "Medium"
    Purpose  = "Network anomaly detection"
  }
}

# ===========================
# Variables
# ===========================

variable "dev_vpc_id" {
  description = "Development VPC ID"
  type        = string
  default     = "vpc-dev123456789"
}

variable "dev_subnet_ids" {
  description = "Development VPC subnet IDs for TGW attachment"
  type        = list(string)
  default     = ["subnet-dev1", "subnet-dev2"]
}

variable "dev_vpc_cidr" {
  description = "Development VPC CIDR"
  type        = string
  default     = "10.1.0.0/16"
}

variable "cde_vpc_id" {
  description = "CDE VPC ID"
  type        = string
  default     = "vpc-cde123456789"
}

variable "cde_subnet_ids" {
  description = "CDE VPC subnet IDs for TGW attachment"
  type        = list(string)
  default     = ["subnet-cde1", "subnet-cde2"]
}

variable "cde_vpc_cidr" {
  description = "CDE VPC CIDR"
  type        = string
  default     = "10.100.0.0/16"
}

variable "security_vpc_id" {
  description = "Security VPC ID"
  type        = string
  default     = "vpc-sec123456789"
}

variable "security_subnet_ids" {
  description = "Security VPC subnet IDs for TGW attachment"
  type        = list(string)
  default     = ["subnet-sec1", "subnet-sec2"]
}

variable "security_vpc_cidr" {
  description = "Security VPC CIDR"
  type        = string
  default     = "10.10.0.0/16"
}

# ===========================
# Outputs
# ===========================

output "transit_gateway_id" {
  description = "Transit Gateway ID"
  value       = aws_ec2_transit_gateway.main.id
}

output "transit_gateway_attachments" {
  description = "Transit Gateway VPC attachments"
  value = {
    production  = aws_ec2_transit_gateway_vpc_attachment.production.id
    development = aws_ec2_transit_gateway_vpc_attachment.development.id
    cde         = aws_ec2_transit_gateway_vpc_attachment.cde.id
    security    = aws_ec2_transit_gateway_vpc_attachment.security.id
  }
}

output "transit_gateway_route_tables" {
  description = "Transit Gateway route table IDs"
  value = {
    production  = aws_ec2_transit_gateway_route_table.production.id
    development = aws_ec2_transit_gateway_route_table.development.id
    cde         = aws_ec2_transit_gateway_route_table.cde.id
    security    = aws_ec2_transit_gateway_route_table.security.id
  }
}

output "network_topology" {
  description = "Network connectivity summary"
  value = {
    topology = "Hub-and-spoke via Transit Gateway"
    vpcs_connected = "15+"
    cde_isolation = "CDE can only reach Security VPC SIEM subnet"
    pci_compliance = "PCI DSS Req 1.2.2 - CDE isolated from untrusted networks"
  }
}
