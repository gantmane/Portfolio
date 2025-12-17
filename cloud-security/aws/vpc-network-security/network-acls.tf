# Network Access Control Lists (Stateless Filtering)
# Author: Evgeniy Gantman
# Purpose: Subnet-level stateless filtering for defense-in-depth
# PCI DSS: Requirement 1.2.1 (Restrict inbound/outbound), Requirement 1.3 (DMZ)

# Note: NACLs provide an additional layer of security beyond security groups
# Security groups are stateful (return traffic allowed automatically)
# NACLs are stateless (must explicitly allow both inbound and outbound)

# ===========================
# Public Subnet NACL (DMZ)
# ===========================

resource "aws_network_acl" "public" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name        = "examplepay-prod-public-nacl"
    Tier        = "public"
    Environment = "production"
  }
}

# Associate with public subnets
resource "aws_network_acl_association" "public_az1" {
  subnet_id      = aws_subnet.public_az1.id
  network_acl_id = aws_network_acl.public.id
}

resource "aws_network_acl_association" "public_az2" {
  subnet_id      = aws_subnet.public_az2.id
  network_acl_id = aws_network_acl.public.id
}

resource "aws_network_acl_association" "public_az3" {
  subnet_id      = aws_subnet.public_az3.id
  network_acl_id = aws_network_acl.public.id
}

# Inbound rules for public NACL
resource "aws_network_acl_rule" "public_inbound_http" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 80
  to_port        = 80
}

resource "aws_network_acl_rule" "public_inbound_https" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

# Ephemeral ports for return traffic
resource "aws_network_acl_rule" "public_inbound_ephemeral" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 120
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# SSH from corporate network only
resource "aws_network_acl_rule" "public_inbound_ssh_corporate" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 130
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "192.0.2.0/24"  # Corporate network
  from_port      = 22
  to_port        = 22
}

# Outbound rules for public NACL
resource "aws_network_acl_rule" "public_outbound_http" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 80
  to_port        = 80
}

resource "aws_network_acl_rule" "public_outbound_https" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 110
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

# Ephemeral ports for response traffic
resource "aws_network_acl_rule" "public_outbound_ephemeral" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 120
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# Allow outbound to private subnets (app tier)
resource "aws_network_acl_rule" "public_outbound_to_private" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 130
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.16.0/20"  # Private subnet range
  from_port      = 8080
  to_port        = 8080
}

# ===========================
# Private Subnet NACL (Application tier)
# ===========================

resource "aws_network_acl" "private" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name        = "examplepay-prod-private-nacl"
    Tier        = "private"
    Environment = "production"
  }
}

# Associate with private subnets
resource "aws_network_acl_association" "private_az1" {
  subnet_id      = aws_subnet.private_az1.id
  network_acl_id = aws_network_acl.private.id
}

resource "aws_network_acl_association" "private_az2" {
  subnet_id      = aws_subnet.private_az2.id
  network_acl_id = aws_network_acl.private.id
}

resource "aws_network_acl_association" "private_az3" {
  subnet_id      = aws_subnet.private_az3.id
  network_acl_id = aws_network_acl.private.id
}

# Inbound rules for private NACL
# From public subnet (ALB)
resource "aws_network_acl_rule" "private_inbound_from_public" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/20"  # Public subnet range
  from_port      = 8080
  to_port        = 8080
}

# From other private subnets (microservices communication)
resource "aws_network_acl_rule" "private_inbound_from_private" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.16.0/20"  # Private subnet range
  from_port      = 8080
  to_port        = 8090
}

# SSH from management subnet (bastion)
resource "aws_network_acl_rule" "private_inbound_ssh_from_management" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 120
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = var.management_subnet_cidr
  from_port      = 22
  to_port        = 22
}

# Ephemeral ports for return traffic
resource "aws_network_acl_rule" "private_inbound_ephemeral" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 130
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# Outbound rules for private NACL
# To database tier
resource "aws_network_acl_rule" "private_outbound_to_database" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 100
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.32.0/20"  # Data subnet range
  from_port      = 5432
  to_port        = 5432
}

# To cache tier
resource "aws_network_acl_rule" "private_outbound_to_cache" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 110
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.32.0/20"  # Data subnet range
  from_port      = 6379
  to_port        = 6379
}

# HTTPS to internet (via NAT Gateway)
resource "aws_network_acl_rule" "private_outbound_https" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 120
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

# To other private subnets (microservices)
resource "aws_network_acl_rule" "private_outbound_to_private" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 130
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.16.0/20"
  from_port      = 8080
  to_port        = 8090
}

# Ephemeral ports for response traffic
resource "aws_network_acl_rule" "private_outbound_ephemeral" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 140
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# ===========================
# Data Subnet NACL (Database tier)
# ===========================

resource "aws_network_acl" "data" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name        = "examplepay-prod-data-nacl"
    Tier        = "data"
    Environment = "production"
  }
}

# Associate with data subnets
resource "aws_network_acl_association" "data_az1" {
  subnet_id      = aws_subnet.data_az1.id
  network_acl_id = aws_network_acl.data.id
}

resource "aws_network_acl_association" "data_az2" {
  subnet_id      = aws_subnet.data_az2.id
  network_acl_id = aws_network_acl.data.id
}

resource "aws_network_acl_association" "data_az3" {
  subnet_id      = aws_subnet.data_az3.id
  network_acl_id = aws_network_acl.data.id
}

# Inbound rules for data NACL
# PostgreSQL from private subnet only
resource "aws_network_acl_rule" "data_inbound_postgres" {
  network_acl_id = aws_network_acl.data.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.16.0/20"  # Private subnet range
  from_port      = 5432
  to_port        = 5432
}

# Redis from private subnet only
resource "aws_network_acl_rule" "data_inbound_redis" {
  network_acl_id = aws_network_acl.data.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.16.0/20"
  from_port      = 6379
  to_port        = 6379
}

# Ephemeral ports for return traffic
resource "aws_network_acl_rule" "data_inbound_ephemeral" {
  network_acl_id = aws_network_acl.data.id
  rule_number    = 120
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.16.0/20"
  from_port      = 1024
  to_port        = 65535
}

# Outbound rules for data NACL
# Ephemeral ports for response traffic to private subnet
resource "aws_network_acl_rule" "data_outbound_ephemeral" {
  network_acl_id = aws_network_acl.data.id
  rule_number    = 100
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.16.0/20"  # Private subnet range
  from_port      = 1024
  to_port        = 65535
}

# ===========================
# Management Subnet NACL
# ===========================

resource "aws_network_acl" "management" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name        = "examplepay-prod-management-nacl"
    Tier        = "management"
    Environment = "production"
  }
}

resource "aws_network_acl_association" "management" {
  subnet_id      = aws_subnet.management.id
  network_acl_id = aws_network_acl.management.id
}

# Inbound SSH from corporate network
resource "aws_network_acl_rule" "management_inbound_ssh" {
  network_acl_id = aws_network_acl.management.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "192.0.2.0/24"  # Corporate network
  from_port      = 22
  to_port        = 22
}

# Ephemeral ports for return traffic
resource "aws_network_acl_rule" "management_inbound_ephemeral" {
  network_acl_id = aws_network_acl.management.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# Outbound SSH to private subnets
resource "aws_network_acl_rule" "management_outbound_ssh" {
  network_acl_id = aws_network_acl.management.id
  rule_number    = 100
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.16.0/20"  # Private subnet range
  from_port      = 22
  to_port        = 22
}

# HTTPS for updates
resource "aws_network_acl_rule" "management_outbound_https" {
  network_acl_id = aws_network_acl.management.id
  rule_number    = 110
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

# Ephemeral ports
resource "aws_network_acl_rule" "management_outbound_ephemeral" {
  network_acl_id = aws_network_acl.management.id
  rule_number    = 120
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# ===========================
# Explicit Deny Rules (Optional - for known threats)
# ===========================

# Example: Block known malicious IP ranges
# Deny rules must have lower rule numbers (processed first)

resource "aws_network_acl_rule" "public_deny_malicious_inbound" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 50  # Processed before allow rules
  egress         = false
  protocol       = -1  # All protocols
  rule_action    = "deny"
  cidr_block     = "198.51.100.0/24"  # Example malicious IP range
}

# ===========================
# Outputs
# ===========================

output "network_acl_ids" {
  description = "Map of Network ACL names to IDs"
  value = {
    public     = aws_network_acl.public.id
    private    = aws_network_acl.private.id
    data       = aws_network_acl.data.id
    management = aws_network_acl.management.id
  }
}
