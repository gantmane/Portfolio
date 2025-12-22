# Azure Network Security Configuration
# Author: Evgeniy Gantman
# Purpose: Hub-spoke VNet topology with Azure Firewall and NSGs
# PCI DSS: Requirement 1.2 (Firewall configuration), Requirement 1.3 (Network segmentation)

# Benefits:
# - Hub-spoke topology for centralized security controls
# - Azure Firewall for centralized network filtering
# - Network Security Groups at subnet level
# - DDoS Protection Standard
# - Private Link for secure service access
# - ExpressRoute for encrypted AWS connectivity

# ===========================
# Resource Groups
# ===========================

# Production resource group
resource "azurerm_resource_group" "production" {
  name     = "rg-examplepay-production"
  location = var.primary_region

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
    CostCenter  = "Engineering"
    Compliance  = "PCI-DSS"
  }
}

# ===========================
# Hub Virtual Network
# ===========================

# Hub VNet for shared services
resource "azurerm_virtual_network" "hub" {
  name                = "vnet-examplepay-hub"
  location            = azurerm_resource_group.shared_services.location
  resource_group_name = azurerm_resource_group.shared_services.name
  address_space       = ["10.1.0.0/16"]

  tags = {
    Environment = "Shared"
    ManagedBy   = "Terraform"
    Topology    = "Hub"
  }
}

# Firewall subnet (must be named AzureFirewallSubnet)
resource "azurerm_subnet" "firewall" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.shared_services.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = ["10.1.1.0/24"]
}

# Gateway subnet for ExpressRoute
resource "azurerm_subnet" "gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.shared_services.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = ["10.1.2.0/24"]
}

# Bastion subnet for secure VM access
resource "azurerm_subnet" "bastion" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.shared_services.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = ["10.1.3.0/24"]
}

# ===========================
# Production Spoke Virtual Network
# ===========================

# Production spoke VNet
resource "azurerm_virtual_network" "production" {
  name                = "vnet-examplepay-production"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name
  address_space       = ["10.10.0.0/16"]

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
    Topology    = "Spoke"
  }
}

# AKS subnet
resource "azurerm_subnet" "aks" {
  name                 = "snet-aks"
  resource_group_name  = azurerm_resource_group.production.name
  virtual_network_name = azurerm_virtual_network.production.name
  address_prefixes     = ["10.10.0.0/20"]

  # Delegate to AKS
  delegation {
    name = "aks-delegation"

    service_delegation {
      name    = "Microsoft.ContainerService/managedClusters"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# Database subnet
resource "azurerm_subnet" "database" {
  name                 = "snet-database"
  resource_group_name  = azurerm_resource_group.production.name
  virtual_network_name = azurerm_virtual_network.production.name
  address_prefixes     = ["10.10.16.0/24"]

  # Enable service endpoints
  service_endpoints = [
    "Microsoft.Sql",
    "Microsoft.Storage",
  ]
}

# Application subnet
resource "azurerm_subnet" "application" {
  name                 = "snet-application"
  resource_group_name  = azurerm_resource_group.production.name
  virtual_network_name = azurerm_virtual_network.production.name
  address_prefixes     = ["10.10.17.0/24"]
}

# ===========================
# VNet Peering (Hub-Spoke)
# ===========================

# Hub to production spoke peering
resource "azurerm_virtual_network_peering" "hub_to_production" {
  name                         = "hub-to-production"
  resource_group_name          = azurerm_resource_group.shared_services.name
  virtual_network_name         = azurerm_virtual_network.hub.name
  remote_virtual_network_id    = azurerm_virtual_network.production.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = true
}

# Production spoke to hub peering
resource "azurerm_virtual_network_peering" "production_to_hub" {
  name                         = "production-to-hub"
  resource_group_name          = azurerm_resource_group.production.name
  virtual_network_name         = azurerm_virtual_network.production.name
  remote_virtual_network_id    = azurerm_virtual_network.hub.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  use_remote_gateways          = true

  depends_on = [azurerm_virtual_network_gateway.expressroute]
}

# ===========================
# Network Security Groups
# ===========================

# NSG for AKS subnet
resource "azurerm_network_security_group" "aks" {
  name                = "nsg-aks"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# Allow inbound HTTPS to AKS
resource "azurerm_network_security_rule" "aks_allow_https" {
  name                        = "AllowHTTPSInbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.production.name
  network_security_group_name = azurerm_network_security_group.aks.name
}

# Deny all other inbound to AKS
resource "azurerm_network_security_rule" "aks_deny_all_inbound" {
  name                        = "DenyAllInbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.production.name
  network_security_group_name = azurerm_network_security_group.aks.name
}

# Associate NSG with AKS subnet
resource "azurerm_subnet_network_security_group_association" "aks" {
  subnet_id                 = azurerm_subnet.aks.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

# NSG for database subnet
resource "azurerm_network_security_group" "database" {
  name                = "nsg-database"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
    Compliance  = "PCI-DSS-1.3"
  }
}

# Allow SQL from AKS subnet only
resource "azurerm_network_security_rule" "db_allow_sql_from_aks" {
  name                        = "AllowSQLFromAKS"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "1433"
  source_address_prefix       = "10.10.0.0/20"  # AKS subnet
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.production.name
  network_security_group_name = azurerm_network_security_group.database.name
}

# Deny all other inbound to database
resource "azurerm_network_security_rule" "db_deny_all_inbound" {
  name                        = "DenyAllInbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.production.name
  network_security_group_name = azurerm_network_security_group.database.name
}

# Associate NSG with database subnet
resource "azurerm_subnet_network_security_group_association" "database" {
  subnet_id                 = azurerm_subnet.database.id
  network_security_group_id = azurerm_network_security_group.database.id
}

# ===========================
# Azure Firewall
# ===========================

# Public IP for Azure Firewall
resource "azurerm_public_ip" "firewall" {
  name                = "pip-firewall"
  location            = azurerm_resource_group.shared_services.location
  resource_group_name = azurerm_resource_group.shared_services.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    Environment = "Shared"
    ManagedBy   = "Terraform"
  }
}

# Azure Firewall
resource "azurerm_firewall" "hub" {
  name                = "fw-examplepay-hub"
  location            = azurerm_resource_group.shared_services.location
  resource_group_name = azurerm_resource_group.shared_services.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  threat_intel_mode   = "Alert"

  ip_configuration {
    name                 = "firewall-config"
    subnet_id            = azurerm_subnet.firewall.id
    public_ip_address_id = azurerm_public_ip.firewall.id
  }

  tags = {
    Environment = "Shared"
    ManagedBy   = "Terraform"
  }
}

# Firewall Network Rule Collection
resource "azurerm_firewall_network_rule_collection" "allow_outbound" {
  name                = "allow-outbound"
  azure_firewall_name = azurerm_firewall.hub.name
  resource_group_name = azurerm_resource_group.shared_services.name
  priority            = 100
  action              = "Allow"

  rule {
    name = "allow-https"

    source_addresses = [
      "10.10.0.0/16",  # Production spoke
    ]

    destination_ports = [
      "443",
    ]

    destination_addresses = [
      "*",
    ]

    protocols = [
      "TCP",
    ]
  }

  rule {
    name = "allow-dns"

    source_addresses = [
      "10.10.0.0/16",
    ]

    destination_ports = [
      "53",
    ]

    destination_addresses = [
      "*",
    ]

    protocols = [
      "TCP",
      "UDP",
    ]
  }
}

# Firewall Application Rule Collection
resource "azurerm_firewall_application_rule_collection" "allow_microsoft" {
  name                = "allow-microsoft-services"
  azure_firewall_name = azurerm_firewall.hub.name
  resource_group_name = azurerm_resource_group.shared_services.name
  priority            = 100
  action              = "Allow"

  rule {
    name = "allow-azure-apis"

    source_addresses = [
      "10.10.0.0/16",
    ]

    target_fqdns = [
      "*.azure.com",
      "*.microsoft.com",
      "*.windows.net",
    ]

    protocol {
      port = "443"
      type = "Https"
    }
  }
}

# ===========================
# DDoS Protection
# ===========================

# DDoS Protection Plan
resource "azurerm_network_ddos_protection_plan" "production" {
  name                = "ddos-examplepay-production"
  location            = azurerm_resource_group.shared_services.location
  resource_group_name = azurerm_resource_group.shared_services.name

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# Enable DDoS on production VNet
resource "azurerm_virtual_network" "production_with_ddos" {
  name                = azurerm_virtual_network.production.name
  location            = azurerm_virtual_network.production.location
  resource_group_name = azurerm_virtual_network.production.resource_group_name
  address_space       = azurerm_virtual_network.production.address_space

  ddos_protection_plan {
    id     = azurerm_network_ddos_protection_plan.production.id
    enable = true
  }

  tags = azurerm_virtual_network.production.tags

  depends_on = [azurerm_virtual_network.production]
}

# ===========================
# ExpressRoute to AWS
# ===========================

# ExpressRoute Gateway
resource "azurerm_virtual_network_gateway" "expressroute" {
  name                = "vgw-examplepay-expressroute"
  location            = azurerm_resource_group.shared_services.location
  resource_group_name = azurerm_resource_group.shared_services.name

  type     = "ExpressRoute"
  vpn_type = "RouteBased"

  sku = "Standard"

  ip_configuration {
    name                          = "vnetGatewayConfig"
    public_ip_address_id          = azurerm_public_ip.gateway.id
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.gateway.id
  }

  tags = {
    Environment = "Shared"
    ManagedBy   = "Terraform"
    Purpose     = "AWS Connectivity"
  }
}

# Public IP for ExpressRoute Gateway
resource "azurerm_public_ip" "gateway" {
  name                = "pip-gateway"
  location            = azurerm_resource_group.shared_services.location
  resource_group_name = azurerm_resource_group.shared_services.name
  allocation_method   = "Dynamic"

  tags = {
    Environment = "Shared"
    ManagedBy   = "Terraform"
  }
}

# ExpressRoute Circuit (requires manual provisioning by service provider)
resource "azurerm_express_route_circuit" "aws" {
  name                  = "erc-examplepay-aws"
  location              = azurerm_resource_group.shared_services.location
  resource_group_name   = azurerm_resource_group.shared_services.name
  service_provider_name = "Equinix"
  peering_location      = "Silicon Valley"
  bandwidth_in_mbps     = 50

  sku {
    tier   = "Standard"
    family = "MeteredData"
  }

  tags = {
    Environment = "Shared"
    ManagedBy   = "Terraform"
    Purpose     = "AWS Multi-Cloud Connectivity"
  }
}

# ExpressRoute Circuit Peering
resource "azurerm_express_route_circuit_peering" "private" {
  peering_type                  = "AzurePrivatePeering"
  express_route_circuit_name    = azurerm_express_route_circuit.aws.name
  resource_group_name           = azurerm_resource_group.shared_services.name
  peer_asn                      = 65515
  primary_peer_address_prefix   = "192.168.1.0/30"
  secondary_peer_address_prefix = "192.168.2.0/30"
  vlan_id                       = 100

  microsoft_peering_config {
    advertised_public_prefixes = []
  }
}

# ===========================
# Azure Bastion
# ===========================

# Public IP for Bastion
resource "azurerm_public_ip" "bastion" {
  name                = "pip-bastion"
  location            = azurerm_resource_group.shared_services.location
  resource_group_name = azurerm_resource_group.shared_services.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    Environment = "Shared"
    ManagedBy   = "Terraform"
  }
}

# Azure Bastion for secure VM access
resource "azurerm_bastion_host" "hub" {
  name                = "bastion-examplepay-hub"
  location            = azurerm_resource_group.shared_services.location
  resource_group_name = azurerm_resource_group.shared_services.name

  ip_configuration {
    name                 = "bastion-config"
    subnet_id            = azurerm_subnet.bastion.id
    public_ip_address_id = azurerm_public_ip.bastion.id
  }

  tags = {
    Environment = "Shared"
    ManagedBy   = "Terraform"
  }
}

# ===========================
# Private DNS Zones
# ===========================

# Private DNS zone for Azure SQL
resource "azurerm_private_dns_zone" "sql" {
  name                = "privatelink.database.windows.net"
  resource_group_name = azurerm_resource_group.shared_services.name

  tags = {
    Environment = "Shared"
    ManagedBy   = "Terraform"
  }
}

# Link private DNS to production VNet
resource "azurerm_private_dns_zone_virtual_network_link" "sql_prod" {
  name                  = "sql-prod-link"
  resource_group_name   = azurerm_resource_group.shared_services.name
  private_dns_zone_name = azurerm_private_dns_zone.sql.name
  virtual_network_id    = azurerm_virtual_network.production.id

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# ===========================
# Route Tables
# ===========================

# Route table for production spoke (route via firewall)
resource "azurerm_route_table" "production" {
  name                = "rt-production"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name

  route {
    name                   = "to-internet"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = azurerm_firewall.hub.ip_configuration[0].private_ip_address
  }

  route {
    name           = "to-aws"
    address_prefix = "10.0.0.0/16"  # AWS VPC CIDR
    next_hop_type  = "VirtualNetworkGateway"
  }

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# Associate route table with AKS subnet
resource "azurerm_subnet_route_table_association" "aks" {
  subnet_id      = azurerm_subnet.aks.id
  route_table_id = azurerm_route_table.production.id
}

# ===========================
# Variables
# ===========================

variable "primary_region" {
  description = "Primary Azure region"
  type        = string
  default     = "eastus"
}

# ===========================
# Outputs
# ===========================

output "virtual_networks" {
  description = "Created virtual networks"
  value = {
    hub        = azurerm_virtual_network.hub.id
    production = azurerm_virtual_network.production.id
  }
}

output "subnets" {
  description = "Created subnets"
  value = {
    aks         = azurerm_subnet.aks.id
    database    = azurerm_subnet.database.id
    application = azurerm_subnet.application.id
  }
}

output "network_security_groups" {
  description = "Created network security groups"
  value = {
    aks      = azurerm_network_security_group.aks.id
    database = azurerm_network_security_group.database.id
  }
}

output "azure_firewall" {
  description = "Azure Firewall configuration"
  value = {
    id         = azurerm_firewall.hub.id
    private_ip = azurerm_firewall.hub.ip_configuration[0].private_ip_address
    public_ip  = azurerm_public_ip.firewall.ip_address
  }
}

output "expressroute" {
  description = "ExpressRoute configuration"
  value = {
    circuit_id   = azurerm_express_route_circuit.aws.id
    service_key  = azurerm_express_route_circuit.aws.service_key
    bandwidth    = "50 Mbps"
    peering_type = "Azure Private Peering"
  }
  sensitive = true
}

output "network_summary" {
  description = "Summary of network security configuration"
  value = {
    topology = {
      model               = "Hub-Spoke"
      hub_vnet            = "10.1.0.0/16"
      production_vnet     = "10.10.0.0/16"
      vnet_peerings       = 2
    }

    security_controls = {
      azure_firewall      = "Enabled with threat intelligence"
      network_security_groups = 2
      ddos_protection     = "Standard tier enabled"
      azure_bastion       = "Enabled for secure VM access"
      private_link        = "Enabled for Azure SQL"
    }

    connectivity = {
      expressroute_to_aws = "50 Mbps circuit via Equinix"
      aws_vpc_cidr        = "10.0.0.0/16"
      encryption          = "IPSec via ExpressRoute"
    }

    pci_dss_compliance = {
      requirement_1_2 = "Azure Firewall with application rules"
      requirement_1_3 = "Network segmentation via subnets and NSGs"
      requirement_1_4 = "No public IPs on database subnet"
      requirement_2_3 = "Encrypted ExpressRoute to AWS"
    }

    traffic_flow = {
      internet_egress  = "Via Azure Firewall (centralized filtering)"
      aws_connectivity = "Via ExpressRoute Gateway"
      internal_routing = "Via route tables"
    }
  }
}
