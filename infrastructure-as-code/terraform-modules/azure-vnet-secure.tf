# Azure Secure VNet Module
# Compliance: PCI DSS 1.3, CIS Azure 6.1

variable "resource_group_name" {
  description = "Resource group name"
  type        = string
}

variable "location" {
  description = "Azure location"
  type        = string
}

variable "vnet_name" {
  description = "VNet name"
  type        = string
}

variable "address_space" {
  description = "VNet address space"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "subnets" {
  description = "List of subnets"
  type = list(object({
    name             = string
    address_prefixes = list(string)
  }))
}

resource "azurerm_virtual_network" "main" {
  name                = var.vnet_name
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = var.address_space

  tags = {
    ManagedBy = "Terraform"
  }
}

resource "azurerm_subnet" "main" {
  for_each = { for subnet in var.subnets : subnet.name => subnet }

  name                 = each.value.name
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = each.value.address_prefixes
}

resource "azurerm_network_security_group" "main" {
  for_each = { for subnet in var.subnets : subnet.name => subnet }

  name                = "${each.value.name}-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = {
    ManagedBy = "Terraform"
  }
}

resource "azurerm_subnet_network_security_group_association" "main" {
  for_each = { for subnet in var.subnets : subnet.name => subnet }

  subnet_id                 = azurerm_subnet.main[each.key].id
  network_security_group_id = azurerm_network_security_group.main[each.key].id
}

output "vnet_id" {
  description = "VNet ID"
  value       = azurerm_virtual_network.main.id
}

output "subnet_ids" {
  description = "Map of subnet IDs"
  value       = { for k, v in azurerm_subnet.main : k => v.id }
}
