###############################################################################
# modules/nsg-rules/main.tf
#
# Least-privilege NSG — explicit deny-all with minimal allow rules
# Inbound: SSH from allowed CIDR only
# Outbound: HTTPS + DNS only (no unrestricted outbound)
###############################################################################

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }
}

resource "azurerm_network_security_group" "main" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name

  ###########################################################################
  # INBOUND RULES
  ###########################################################################

  # Allow SSH from approved CIDR only
  security_rule {
    name                       = "Allow-SSH-Inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.allowed_ssh_cidr
    destination_address_prefix = "VirtualNetwork"
    description                = "SSH from approved management CIDR only"
  }

  # Allow Azure Load Balancer health probes
  security_rule {
    name                       = "Allow-AzureLoadBalancer-Inbound"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "AzureLoadBalancer"
    destination_address_prefix = "*"
    description                = "Required for Azure health probes"
  }

  # Deny all other inbound — explicit (belt and braces over default deny)
  security_rule {
    name                       = "Deny-All-Inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
    description                = "Explicit deny-all inbound — do not remove"
  }

  ###########################################################################
  # OUTBOUND RULES — restrict to minimum required
  ###########################################################################

  # Allow HTTPS outbound (package updates, Azure services)
  security_rule {
    name                       = "Allow-HTTPS-Outbound"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "Internet"
    description                = "HTTPS for updates and Azure service communication"
  }

  # Allow DNS outbound
  security_rule {
    name                       = "Allow-DNS-Outbound"
    priority                   = 110
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "53"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "*"
    description                = "DNS resolution"
  }

  # Allow Azure Monitor and diagnostics
  security_rule {
    name                       = "Allow-AzureMonitor-Outbound"
    priority                   = 120
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "AzureMonitor"
    description                = "Azure Monitor agent telemetry"
  }

  # Deny all other outbound
  security_rule {
    name                       = "Deny-All-Outbound"
    priority                   = 4096
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
    description                = "Explicit deny-all outbound — do not remove"
  }

  tags = var.tags
}

###############################################################################
# Variables + Outputs
###############################################################################

variable "name"                { type = string }
variable "resource_group_name" { type = string }
variable "location"            { type = string }
variable "allowed_ssh_cidr"    { type = string }
variable "tags"                { type = map(string) ; default = {} }

output "nsg_id"   { value = azurerm_network_security_group.main.id }
output "nsg_name" { value = azurerm_network_security_group.main.name }
