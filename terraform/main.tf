###############################################################################
# it-infra-automation / terraform / main.tf
#
# Deploys a hardened Azure VM environment including:
#   - Resource Group
#   - Virtual Network + Subnet with NSG (least-privilege rules)
#   - Hardened Linux VM (Ubuntu 22.04 LTS)
#   - Azure Key Vault for secret management (no hardcoded credentials)
#   - Boot diagnostics storage account
#   - Azure Monitor diagnostic settings
#
# Author  : Fady Hakim
# Version : 1.0
###############################################################################

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state — keeps tfstate out of the repo (no secrets in git)
  backend "azurerm" {
    resource_group_name  = "rg-tfstate"
    storage_account_name = "stfadytfstate"
    container_name       = "tfstate"
    key                  = "infra-automation.tfstate"
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
    virtual_machine {
      delete_os_disk_on_deletion     = true
      graceful_shutdown              = false
      skip_shutdown_and_force_delete = false
    }
  }
}

###############################################################################
# Data sources
###############################################################################

data "azurerm_client_config" "current" {}

###############################################################################
# Resource Group
###############################################################################

resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location

  tags = local.common_tags
}

###############################################################################
# Networking
###############################################################################

resource "azurerm_virtual_network" "main" {
  name                = "vnet-${var.environment}-${var.location_short}"
  address_space       = [var.vnet_address_space]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = local.common_tags
}

resource "azurerm_subnet" "main" {
  name                 = "snet-${var.environment}-vm"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.subnet_address_prefix]
}

###############################################################################
# NSG — Least-privilege rules
###############################################################################

module "nsg" {
  source              = "./modules/nsg-rules"
  name                = "nsg-${var.environment}-vm"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  allowed_ssh_cidr    = var.allowed_ssh_cidr
  tags                = local.common_tags
}

resource "azurerm_subnet_network_security_group_association" "main" {
  subnet_id                 = azurerm_subnet.main.id
  network_security_group_id = module.nsg.nsg_id
}

###############################################################################
# Key Vault — secrets never hardcoded or in tfstate plaintext
###############################################################################

resource "azurerm_key_vault" "main" {
  name                        = "kv-${var.environment}-${random_string.kv_suffix.result}"
  location                    = azurerm_resource_group.main.location
  resource_group_name         = azurerm_resource_group.main.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  soft_delete_retention_days  = 7
  purge_protection_enabled    = true
  enable_rbac_authorization   = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.allowed_ssh_cidr != "0.0.0.0/0" ? [var.allowed_ssh_cidr] : []
  }

  tags = local.common_tags
}

# Grant deploying identity access to Key Vault secrets
resource "azurerm_role_assignment" "kv_deployer" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "random_string" "kv_suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "random_password" "vm_admin" {
  length           = 24
  special          = true
  override_special = "!@#$%"
  min_lower        = 4
  min_upper        = 4
  min_numeric      = 4
  min_special      = 2
}

resource "azurerm_key_vault_secret" "vm_admin_password" {
  name         = "vm-admin-password"
  value        = random_password.vm_admin.result
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_role_assignment.kv_deployer]

  tags = local.common_tags
}

###############################################################################
# Hardened VM
###############################################################################

module "vm" {
  source              = "./modules/vm-hardened"
  name                = "vm-${var.environment}-${var.location_short}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  subnet_id           = azurerm_subnet.main.id
  vm_size             = var.vm_size
  admin_username      = var.vm_admin_username
  admin_password      = random_password.vm_admin.result
  os_disk_size_gb     = var.os_disk_size_gb
  storage_account_uri = azurerm_storage_account.diag.primary_blob_endpoint
  tags                = local.common_tags
}

###############################################################################
# Boot diagnostics storage
###############################################################################

resource "azurerm_storage_account" "diag" {
  name                     = "stdiag${random_string.kv_suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Security hardening
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = true
  https_traffic_only_enabled      = true

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }

  tags = local.common_tags
}

###############################################################################
# Azure Monitor — diagnostic logs
###############################################################################

resource "azurerm_monitor_diagnostic_setting" "vm" {
  name               = "diag-vm-${var.environment}"
  target_resource_id = module.vm.vm_id

  storage_account_id = azurerm_storage_account.diag.id

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

###############################################################################
# Locals
###############################################################################

locals {
  common_tags = {
    Environment = var.environment
    Project     = "it-infra-automation"
    ManagedBy   = "terraform"
    Owner       = var.owner_tag
    CreatedAt   = timestamp()
  }
}
