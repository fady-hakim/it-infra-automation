###############################################################################
# variables.tf — all inputs declared here, no values hardcoded in main.tf
###############################################################################

variable "resource_group_name" {
  description = "Name of the Azure Resource Group"
  type        = string
  default     = "rg-infra-automation-dev"

  validation {
    condition     = can(regex("^rg-", var.resource_group_name))
    error_message = "Resource group name must start with 'rg-' to follow naming conventions."
  }
}

variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "uksouth"

  validation {
    condition     = contains(["uksouth", "ukwest", "westeurope", "northeurope", "eastus", "eastus2", "westus2"], var.location)
    error_message = "Location must be a supported Azure region."
  }
}

variable "location_short" {
  description = "Short code for location used in resource naming (e.g. uks, we)"
  type        = string
  default     = "uks"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "vnet_address_space" {
  description = "CIDR block for the Virtual Network"
  type        = string
  default     = "10.10.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vnet_address_space))
    error_message = "vnet_address_space must be a valid CIDR block."
  }
}

variable "subnet_address_prefix" {
  description = "CIDR block for the VM subnet"
  type        = string
  default     = "10.10.1.0/24"
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed SSH access to the VM. NEVER use 0.0.0.0/0 in production."
  type        = string
  default     = "10.10.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.allowed_ssh_cidr))
    error_message = "allowed_ssh_cidr must be a valid CIDR block."
  }
}

variable "vm_size" {
  description = "Azure VM SKU size"
  type        = string
  default     = "Standard_B2s"
}

variable "vm_admin_username" {
  description = "Administrator username for the VM. Cannot be 'admin' or 'root'."
  type        = string
  default     = "azureadmin"

  validation {
    condition     = !contains(["admin", "root", "administrator", "guest"], lower(var.vm_admin_username))
    error_message = "Admin username cannot be a reserved name (admin, root, administrator, guest)."
  }
}

variable "os_disk_size_gb" {
  description = "OS disk size in GB"
  type        = number
  default     = 64

  validation {
    condition     = var.os_disk_size_gb >= 30 && var.os_disk_size_gb <= 1024
    error_message = "OS disk size must be between 30 and 1024 GB."
  }
}

variable "owner_tag" {
  description = "Owner tag applied to all resources for cost attribution"
  type        = string
  default     = "fady-hakim"
}
