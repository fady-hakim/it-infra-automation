###############################################################################
# outputs.tf — expose useful values post-deployment
# NOTE: sensitive = true on anything that could leak credentials
###############################################################################

output "resource_group_name" {
  description = "Name of the deployed resource group"
  value       = azurerm_resource_group.main.name
}

output "vm_id" {
  description = "Azure resource ID of the deployed VM"
  value       = module.vm.vm_id
}

output "vm_private_ip" {
  description = "Private IP address of the VM"
  value       = module.vm.private_ip_address
}

output "vm_name" {
  description = "Name of the deployed VM"
  value       = module.vm.vm_name
}

output "vnet_id" {
  description = "ID of the Virtual Network"
  value       = azurerm_virtual_network.main.id
}

output "subnet_id" {
  description = "ID of the VM subnet"
  value       = azurerm_subnet.main.id
}

output "nsg_id" {
  description = "ID of the Network Security Group"
  value       = module.nsg.nsg_id
}

output "key_vault_name" {
  description = "Name of the Key Vault holding VM credentials"
  value       = azurerm_key_vault.main.name
}

output "key_vault_uri" {
  description = "URI of the Key Vault"
  value       = azurerm_key_vault.main.vault_uri
}

output "vm_admin_password_secret_name" {
  description = "Key Vault secret name containing the VM admin password"
  value       = azurerm_key_vault_secret.vm_admin_password.name
  sensitive   = true
}

output "diagnostics_storage_account" {
  description = "Name of the boot diagnostics storage account"
  value       = azurerm_storage_account.diag.name
}
