###############################################################################
# modules/vm-hardened/outputs.tf
###############################################################################

output "vm_id"              { value = azurerm_linux_virtual_machine.main.id }
output "vm_name"            { value = azurerm_linux_virtual_machine.main.name }
output "private_ip_address" { value = azurerm_network_interface.main.private_ip_address }
output "identity_principal" { value = azurerm_linux_virtual_machine.main.identity[0].principal_id }
