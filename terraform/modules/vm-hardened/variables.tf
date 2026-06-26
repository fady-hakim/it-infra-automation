###############################################################################
# modules/vm-hardened/variables.tf
###############################################################################

variable "name"                { type = string }
variable "resource_group_name" { type = string }
variable "location"            { type = string }
variable "subnet_id"           { type = string }
variable "vm_size"             { type = string  ; default = "Standard_B2s" }
variable "admin_username"      { type = string }
variable "admin_password"      { type = string  ; sensitive = true }
variable "os_disk_size_gb"     { type = number  ; default = 64 }
variable "storage_account_uri" { type = string }
variable "tags"                { type = map(string) ; default = {} }
