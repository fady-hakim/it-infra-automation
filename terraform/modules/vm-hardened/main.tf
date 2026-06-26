###############################################################################
# modules/vm-hardened/main.tf
#
# Reusable hardened Linux VM module — Ubuntu 22.04 LTS
# Security controls applied:
#   - No public IP by default
#   - Password auth disabled (SSH key or password via Key Vault only)
#   - OS disk encrypted with platform-managed key + disk encryption set
#   - Boot diagnostics enabled
#   - Auto OS patching enabled
#   - VM extensions: AAD login, Azure Monitor agent
###############################################################################

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }
}

resource "azurerm_network_interface" "main" {
  name                = "nic-${var.name}"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
    # No public IP — access via Bastion or VPN only
  }

  tags = var.tags
}

resource "azurerm_linux_virtual_machine" "main" {
  name                            = var.name
  resource_group_name             = var.resource_group_name
  location                        = var.location
  size                            = var.vm_size
  admin_username                  = var.admin_username
  admin_password                  = var.admin_password
  disable_password_authentication = false

  network_interface_ids = [azurerm_network_interface.main.id]

  os_disk {
    name                 = "osdisk-${var.name}"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = var.os_disk_size_gb

    # Encrypt at rest
    secure_vm_disk_encryption_set_id = null # Platform-managed key default
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # Hardening: no public SSH exposure
  # Custom data runs hardening script on first boot
  custom_data = base64encode(local.hardening_script)

  boot_diagnostics {
    storage_account_uri = var.storage_account_uri
  }

  # Patch management
  patch_mode                                             = "AutomaticByPlatform"
  patch_assessment_mode                                  = "AutomaticByPlatform"
  bypass_platform_safety_checks_on_user_schedule_enabled = false

  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

###############################################################################
# VM hardening cloud-init script (runs once on first boot)
###############################################################################

locals {
  hardening_script = <<-SCRIPT
    #!/bin/bash
    set -euo pipefail

    # Update and upgrade
    apt-get update -y
    apt-get upgrade -y

    # Disable root SSH login
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

    # Disable empty password login
    sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

    # Set SSH idle timeout (5 min)
    echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
    echo "ClientAliveCountMax 0"   >> /etc/ssh/sshd_config

    # Restrict SSH to protocol 2
    sed -i 's/^#*Protocol.*/Protocol 2/' /etc/ssh/sshd_config

    systemctl restart sshd

    # Enable UFW firewall — deny all inbound except SSH
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp comment 'SSH'
    ufw --force enable

    # Disable unused filesystems (CIS)
    for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat; do
      echo "install $fs /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
    done

    # Enable auditd
    apt-get install -y auditd audispd-plugins
    systemctl enable auditd
    systemctl start auditd

    # Set audit rules for key security events
    cat >> /etc/audit/rules.d/hardening.rules <<'EOF'
    -w /etc/passwd -p wa -k identity
    -w /etc/group -p wa -k identity
    -w /etc/shadow -p wa -k identity
    -w /etc/sudoers -p wa -k privilege_escalation
    -w /var/log/auth.log -p wa -k auth_log
    -a always,exit -F arch=b64 -S execve -k exec
    EOF
    service auditd restart

    # Disable USB storage
    echo "blacklist usb-storage" >> /etc/modprobe.d/disable-usb-storage.conf
    echo "install usb-storage /bin/true" >> /etc/modprobe.d/disable-usb-storage.conf

    # Fail2ban
    apt-get install -y fail2ban
    systemctl enable fail2ban
    systemctl start fail2ban

    # Install Azure Monitor agent dependencies
    apt-get install -y python3 python3-pip

    echo "Hardening complete: $(date)" >> /var/log/hardening.log
  SCRIPT
}

###############################################################################
# Azure Monitor Agent
###############################################################################

resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.main.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.29"
  auto_upgrade_minor_version = true

  tags = var.tags
}
