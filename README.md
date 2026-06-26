# IT Infrastructure & Cloud Automation Toolkit

Production-grade automation scripts and Infrastructure-as-Code for Windows/Linux environments and Azure cloud deployments. Built to reflect real-world engineering standards: modular, idempotent, secure by default, and fully documented.

---

## Repository Structure

```
it-infra-automation/
├── powershell/                     # Windows SysAdmin automation
│   ├── ad-user-management.ps1      # AD user lifecycle (bulk create, disable, audit)
│   ├── gpo-health-report.ps1       # GPO compliance report with HTML output
│   ├── security-baseline-audit.ps1 # CIS Benchmark Level 1 audit
│   ├── eventlog-monitor.ps1        # Security event monitoring & alerting
│   └── disk-cleanup-report.ps1     # Disk usage analysis and cleanup
│
├── terraform/                      # Azure IaC deployment
│   ├── main.tf                     # Core infrastructure
│   ├── variables.tf                # All inputs — no hardcoded values
│   ├── outputs.tf                  # Post-deployment outputs
│   └── modules/
│       ├── vm-hardened/            # Reusable hardened Linux VM module
│       └── nsg-rules/              # Least-privilege NSG module
│
└── .github/workflows/
    └── terraform-ci.yml            # CI: fmt → security scan → validate → plan
```

---

## PowerShell Scripts

### Prerequisites
- Windows PowerShell 5.1+ or PowerShell 7+
- RSAT modules: `ActiveDirectory`, `GroupPolicy` (for AD/GPO scripts)
- Domain Admin or delegated OU permissions where required
- Run as Administrator

---

### `ad-user-management.ps1`
Automates Active Directory user lifecycle management.

**Actions:**

| Action | Description |
|--------|-------------|
| `BulkCreate` | Provision users from CSV — sets UPN, OU, manager, forces password change at logon |
| `BulkDisable` | Disable and move offboarded accounts to Disabled Users OU |
| `Audit` | Export full account health report — flags inactive, locked, expired, never-expiring passwords |

```powershell
# Provision new starters
.\ad-user-management.ps1 -Action BulkCreate -InputCSV .\new-users.csv

# Offboard leavers
.\ad-user-management.ps1 -Action BulkDisable -InputCSV .\leavers.csv -Force

# Full domain audit
.\ad-user-management.ps1 -Action Audit -OutputPath C:\Reports\
```

**CSV format for BulkCreate:**
```
FirstName,LastName,Username,Department,Title,OU,Manager,Password
John,Smith,jsmith,IT,Engineer,OU=Users,DC=corp,DC=local,admin,P@ssw0rd!
```

---

### `gpo-health-report.ps1`
Scans all GPOs in the domain and produces a health report.

**Checks:** link status, unlinked GPOs, stale GPOs, WMI filters, enforced links, security filtering, disabled policy sections.

```powershell
.\gpo-health-report.ps1 -IncludeHTML -OutputPath C:\Reports\
.\gpo-health-report.ps1 -StaleDays 90
```

---

### `security-baseline-audit.ps1`
Audits a Windows endpoint against **CIS Benchmark Level 1** and produces a scored pass/fail report.

**Coverage:** Password policy · Account lockout · Windows Firewall · RDP/NLA settings · WinRM · SMBv1/signing · USB control · AutoRun · Audit policy · Dangerous services · Guest/Admin account status.

```powershell
# Audit and generate HTML report
.\security-baseline-audit.ps1 -IncludeHTML -OutputPath C:\Reports\

# Simulate only (no changes)
.\security-baseline-audit.ps1 -Remediate -WhatIf
```

Output includes a **compliance score** (e.g. `87.5%`) and per-control remediation guidance.

---

### `eventlog-monitor.ps1`
Parses Windows Security logs for high-signal security events. Designed to run as a scheduled task every 1–6 hours.

**Detects:** Brute force · Account lockouts · Privileged logon volume · Account/group changes · Audit policy tampering · New service installation.

```powershell
# Analyse last 24 hours
.\eventlog-monitor.ps1

# Tighter threshold, email alerts
.\eventlog-monitor.ps1 -HoursBack 6 -BruteForceThreshold 3 `
    -AlertEmail soc@company.com -SMTPServer mail.company.com
```

Exit codes: `0` = clean · `1` = HIGH alerts · `2` = CRITICAL alerts (integrates with monitoring tools).

---

### `disk-cleanup-report.ps1`
Analyses disk usage across all fixed drives and identifies cleanup candidates.

**Reports:** Drive usage summary · Top 20 largest files per drive · Stale files (not accessed in N days) · Temp folder sizes · Cleanup candidates.

```powershell
.\disk-cleanup-report.ps1 -StaleFileDays 90

# Safe cleanup of temp folders only (7+ days old)
.\disk-cleanup-report.ps1 -Cleanup -Force
```

---

## Terraform — Azure Deployment

### Architecture

```
Azure Subscription
└── Resource Group: rg-infra-automation-dev
    ├── Virtual Network (10.10.0.0/16)
    │   └── Subnet (10.10.1.0/24)
    │       └── NSG — least-privilege rules
    │           ├── Inbound: SSH from approved CIDR only
    │           └── Outbound: HTTPS + DNS only
    ├── Hardened Ubuntu 22.04 VM
    │   ├── No public IP
    │   ├── Cloud-init hardening (SSH, UFW, auditd, fail2ban)
    │   └── Azure Monitor Agent
    ├── Key Vault (admin password — never in tfstate plaintext)
    └── Storage Account (boot diagnostics)
```

### Security Approach
- **No hardcoded secrets** — credentials generated by Terraform and stored in Key Vault
- **No public IP** on VM — access via approved CIDR, Bastion, or VPN
- **Remote backend** — tfstate stored in Azure Storage, not in the repo
- **Least-privilege NSG** — explicit deny-all with minimum required allow rules
- **VM hardening** via cloud-init: root SSH disabled, UFW enabled, auditd, fail2ban, USB storage blacklisted
- **Sensitive outputs** marked `sensitive = true`

### Prerequisites
- Terraform >= 1.7.0
- Azure CLI authenticated (`az login`)
- Service Principal with Contributor on the subscription

### Usage

```bash
cd terraform

# Initialise with remote backend
terraform init

# Review what will be created
terraform plan -var="environment=dev"

# Deploy
terraform apply -var="environment=dev"

# Retrieve the VM admin password from Key Vault (not exposed in outputs)
az keyvault secret show \
  --vault-name $(terraform output -raw key_vault_name) \
  --name vm-admin-password \
  --query value -o tsv

# Destroy when done (important if using free tier credits)
terraform destroy
```

### Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `environment` | `dev` | `dev`, `staging`, or `prod` |
| `location` | `uksouth` | Azure region |
| `vm_size` | `Standard_B2s` | VM SKU |
| `allowed_ssh_cidr` | `10.10.0.0/16` | CIDR allowed SSH access — never use `0.0.0.0/0` |
| `vm_admin_username` | `azureadmin` | Cannot be `admin`, `root`, `administrator` |

---

## CI/CD Pipeline

GitHub Actions runs on every push to `main` or `develop` and on all PRs:

| Step | Tool | Purpose |
|------|------|---------|
| Format check | `terraform fmt` | Enforces consistent code style |
| Security scan | `tfsec` | Catches misconfigurations before deploy |
| Validate | `terraform validate` | Syntax and provider validation |
| Plan | `terraform plan` | Shows exact changes — posted as PR comment |

**Required GitHub Secrets:**

```
ARM_CLIENT_ID
ARM_CLIENT_SECRET
ARM_SUBSCRIPTION_ID
ARM_TENANT_ID
```

---

## Author

**Fady Hakim** — BSc Applied Cyber Security (2:1), University of South Wales  
[LinkedIn](https://www.linkedin.com/in/fadyhakim/) · Cardiff, UK
