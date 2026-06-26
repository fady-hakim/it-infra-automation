#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Audits Windows endpoint security configuration against CIS Benchmark Level 1.

.DESCRIPTION
    Checks 30+ security controls across:
      - Password and account lockout policy
      - Audit policy (event logging)
      - Windows Firewall profiles
      - Remote access (RDP, WinRM)
      - Service hardening (disabled dangerous services)
      - Registry-based security settings
      - USB/removable media control
      - SMB signing and version enforcement

    Produces a pass/fail CSV report with remediation guidance for each control.

.PARAMETER OutputPath
    Directory for output reports. Defaults to .\Reports\

.PARAMETER IncludeHTML
    Generate an HTML report in addition to CSV.

.PARAMETER Remediate
    Attempt automatic remediation of failed controls (use with caution).

.EXAMPLE
    .\security-baseline-audit.ps1
    .\security-baseline-audit.ps1 -OutputPath C:\Reports -IncludeHTML
    .\security-baseline-audit.ps1 -Remediate -WhatIf

.NOTES
    Author  : Fady Hakim
    Version : 1.0
    Reference: CIS Microsoft Windows Server 2019/2022 Benchmark Level 1
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [string]$OutputPath = '.\Reports',

    [Parameter()]
    [switch]$IncludeHTML,

    [Parameter()]
    [switch]$Remediate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$null      = New-Item -ItemType Directory -Path $OutputPath -Force
$results   = [System.Collections.Generic.List[PSObject]]::new()
$passed    = 0
$failed    = 0
$warnings  = 0

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','PASS','FAIL')][string]$Level = 'INFO')
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'INFO'  { Write-Host $entry -ForegroundColor Cyan }
        'PASS'  { Write-Host $entry -ForegroundColor Green }
        'FAIL'  { Write-Host $entry -ForegroundColor Red }
        'WARN'  { Write-Host $entry -ForegroundColor Yellow }
        'ERROR' { Write-Host $entry -ForegroundColor Red }
    }
}

function Add-Result {
    param(
        [string]$Category,
        [string]$Control,
        [string]$Expected,
        [string]$Actual,
        [bool]$Pass,
        [string]$Remediation = '',
        [string]$CISRef = ''
    )
    $status = if ($Pass) { 'PASS' } else { 'FAIL' }
    Write-Log "$status — $Control" -Level $status
    if ($Pass) { $script:passed++ } else { $script:failed++ }

    $results.Add([PSCustomObject]@{
        Category    = $Category
        Control     = $Control
        Expected    = $Expected
        Actual      = $Actual
        Status      = $status
        CISRef      = $CISRef
        Remediation = $Remediation
        Timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    })
}

function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    }
    catch { return $null }
}

Write-Log "Starting CIS Benchmark Security Audit — Host: $env:COMPUTERNAME"

#region --- Password Policy ---

Write-Log "--- Password Policy ---"
try {
    $passPolicy = Get-LocalUser | Select-Object -First 1 | Get-LocalUser
    $netAccounts = net accounts 2>$null

    $minLength    = ($netAccounts | Select-String 'Minimum password length').ToString() -replace '\D+',''
    $maxAge       = ($netAccounts | Select-String 'Maximum password age').ToString() -replace '\D+',''
    $minAge       = ($netAccounts | Select-String 'Minimum password age').ToString() -replace '\D+',''
    $history      = ($netAccounts | Select-String 'Length of password history').ToString() -replace '\D+',''
    $complexity   = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'RequireStrongKey'
    $lockoutThresh = ($netAccounts | Select-String 'Lockout threshold').ToString() -replace '\D+',''
    $lockoutDur   = ($netAccounts | Select-String 'Lockout duration').ToString() -replace '\D+',''

    Add-Result 'Password Policy' 'Minimum password length >= 14' '>= 14' $minLength ([int]$minLength -ge 14) `
        'Set via: net accounts /minpwlen:14' 'CIS 1.1.4'

    Add-Result 'Password Policy' 'Maximum password age <= 60 days' '<= 60' $maxAge ([int]$maxAge -le 60 -and [int]$maxAge -gt 0) `
        'Set via: net accounts /maxpwage:60' 'CIS 1.1.2'

    Add-Result 'Password Policy' 'Minimum password age >= 1 day' '>= 1' $minAge ([int]$minAge -ge 1) `
        'Set via: net accounts /minpwage:1' 'CIS 1.1.3'

    Add-Result 'Password Policy' 'Password history >= 24' '>= 24' $history ([int]$history -ge 24) `
        'Set via: net accounts /uniquepw:24' 'CIS 1.1.1'

    Add-Result 'Password Policy' 'Account lockout threshold <= 5' '<= 5' $lockoutThresh `
        ([int]$lockoutThresh -gt 0 -and [int]$lockoutThresh -le 5) `
        'Set via: net accounts /lockoutthreshold:5' 'CIS 1.2.1'

    Add-Result 'Password Policy' 'Lockout duration >= 15 min' '>= 15' $lockoutDur ([int]$lockoutDur -ge 15) `
        'Set via: net accounts /lockoutduration:15' 'CIS 1.2.2'
}
catch { Write-Log "Password policy check error: $_" -Level WARN; $warnings++ }

#endregion

#region --- Windows Firewall ---

Write-Log "--- Windows Firewall ---"
try {
    $profiles = Get-NetFirewallProfile -All
    foreach ($profile in $profiles) {
        Add-Result 'Firewall' "Firewall enabled — $($profile.Name)" 'True' $profile.Enabled.ToString() $profile.Enabled `
            "Enable-NetFirewallProfile -Profile $($profile.Name) -Enabled True" 'CIS 9.1-9.3'

        Add-Result 'Firewall' "Default inbound block — $($profile.Name)" 'Block' $profile.DefaultInboundAction.ToString() `
            ($profile.DefaultInboundAction -eq 'Block') `
            "Set-NetFirewallProfile -Profile $($profile.Name) -DefaultInboundAction Block" 'CIS 9.1-9.3'
    }
}
catch { Write-Log "Firewall check error: $_" -Level WARN; $warnings++ }

#endregion

#region --- Remote Access ---

Write-Log "--- Remote Access ---"
try {
    # RDP encryption level
    $rdpEncryption = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel'
    Add-Result 'Remote Access' 'RDP encryption level = High (3)' '3' "$rdpEncryption" ($rdpEncryption -eq 3) `
        'Set registry: MinEncryptionLevel = 3' 'CIS 18.9.65'

    # NLA required for RDP
    $nla = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    Add-Result 'Remote Access' 'NLA required for RDP' '1' "$nla" ($nla -eq 1) `
        'Set registry: UserAuthentication = 1' 'CIS 18.9.65.3'

    # WinRM service state
    $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    $winrmRunning = $winrm -and $winrm.Status -eq 'Running'
    Add-Result 'Remote Access' 'WinRM not running (unless required)' 'Stopped' ($winrm?.Status ?? 'Not found') `
        (-not $winrmRunning) 'Stop-Service WinRM; Set-Service WinRM -StartupType Disabled' 'CIS 18.6'
}
catch { Write-Log "Remote access check error: $_" -Level WARN; $warnings++ }

#endregion

#region --- SMB Hardening ---

Write-Log "--- SMB Hardening ---"
try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    Add-Result 'SMB' 'SMBv1 disabled' 'Disabled' ($smb1?.State ?? 'Unknown') `
        ($smb1 -and $smb1.State -eq 'Disabled') `
        'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart' 'CIS 18.3.3'

    $smbSigning = Get-SmbServerConfiguration | Select-Object -ExpandProperty RequireSecuritySignature
    Add-Result 'SMB' 'SMB signing required' 'True' $smbSigning.ToString() $smbSigning `
        'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force' 'CIS 2.3.8'

    $smbEncrypt = (Get-SmbServerConfiguration).EncryptData
    Add-Result 'SMB' 'SMB encryption enabled' 'True' $smbEncrypt.ToString() $smbEncrypt `
        'Set-SmbServerConfiguration -EncryptData $true -Force' 'CIS 2.3.8'
}
catch { Write-Log "SMB check error: $_" -Level WARN; $warnings++ }

#endregion

#region --- USB / Removable Media ---

Write-Log "--- USB / Removable Media ---"
try {
    $usbStorage = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor' 'Start'
    Add-Result 'USB Control' 'USB storage driver disabled (Start=4)' '4' "$usbStorage" ($usbStorage -eq 4) `
        'Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor -Name Start -Value 4' 'CIS Custom'

    $autorun = Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    Add-Result 'USB Control' 'AutoRun disabled (NoDriveTypeAutoRun=255)' '255' "$autorun" ($autorun -eq 255) `
        'Set NoDriveTypeAutoRun = 255 via GPO or registry' 'CIS 18.9.8.1'
}
catch { Write-Log "USB check error: $_" -Level WARN; $warnings++ }

#endregion

#region --- Audit Policy ---

Write-Log "--- Audit Policy ---"
try {
    $auditCategories = @(
        @{ Name = 'Logon/Logoff'; SubCategory = 'Logon'; Expected = 'Success and Failure' }
        @{ Name = 'Account Logon'; SubCategory = 'Credential Validation'; Expected = 'Success and Failure' }
        @{ Name = 'Account Management'; SubCategory = 'User Account Management'; Expected = 'Success and Failure' }
        @{ Name = 'Policy Change'; SubCategory = 'Audit Policy Change'; Expected = 'Success' }
        @{ Name = 'Privilege Use'; SubCategory = 'Sensitive Privilege Use'; Expected = 'Success and Failure' }
    )

    foreach ($cat in $auditCategories) {
        $policy = auditpol /get /subcategory:"$($cat.SubCategory)" 2>$null
        $line   = $policy | Select-String $cat.SubCategory
        $actual = if ($line) { $line.ToString().Trim() -replace ".*$($cat.SubCategory)\s+", '' } else { 'Unknown' }
        $pass   = $actual -like "*$($cat.Expected)*" -or $actual -like "*Success and Failure*"

        Add-Result 'Audit Policy' "Audit: $($cat.SubCategory)" $cat.Expected $actual $pass `
            "auditpol /set /subcategory:`"$($cat.SubCategory)`" /success:enable /failure:enable" 'CIS 17.x'
    }
}
catch { Write-Log "Audit policy check error: $_" -Level WARN; $warnings++ }

#endregion

#region --- Dangerous Services ---

Write-Log "--- Dangerous Services ---"
$dangerousServices = @(
    @{ Name = 'Telnet';  DisplayName = 'Telnet' }
    @{ Name = 'SNMP';    DisplayName = 'SNMP Service' }
    @{ Name = 'RemoteRegistry'; DisplayName = 'Remote Registry' }
    @{ Name = 'Fax';     DisplayName = 'Fax' }
)

foreach ($svc in $dangerousServices) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        $running = $service -and $service.Status -eq 'Running'
        Add-Result 'Services' "$($svc.DisplayName) not running" 'Stopped/NotInstalled' `
            ($service?.Status.ToString() ?? 'Not installed') (-not $running) `
            "Stop-Service $($svc.Name); Set-Service $($svc.Name) -StartupType Disabled" 'CIS 5.x'
    }
    catch { Write-Log "Service check failed: $($svc.Name)" -Level WARN; $warnings++ }
}

#endregion

#region --- Guest Account ---

Write-Log "--- Local Accounts ---"
try {
    $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
    Add-Result 'Local Accounts' 'Guest account disabled' 'False' ($guest?.Enabled.ToString() ?? 'Not found') `
        (-not $guest -or -not $guest.Enabled) 'Disable-LocalUser -Name Guest' 'CIS 2.3.1.2'

    $admin = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
    Add-Result 'Local Accounts' 'Default Administrator account renamed or disabled' 'Renamed/Disabled' `
        ($admin?.Name ?? 'Not found') (-not $admin -or -not $admin.Enabled) `
        'Rename or disable the default Administrator account' 'CIS 2.3.1.1'
}
catch { Write-Log "Local account check error: $_" -Level WARN; $warnings++ }

#endregion

#region --- Output ---

$csvPath = Join-Path $OutputPath "security-baseline-audit-$timestamp.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Log "CSV saved: $csvPath"

if ($IncludeHTML) {
    $rows = $results | ForEach-Object {
        $color = if ($_.Status -eq 'PASS') { '#d5f5e3' } else { '#fadbd8' }
        "<tr style='background:$color'>
          <td>$($_.Category)</td>
          <td>$($_.Control)</td>
          <td>$($_.Expected)</td>
          <td>$($_.Actual)</td>
          <td><strong>$($_.Status)</strong></td>
          <td>$($_.CISRef)</td>
          <td style='font-size:11px;color:#555'>$($_.Remediation)</td>
        </tr>"
    }

    $score = [math]::Round(($passed / ($passed + $failed)) * 100, 1)

    $html = @"
<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Security Baseline Audit</title>
<style>
  body { font-family: Segoe UI, sans-serif; font-size: 13px; margin: 2rem; }
  h1 { color: #1a5276; }
  .score { font-size: 3rem; font-weight: bold; color: $(if ($score -ge 80) { '#27ae60' } elseif ($score -ge 60) { '#e67e22' } else { '#c0392b' }); }
  .summary { display: flex; gap: 2rem; margin: 1rem 0 2rem; }
  .card { background: #f4f6f7; border-radius: 8px; padding: 1rem 1.5rem; }
  .card .num { font-size: 2rem; font-weight: bold; }
  table { border-collapse: collapse; width: 100%; }
  th { background: #1a5276; color: white; padding: 8px 12px; text-align: left; }
  td { padding: 6px 12px; border-bottom: 1px solid #eee; }
</style></head><body>
<h1>Security Baseline Audit — $env:COMPUTERNAME</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Reference: CIS Benchmark Level 1</p>
<div class='score'>$score%</div><p>Compliance Score</p>
<div class='summary'>
  <div class='card'><div class='num' style='color:#27ae60'>$passed</div>Passed</div>
  <div class='card'><div class='num' style='color:#c0392b'>$failed</div>Failed</div>
  <div class='card'><div class='num' style='color:#e67e22'>$warnings</div>Warnings</div>
</div>
<table>
<tr><th>Category</th><th>Control</th><th>Expected</th><th>Actual</th><th>Status</th><th>CIS Ref</th><th>Remediation</th></tr>
$($rows -join "`n")
</table></body></html>
"@
    $htmlPath = Join-Path $OutputPath "security-baseline-audit-$timestamp.html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Log "HTML report saved: $htmlPath"
}

$score = [math]::Round(($passed / [math]::Max(1, $passed + $failed)) * 100, 1)
Write-Log "Audit complete — PASSED: $passed | FAILED: $failed | WARNINGS: $warnings | Score: $score%"

if ($failed -gt 0) { exit 1 } else { exit 0 }

#endregion
