#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Active Directory user lifecycle automation — bulk create, disable, and audit AD accounts.

.DESCRIPTION
    Automates three core AD operations with full logging and CSV reporting:
      - BulkCreate  : Provision new users from a CSV input file
      - BulkDisable : Disable inactive or offboarded accounts
      - Audit       : Export a full account health report

    All actions are logged to a transcript file. No operation modifies AD without
    explicit confirmation (unless -Force is passed). Designed for use in managed
    multi-site environments.

.PARAMETER Action
    Required. One of: BulkCreate | BulkDisable | Audit

.PARAMETER InputCSV
    Path to input CSV file (required for BulkCreate and BulkDisable).

.PARAMETER OutputPath
    Directory for output reports and logs. Defaults to .\Reports\

.PARAMETER Force
    Suppress confirmation prompts. Use with caution in production.

.PARAMETER WhatIf
    Simulates all AD changes without applying them.

.EXAMPLE
    .\ad-user-management.ps1 -Action BulkCreate -InputCSV .\new-users.csv
    .\ad-user-management.ps1 -Action Audit -OutputPath C:\Reports\
    .\ad-user-management.ps1 -Action BulkDisable -InputCSV .\offboard.csv -Force

.NOTES
    Author  : Fady Hakim
    Version : 1.0
    Requires: ActiveDirectory module, Domain Admin or delegated OU permissions
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [ValidateSet('BulkCreate', 'BulkDisable', 'Audit')]
    [string]$Action,

    [Parameter()]
    [ValidateScript({ if ($_ -and -not (Test-Path $_)) { throw "Input CSV not found: $_" } $true })]
    [string]$InputCSV,

    [Parameter()]
    [string]$OutputPath = '.\Reports',

    [Parameter()]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Initialisation ---

$timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$null        = New-Item -ItemType Directory -Path $OutputPath -Force
$transcriptPath = Join-Path $OutputPath "ad-mgmt-transcript-$timestamp.log"
Start-Transcript -Path $transcriptPath -Append

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO')
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'INFO'  { Write-Host $entry -ForegroundColor Cyan }
        'WARN'  { Write-Host $entry -ForegroundColor Yellow }
        'ERROR' { Write-Host $entry -ForegroundColor Red }
    }
}

function Confirm-Action {
    param([string]$Description)
    if ($Force) { return $true }
    $response = Read-Host "$Description — Proceed? (y/N)"
    return $response -ieq 'y'
}

Write-Log "Starting AD User Management — Action: $Action"

#endregion

#region --- BulkCreate ---

function Invoke-BulkCreate {
    <#
    CSV expected headers:
    FirstName, LastName, Username, Department, Title, OU, Manager, Password
    #>
    if (-not $InputCSV) { throw "BulkCreate requires -InputCSV" }

    $users   = Import-Csv -Path $InputCSV
    $results = [System.Collections.Generic.List[PSObject]]::new()
    $created = 0
    $skipped = 0
    $failed  = 0

    foreach ($user in $users) {
        $sam = $user.Username.Trim().ToLower()
        $upn = "$sam@$((Get-ADDomain).DNSRoot)"

        $result = [PSCustomObject]@{
            Username   = $sam
            FullName   = "$($user.FirstName) $($user.LastName)"
            Department = $user.Department
            Status     = ''
            Message    = ''
            Timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }

        try {
            # Validate required fields
            foreach ($field in @('FirstName','LastName','Username','OU','Password')) {
                if ([string]::IsNullOrWhiteSpace($user.$field)) {
                    throw "Missing required field: $field"
                }
            }

            # Check for existing account
            if (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
                Write-Log "SKIP — User already exists: $sam" -Level WARN
                $result.Status  = 'Skipped'
                $result.Message = 'Account already exists'
                $skipped++
                $results.Add($result)
                continue
            }

            $securePassword = ConvertTo-SecureString $user.Password -AsPlainText -Force

            $params = @{
                GivenName             = $user.FirstName.Trim()
                Surname               = $user.LastName.Trim()
                Name                  = "$($user.FirstName.Trim()) $($user.LastName.Trim())"
                SamAccountName        = $sam
                UserPrincipalName     = $upn
                Department            = $user.Department.Trim()
                Title                 = $user.Title.Trim()
                Path                  = $user.OU.Trim()
                AccountPassword       = $securePassword
                Enabled               = $true
                ChangePasswordAtLogon = $true
                PasswordNeverExpires  = $false
            }

            if (-not [string]::IsNullOrWhiteSpace($user.Manager)) {
                $manager = Get-ADUser -Filter "SamAccountName -eq '$($user.Manager.Trim())'" -ErrorAction SilentlyContinue
                if ($manager) { $params['Manager'] = $manager.DistinguishedName }
                else { Write-Log "Manager '$($user.Manager)' not found for $sam — skipping manager field" -Level WARN }
            }

            if ($PSCmdlet.ShouldProcess($sam, "Create AD user")) {
                if (Confirm-Action "Create user: $sam ($($user.FirstName) $($user.LastName))") {
                    New-ADUser @params
                    Write-Log "Created: $sam — $($user.FirstName) $($user.LastName) [$($user.Department)]"
                    $result.Status  = 'Created'
                    $result.Message = "UPN: $upn"
                    $created++
                }
            }
        }
        catch {
            Write-Log "FAILED: $sam — $($_.Exception.Message)" -Level ERROR
            $result.Status  = 'Failed'
            $result.Message = $_.Exception.Message
            $failed++
        }

        $results.Add($result)
    }

    $reportPath = Join-Path $OutputPath "bulk-create-report-$timestamp.csv"
    $results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
    Write-Log "BulkCreate complete — Created: $created | Skipped: $skipped | Failed: $failed"
    Write-Log "Report saved: $reportPath"
}

#endregion

#region --- BulkDisable ---

function Invoke-BulkDisable {
    <#
    CSV expected headers: Username, Reason
    #>
    if (-not $InputCSV) { throw "BulkDisable requires -InputCSV" }

    $users   = Import-Csv -Path $InputCSV
    $results = [System.Collections.Generic.List[PSObject]]::new()
    $disabled = 0
    $skipped  = 0
    $failed   = 0

    foreach ($user in $users) {
        $sam = $user.Username.Trim().ToLower()

        $result = [PSCustomObject]@{
            Username  = $sam
            Reason    = $user.Reason
            Status    = ''
            Message   = ''
            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }

        try {
            $adUser = Get-ADUser -Identity $sam -Properties Enabled, Description, LastLogonDate -ErrorAction Stop

            if (-not $adUser.Enabled) {
                Write-Log "SKIP — Already disabled: $sam" -Level WARN
                $result.Status  = 'Skipped'
                $result.Message = 'Account already disabled'
                $skipped++
                $results.Add($result)
                continue
            }

            if ($PSCmdlet.ShouldProcess($sam, "Disable AD user")) {
                if (Confirm-Action "Disable account: $sam (Reason: $($user.Reason))") {
                    # Move to disabled OU if it exists
                    $disabledOU = "OU=Disabled Users,$(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)"
                    $ouExists   = [bool](Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$disabledOU'" -ErrorAction SilentlyContinue)

                    Disable-ADAccount -Identity $sam
                    Set-ADUser -Identity $sam -Description "DISABLED $timestamp — $($user.Reason)"

                    if ($ouExists) {
                        Move-ADObject -Identity $adUser.DistinguishedName -TargetPath $disabledOU
                        Write-Log "Moved $sam to Disabled Users OU"
                    }

                    Write-Log "Disabled: $sam — Reason: $($user.Reason)"
                    $result.Status  = 'Disabled'
                    $result.Message = "Last logon: $($adUser.LastLogonDate)"
                    $disabled++
                }
            }
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Log "NOT FOUND: $sam" -Level ERROR
            $result.Status  = 'Failed'
            $result.Message = 'User not found in AD'
            $failed++
        }
        catch {
            Write-Log "FAILED: $sam — $($_.Exception.Message)" -Level ERROR
            $result.Status  = 'Failed'
            $result.Message = $_.Exception.Message
            $failed++
        }

        $results.Add($result)
    }

    $reportPath = Join-Path $OutputPath "bulk-disable-report-$timestamp.csv"
    $results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
    Write-Log "BulkDisable complete — Disabled: $disabled | Skipped: $skipped | Failed: $failed"
    Write-Log "Report saved: $reportPath"
}

#endregion

#region --- Audit ---

function Invoke-Audit {
    Write-Log "Running AD account audit..."

    $allUsers = Get-ADUser -Filter * -Properties `
        SamAccountName, DisplayName, Department, Title, Enabled,
        LastLogonDate, PasswordLastSet, PasswordNeverExpires,
        PasswordExpired, LockedOut, Created, Description, Manager

    $cutoff     = (Get-Date).AddDays(-90)
    $pwdCutoff  = (Get-Date).AddDays(-60)
    $results    = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($user in $allUsers) {
        $issues = [System.Collections.Generic.List[string]]::new()

        if (-not $user.Enabled)                                        { $issues.Add('Disabled') }
        if ($user.PasswordNeverExpires)                                { $issues.Add('Password never expires') }
        if ($user.PasswordExpired)                                     { $issues.Add('Password expired') }
        if ($user.LockedOut)                                           { $issues.Add('Locked out') }
        if ($user.LastLogonDate -and $user.LastLogonDate -lt $cutoff) { $issues.Add('Inactive 90+ days') }
        if ($user.PasswordLastSet -and $user.PasswordLastSet -lt $pwdCutoff) { $issues.Add('Password 60+ days old') }

        $managerName = ''
        if ($user.Manager) {
            try { $managerName = (Get-ADUser -Identity $user.Manager).SamAccountName }
            catch { $managerName = 'Unknown' }
        }

        $results.Add([PSCustomObject]@{
            Username             = $user.SamAccountName
            DisplayName          = $user.DisplayName
            Department           = $user.Department
            Title                = $user.Title
            Enabled              = $user.Enabled
            LastLogon            = $user.LastLogonDate
            PasswordLastSet      = $user.PasswordLastSet
            PasswordNeverExpires = $user.PasswordNeverExpires
            PasswordExpired      = $user.PasswordExpired
            LockedOut            = $user.LockedOut
            Created              = $user.Created
            Manager              = $managerName
            Issues               = if ($issues.Count -gt 0) { $issues -join '; ' } else { 'OK' }
            Timestamp            = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        })
    }

    $reportPath = Join-Path $OutputPath "ad-audit-report-$timestamp.csv"
    $results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    # Summary stats
    $total    = $results.Count
    $enabled  = ($results | Where-Object Enabled).Count
    $issues   = ($results | Where-Object { $_.Issues -ne 'OK' }).Count
    $inactive = ($results | Where-Object { $_.Issues -match 'Inactive' }).Count

    Write-Log "Audit complete — Total: $total | Enabled: $enabled | With issues: $issues | Inactive 90d: $inactive"
    Write-Log "Report saved: $reportPath"
}

#endregion

#region --- Entry point ---

try {
    switch ($Action) {
        'BulkCreate'  { Invoke-BulkCreate }
        'BulkDisable' { Invoke-BulkDisable }
        'Audit'       { Invoke-Audit }
    }
}
catch {
    Write-Log "Fatal error: $($_.Exception.Message)" -Level ERROR
    exit 1
}
finally {
    Stop-Transcript
}

#endregion
