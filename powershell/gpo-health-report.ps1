#Requires -Modules GroupPolicy, ActiveDirectory
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Exports a full Group Policy health and compliance report across all OUs.

.DESCRIPTION
    Scans all GPOs in the domain and produces a structured CSV + HTML report covering:
      - GPO link status (enabled/disabled/enforced)
      - WMI filter presence
      - Last modification date (flags stale GPOs)
      - Unlinked GPOs (cleanup candidates)
      - Computer and user policy section status
      - Security filtering principals

.PARAMETER OutputPath
    Directory for output reports. Defaults to .\Reports\

.PARAMETER StaleDays
    Number of days since last modification to flag a GPO as stale. Default: 180.

.PARAMETER IncludeHTML
    Generate an HTML report in addition to CSV.

.EXAMPLE
    .\gpo-health-report.ps1
    .\gpo-health-report.ps1 -OutputPath C:\Reports -StaleDays 90 -IncludeHTML

.NOTES
    Author  : Fady Hakim
    Version : 1.0
    Requires: GroupPolicy module (RSAT), Domain read access
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$OutputPath = '.\Reports',

    [Parameter()]
    [ValidateRange(30, 730)]
    [int]$StaleDays = 180,

    [Parameter()]
    [switch]$IncludeHTML
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$null = New-Item -ItemType Directory -Path $OutputPath -Force

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO')
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'INFO'  { Write-Host $entry -ForegroundColor Cyan }
        'WARN'  { Write-Host $entry -ForegroundColor Yellow }
        'ERROR' { Write-Host $entry -ForegroundColor Red }
    }
}

Write-Log "Starting GPO Health Report — Domain: $((Get-ADDomain).DNSRoot)"

$staleCutoff = (Get-Date).AddDays(-$StaleDays)
$results     = [System.Collections.Generic.List[PSObject]]::new()

try {
    $allGPOs = Get-GPO -All
    Write-Log "Found $($allGPOs.Count) GPOs"

    # Build a map of all GPO links across OUs
    $linkMap = @{}
    $ous = @()
    $ous += Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
    $ous += Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName

    foreach ($ou in $ous) {
        try {
            $links = (Get-GPInheritance -Target $ou).GpoLinks
            foreach ($link in $links) {
                if (-not $linkMap.ContainsKey($link.GpoId.ToString())) {
                    $linkMap[$link.GpoId.ToString()] = [System.Collections.Generic.List[PSObject]]::new()
                }
                $linkMap[$link.GpoId.ToString()].Add([PSCustomObject]@{
                    OU       = $ou
                    Enabled  = $link.Enabled
                    Enforced = $link.Enforced
                    Order    = $link.Order
                })
            }
        }
        catch {
            Write-Log "Could not read GPO links for: $ou" -Level WARN
        }
    }

    foreach ($gpo in $allGPOs) {
        $gpoId    = $gpo.Id.ToString()
        $links    = if ($linkMap.ContainsKey($gpoId)) { $linkMap[$gpoId] } else { @() }
        $isLinked = $links.Count -gt 0
        $isStale  = $gpo.ModificationTime -lt $staleCutoff

        # Security filtering
        $secFiltering = ''
        try {
            $perms        = Get-GPPermission -Guid $gpo.Id -All -ErrorAction SilentlyContinue
            $applyPerms   = $perms | Where-Object { $_.Permission -eq 'GpoApply' }
            $secFiltering = ($applyPerms | ForEach-Object { $_.Trustee.Name }) -join '; '
        }
        catch { $secFiltering = 'Unable to read' }

        # WMI filter
        $wmiFilter = if ($gpo.WmiFilter) { $gpo.WmiFilter.Name } else { 'None' }

        # Link summary
        $linkedOUs    = ($links | ForEach-Object { $_.OU }) -join ' | '
        $hasEnforced  = [bool]($links | Where-Object { $_.Enforced })
        $hasDisabled  = [bool]($links | Where-Object { -not $_.Enabled })

        $flags = [System.Collections.Generic.List[string]]::new()
        if (-not $isLinked)   { $flags.Add('Unlinked') }
        if ($isStale)         { $flags.Add("Stale ($StaleDays+ days)") }
        if ($hasEnforced)     { $flags.Add('Has enforced link') }
        if ($hasDisabled)     { $flags.Add('Has disabled link') }
        if ($wmiFilter -ne 'None') { $flags.Add("WMI filter: $wmiFilter") }
        if ($gpo.GpoStatus -eq 'AllSettingsDisabled') { $flags.Add('All settings disabled') }

        $results.Add([PSCustomObject]@{
            GPOName              = $gpo.DisplayName
            GPOID                = $gpoId
            Status               = $gpo.GpoStatus
            Created              = $gpo.CreationTime
            LastModified         = $gpo.ModificationTime
            IsStale              = $isStale
            IsLinked             = $isLinked
            LinkCount            = $links.Count
            LinkedOUs            = $linkedOUs
            HasEnforcedLink      = $hasEnforced
            HasDisabledLink      = $hasDisabled
            ComputerEnabled      = $gpo.Computer.Enabled
            UserEnabled          = $gpo.User.Enabled
            WMIFilter            = $wmiFilter
            SecurityFiltering    = $secFiltering
            Flags                = if ($flags.Count -gt 0) { $flags -join '; ' } else { 'OK' }
            ReportTimestamp      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        })
    }

    # CSV report
    $csvPath = Join-Path $OutputPath "gpo-health-report-$timestamp.csv"
    $results | Sort-Object IsLinked, IsStale, GPOName | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV saved: $csvPath"

    # HTML report
    if ($IncludeHTML) {
        $unlinked = ($results | Where-Object { -not $_.IsLinked }).Count
        $stale    = ($results | Where-Object IsStale).Count
        $issues   = ($results | Where-Object { $_.Flags -ne 'OK' }).Count
        $total    = $results.Count

        $rows = $results | Sort-Object IsLinked, IsStale, GPOName | ForEach-Object {
            $rowClass = if ($_.Flags -ne 'OK') { 'style="background:#fff3cd"' } else { '' }
            "<tr $rowClass>
              <td>$($_.GPOName)</td>
              <td>$($_.Status)</td>
              <td>$(if ($_.IsLinked) { '&#10003;' } else { '<strong style=color:red>Unlinked</strong>' })</td>
              <td>$($_.LinkCount)</td>
              <td>$(if ($_.IsStale) { '<span style=color:orange>Stale</span>' } else { 'OK' })</td>
              <td>$($_.LastModified.ToString('yyyy-MM-dd'))</td>
              <td>$($_.WMIFilter)</td>
              <td>$($_.Flags)</td>
            </tr>"
        }

        $html = @"
<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>GPO Health Report</title>
<style>
  body { font-family: Segoe UI, sans-serif; font-size: 13px; margin: 2rem; color: #333; }
  h1   { color: #1a5276; }
  .summary { display: flex; gap: 2rem; margin-bottom: 1.5rem; }
  .card { background: #f4f6f7; border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; }
  .card .num { font-size: 2rem; font-weight: bold; color: #1a5276; }
  table { border-collapse: collapse; width: 100%; }
  th { background: #1a5276; color: white; padding: 8px 12px; text-align: left; }
  td { padding: 6px 12px; border-bottom: 1px solid #eee; }
  tr:hover td { background: #eaf4fb; }
</style></head><body>
<h1>GPO Health Report</h1>
<p>Domain: $((Get-ADDomain).DNSRoot) &mdash; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<div class='summary'>
  <div class='card'><div class='num'>$total</div>Total GPOs</div>
  <div class='card'><div class='num' style='color:#c0392b'>$unlinked</div>Unlinked</div>
  <div class='card'><div class='num' style='color:#e67e22'>$stale</div>Stale ($StaleDays d+)</div>
  <div class='card'><div class='num' style='color:#e67e22'>$issues</div>With flags</div>
</div>
<table>
<tr><th>GPO Name</th><th>Status</th><th>Linked</th><th>Links</th><th>Stale</th><th>Last Modified</th><th>WMI Filter</th><th>Flags</th></tr>
$($rows -join "`n")
</table></body></html>
"@
        $htmlPath = Join-Path $OutputPath "gpo-health-report-$timestamp.html"
        $html | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Log "HTML saved: $htmlPath"
    }

    # Summary
    $unlinkedCount = ($results | Where-Object { -not $_.IsLinked }).Count
    $staleCount    = ($results | Where-Object IsStale).Count
    Write-Log "Done — Total: $($results.Count) | Unlinked: $unlinkedCount | Stale: $staleCount | With flags: $(($results | Where-Object { $_.Flags -ne 'OK' }).Count)"
}
catch {
    Write-Log "Fatal error: $($_.Exception.Message)" -Level ERROR
    exit 1
}
