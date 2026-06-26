#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Scans, reports, and optionally cleans stale/large files and temporary data across drives.

.DESCRIPTION
    Produces a full disk health report including:
      - Drive usage summary across all fixed drives
      - Top 20 largest files per drive
      - Stale files not accessed in N days
      - Temp folder sizes (Windows Temp, User Temp, prefetch)
      - Log files older than retention threshold
      - Optional safe cleanup of temp/stale data

.PARAMETER OutputPath
    Directory for output reports. Default: .\Reports\

.PARAMETER StaleFileDays
    Flag files not accessed in this many days as stale. Default: 180.

.PARAMETER LogRetentionDays
    Flag log files older than this as cleanup candidates. Default: 90.

.PARAMETER ScanPaths
    Array of paths to scan. Defaults to all fixed drives.

.PARAMETER Cleanup
    Perform safe cleanup (Windows Temp, user temp folders only). Requires confirmation.

.PARAMETER Force
    Skip confirmation prompts during cleanup.

.EXAMPLE
    .\disk-cleanup-report.ps1
    .\disk-cleanup-report.ps1 -StaleFileDays 90 -IncludeHTML -OutputPath C:\Reports
    .\disk-cleanup-report.ps1 -Cleanup -Force

.NOTES
    Author  : Fady Hakim
    Version : 1.0
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [string]$OutputPath = '.\Reports',

    [Parameter()]
    [ValidateRange(30, 1825)]
    [int]$StaleFileDays = 180,

    [Parameter()]
    [ValidateRange(7, 365)]
    [int]$LogRetentionDays = 90,

    [Parameter()]
    [string[]]$ScanPaths = @(),

    [Parameter()]
    [switch]$Cleanup,

    [Parameter()]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$staleCutoff = (Get-Date).AddDays(-$StaleFileDays)
$logCutoff   = (Get-Date).AddDays(-$LogRetentionDays)
$null        = New-Item -ItemType Directory -Path $OutputPath -Force

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO')
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'INFO'  { Write-Host $entry -ForegroundColor Cyan }
        'WARN'  { Write-Host $entry -ForegroundColor Yellow }
        'ERROR' { Write-Host $entry -ForegroundColor Red }
    }
}

function Format-Size {
    param([long]$Bytes)
    switch ($Bytes) {
        { $_ -ge 1TB } { return "{0:N2} TB" -f ($_ / 1TB) }
        { $_ -ge 1GB } { return "{0:N2} GB" -f ($_ / 1GB) }
        { $_ -ge 1MB } { return "{0:N2} MB" -f ($_ / 1MB) }
        { $_ -ge 1KB } { return "{0:N2} KB" -f ($_ / 1KB) }
        default         { return "$_ B" }
    }
}

Write-Log "Starting Disk Analysis — Host: $env:COMPUTERNAME"

#region --- Drive Summary ---

Write-Log "Scanning drive summary..."
$driveReport = [System.Collections.Generic.List[PSObject]]::new()

$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }

if ($ScanPaths.Count -eq 0) {
    $ScanPaths = $drives | ForEach-Object { $_.Root }
}

foreach ($drive in $drives) {
    $total = $drive.Used + $drive.Free
    if ($total -eq 0) { continue }
    $usedPct = [math]::Round(($drive.Used / $total) * 100, 1)
    $status  = if ($usedPct -ge 90) { 'CRITICAL' } elseif ($usedPct -ge 75) { 'WARNING' } else { 'OK' }

    Write-Log "$($drive.Root) — Used: $(Format-Size $drive.Used) / $(Format-Size $total) ($usedPct%) — $status" `
        -Level $(if ($status -eq 'OK') { 'INFO' } else { 'WARN' })

    $driveReport.Add([PSCustomObject]@{
        Drive      = $drive.Root
        TotalGB    = [math]::Round($total / 1GB, 2)
        UsedGB     = [math]::Round($drive.Used / 1GB, 2)
        FreeGB     = [math]::Round($drive.Free / 1GB, 2)
        UsedPct    = $usedPct
        Status     = $status
        Timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    })
}

$driveCSV = Join-Path $OutputPath "drive-summary-$timestamp.csv"
$driveReport | Export-Csv -Path $driveCSV -NoTypeInformation -Encoding UTF8

#endregion

#region --- Largest Files ---

Write-Log "Scanning for largest files (top 20 per drive)..."
$largeFileReport = [System.Collections.Generic.List[PSObject]]::new()

foreach ($path in $ScanPaths) {
    if (-not (Test-Path $path)) { continue }
    Write-Log "Scanning: $path"
    try {
        $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
            Sort-Object Length -Descending |
            Select-Object -First 20

        foreach ($file in $files) {
            $largeFileReport.Add([PSCustomObject]@{
                Drive        = $path
                Path         = $file.FullName
                SizeGB       = [math]::Round($file.Length / 1GB, 4)
                SizeMB       = [math]::Round($file.Length / 1MB, 2)
                LastAccessed = $file.LastAccessTime
                LastModified = $file.LastWriteTime
                Extension    = $file.Extension
            })
        }
    }
    catch { Write-Log "Could not fully scan $path — partial results" -Level WARN }
}

$largeCSV = Join-Path $OutputPath "large-files-$timestamp.csv"
$largeFileReport | Sort-Object SizeMB -Descending | Export-Csv -Path $largeCSV -NoTypeInformation -Encoding UTF8
Write-Log "Large files report saved: $largeCSV"

#endregion

#region --- Stale Files ---

Write-Log "Scanning for stale files (not accessed in $StaleFileDays days)..."
$staleReport = [System.Collections.Generic.List[PSObject]]::new()
$staleTotal  = 0

foreach ($path in $ScanPaths) {
    if (-not (Test-Path $path)) { continue }
    try {
        $staleFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastAccessTime -lt $staleCutoff }

        foreach ($file in $staleFiles) {
            $staleTotal += $file.Length
            $staleReport.Add([PSCustomObject]@{
                Path         = $file.FullName
                SizeMB       = [math]::Round($file.Length / 1MB, 2)
                LastAccessed = $file.LastAccessTime
                LastModified = $file.LastWriteTime
                AgeDays      = [math]::Round(((Get-Date) - $file.LastAccessTime).TotalDays, 0)
                Extension    = $file.Extension
            })
        }
    }
    catch { Write-Log "Stale file scan partial: $path" -Level WARN }
}

Write-Log "Stale files found: $($staleReport.Count) — Potential reclaim: $(Format-Size $staleTotal)"
$staleCSV = Join-Path $OutputPath "stale-files-$timestamp.csv"
$staleReport | Sort-Object AgeDays -Descending | Export-Csv -Path $staleCSV -NoTypeInformation -Encoding UTF8

#endregion

#region --- Temp Folder Analysis ---

Write-Log "Analysing temp folders..."
$tempPaths = @(
    $env:TEMP,
    $env:TMP,
    "$env:WINDIR\Temp",
    "$env:WINDIR\Prefetch",
    "$env:LOCALAPPDATA\Temp"
) | Sort-Object -Unique | Where-Object { Test-Path $_ }

$tempReport = [System.Collections.Generic.List[PSObject]]::new()

foreach ($tempPath in $tempPaths) {
    try {
        $files = Get-ChildItem -Path $tempPath -Recurse -File -ErrorAction SilentlyContinue
        $size  = ($files | Measure-Object Length -Sum).Sum
        $count = $files.Count
        $oldest = if ($files) { ($files | Sort-Object LastWriteTime)[0].LastWriteTime } else { $null }

        $tempReport.Add([PSCustomObject]@{
            Path      = $tempPath
            FileCount = $count
            SizeMB    = [math]::Round($size / 1MB, 2)
            OldestFile = $oldest
        })
        Write-Log "Temp: $tempPath — $count files, $(Format-Size $size)"
    }
    catch { Write-Log "Could not analyse temp path: $tempPath" -Level WARN }
}

$tempCSV = Join-Path $OutputPath "temp-analysis-$timestamp.csv"
$tempReport | Export-Csv -Path $tempCSV -NoTypeInformation -Encoding UTF8

#endregion

#region --- Optional Cleanup ---

if ($Cleanup) {
    $cleanPaths = @("$env:WINDIR\Temp", $env:TEMP, $env:TMP) | Sort-Object -Unique | Where-Object { Test-Path $_ }
    $cleanedSize  = 0
    $cleanedCount = 0

    Write-Log "Cleanup mode — will remove files from: $($cleanPaths -join ', ')"

    if (-not $Force) {
        $confirm = Read-Host "Proceed with cleanup? (y/N)"
        if ($confirm -ine 'y') { Write-Log "Cleanup cancelled by user"; exit 0 }
    }

    foreach ($cleanPath in $cleanPaths) {
        $files = Get-ChildItem -Path $cleanPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) }

        foreach ($file in $files) {
            if ($PSCmdlet.ShouldProcess($file.FullName, "Delete")) {
                try {
                    $size = $file.Length
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    $cleanedSize  += $size
                    $cleanedCount++
                }
                catch { Write-Log "Could not delete: $($file.FullName)" -Level WARN }
            }
        }
    }

    Write-Log "Cleanup complete — Removed: $cleanedCount files, Reclaimed: $(Format-Size $cleanedSize)"
}

#endregion

#region --- Summary ---

$totalReclaim = $staleReport | Measure-Object SizeMB -Sum | Select-Object -ExpandProperty Sum
$critDrives   = ($driveReport | Where-Object { $_.Status -eq 'CRITICAL' }).Count

Write-Log "========================================="
Write-Log "DISK ANALYSIS COMPLETE — $env:COMPUTERNAME"
Write-Log "Drives scanned  : $($driveReport.Count)"
Write-Log "Critical drives : $critDrives"
Write-Log "Stale files     : $($staleReport.Count) — $(Format-Size $staleTotal) potential reclaim"
Write-Log "Largest file    : $(($largeFileReport | Sort-Object SizeMB -Descending | Select-Object -First 1).Path)"
Write-Log "Reports in      : $OutputPath"
Write-Log "========================================="

if ($critDrives -gt 0) { exit 1 } else { exit 0 }

#endregion
