#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Monitors Windows Security event logs and alerts on suspicious activity patterns.

.DESCRIPTION
    Parses the Windows Security event log for high-signal security events:
      - Brute force / lockout detection (4625, 4740)
      - Privilege escalation attempts (4672, 4673)
      - Account and group changes (4720, 4728, 4732)
      - Logon anomalies (after-hours, new machines)
      - Audit policy tampering (4719)
      - Service installation (7045)

    Produces a CSV alert report. Designed to run as a scheduled task.

.PARAMETER HoursBack
    How many hours of logs to analyse. Default: 24.

.PARAMETER OutputPath
    Directory for alert reports. Default: .\Reports\

.PARAMETER BruteForceThreshold
    Failed logon attempts within the window to trigger a brute force alert. Default: 5.

.PARAMETER AlertEmail
    If provided, sends alert summary via Send-MailMessage (requires SMTP config).

.PARAMETER SMTPServer
    SMTP server address for email alerts.

.EXAMPLE
    .\eventlog-monitor.ps1
    .\eventlog-monitor.ps1 -HoursBack 6 -BruteForceThreshold 3 -OutputPath C:\Reports
    .\eventlog-monitor.ps1 -HoursBack 24 -AlertEmail soc@company.com -SMTPServer mail.company.com

.NOTES
    Author  : Fady Hakim
    Version : 1.0
    Schedule: Run every 1-6 hours via Task Scheduler for continuous monitoring
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateRange(1, 168)]
    [int]$HoursBack = 24,

    [Parameter()]
    [string]$OutputPath = '.\Reports',

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$BruteForceThreshold = 5,

    [Parameter()]
    [string]$AlertEmail = '',

    [Parameter()]
    [string]$SMTPServer = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$startTime  = (Get-Date).AddHours(-$HoursBack)
$null       = New-Item -ItemType Directory -Path $OutputPath -Force
$alerts     = [System.Collections.Generic.List[PSObject]]::new()

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ALERT','ERROR')][string]$Level = 'INFO')
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'INFO'  { Write-Host $entry -ForegroundColor Cyan }
        'WARN'  { Write-Host $entry -ForegroundColor Yellow }
        'ALERT' { Write-Host $entry -ForegroundColor Red }
        'ERROR' { Write-Host $entry -ForegroundColor Red }
    }
}

function Add-Alert {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$Description,
        [string]$Account   = '',
        [string]$SourceIP  = '',
        [string]$EventIDs  = '',
        [int]$Count        = 1,
        [datetime]$FirstSeen = (Get-Date),
        [datetime]$LastSeen  = (Get-Date)
    )
    Write-Log "[$Severity] $Category — $Description" -Level ALERT
    $alerts.Add([PSCustomObject]@{
        Severity    = $Severity
        Category    = $Category
        Description = $Description
        Account     = $Account
        SourceIP    = $SourceIP
        EventIDs    = $EventIDs
        Count       = $Count
        FirstSeen   = $FirstSeen
        LastSeen    = $LastSeen
        Host        = $env:COMPUTERNAME
        Timestamp   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    })
}

Write-Log "Starting event log analysis — Last $HoursBack hours (since $startTime)"

$filterBase = @{
    LogName   = 'Security'
    StartTime = $startTime
}

#region --- Failed Logons / Brute Force (4625) ---

Write-Log "Checking failed logons (Event 4625)..."
try {
    $failedLogons = Get-WinEvent -FilterHashtable (@{ Id = 4625 } + $filterBase) -ErrorAction SilentlyContinue

    if ($failedLogons) {
        # Group by account + source IP to detect brute force
        $grouped = $failedLogons | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data
            [PSCustomObject]@{
                Account    = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                SourceIP   = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                LogonType  = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                TimeCreated = $_.TimeCreated
            }
        } | Group-Object Account, SourceIP

        foreach ($group in $grouped) {
            if ($group.Count -ge $BruteForceThreshold) {
                $times = $group.Group.TimeCreated | Sort-Object
                $parts = $group.Name -split ', '
                Add-Alert -Severity 'HIGH' -Category 'Brute Force' `
                    -Description "$($group.Count) failed logon attempts — threshold: $BruteForceThreshold" `
                    -Account $parts[0] -SourceIP $parts[1] -EventIDs '4625' `
                    -Count $group.Count -FirstSeen $times[0] -LastSeen $times[-1]
            }
        }

        # Alert on admin account failures specifically
        $adminFails = $failedLogons | Where-Object {
            $xml = [xml]$_.ToXml()
            ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text' -in @('Administrator', 'Admin', 'admin')
        }
        if ($adminFails) {
            Add-Alert -Severity 'HIGH' -Category 'Admin Account Targeted' `
                -Description "$($adminFails.Count) failed logons against privileged account names" `
                -Account 'Administrator/Admin' -EventIDs '4625' -Count $adminFails.Count
        }
    }
    else { Write-Log "No failed logon events found" }
}
catch { Write-Log "Failed logon check error: $_" -Level WARN }

#endregion

#region --- Account Lockouts (4740) ---

Write-Log "Checking account lockouts (Event 4740)..."
try {
    $lockouts = Get-WinEvent -FilterHashtable (@{ Id = 4740 } + $filterBase) -ErrorAction SilentlyContinue
    if ($lockouts) {
        $grouped = $lockouts | Group-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text' }
        foreach ($group in $grouped) {
            Add-Alert -Severity 'MEDIUM' -Category 'Account Lockout' `
                -Description "Account locked out $($group.Count) time(s)" `
                -Account $group.Name -EventIDs '4740' -Count $group.Count `
                -FirstSeen ($group.Group.TimeCreated | Sort-Object)[0] `
                -LastSeen ($group.Group.TimeCreated | Sort-Object)[-1]
        }
    }
    else { Write-Log "No lockout events found" }
}
catch { Write-Log "Lockout check error: $_" -Level WARN }

#endregion

#region --- Privilege Use (4672, 4673) ---

Write-Log "Checking privileged logons (Event 4672)..."
try {
    $privLogons = Get-WinEvent -FilterHashtable (@{ Id = 4672 } + $filterBase) -ErrorAction SilentlyContinue
    if ($privLogons) {
        $grouped = $privLogons | Group-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' } | Select-Object -ExpandProperty '#text' } |
            Where-Object { $_.Name -notmatch 'SYSTEM|LOCAL SERVICE|NETWORK SERVICE|\$$' }

        foreach ($group in $grouped | Where-Object { $_.Count -gt 5 }) {
            Add-Alert -Severity 'LOW' -Category 'Privileged Logon Volume' `
                -Description "$($group.Count) privileged logon events — may indicate unusual admin activity" `
                -Account $group.Name -EventIDs '4672' -Count $group.Count
        }
    }
}
catch { Write-Log "Privilege logon check error: $_" -Level WARN }

#endregion

#region --- Account Changes (4720, 4722, 4725, 4726, 4728, 4732, 4756) ---

Write-Log "Checking account and group changes..."
$accountEventMap = @{
    4720 = @{ Severity = 'HIGH';   Description = 'User account created' }
    4722 = @{ Severity = 'MEDIUM'; Description = 'User account enabled' }
    4725 = @{ Severity = 'MEDIUM'; Description = 'User account disabled' }
    4726 = @{ Severity = 'HIGH';   Description = 'User account deleted' }
    4728 = @{ Severity = 'HIGH';   Description = 'Member added to security-enabled global group' }
    4732 = @{ Severity = 'HIGH';   Description = 'Member added to security-enabled local group' }
    4756 = @{ Severity = 'HIGH';   Description = 'Member added to security-enabled universal group' }
}

foreach ($eventId in $accountEventMap.Keys) {
    try {
        $events = Get-WinEvent -FilterHashtable (@{ Id = $eventId } + $filterBase) -ErrorAction SilentlyContinue
        if ($events) {
            Add-Alert -Severity $accountEventMap[$eventId].Severity `
                -Category 'Account Change' `
                -Description "$($accountEventMap[$eventId].Description) — $($events.Count) occurrence(s)" `
                -EventIDs $eventId.ToString() -Count $events.Count `
                -FirstSeen ($events.TimeCreated | Sort-Object)[0] `
                -LastSeen ($events.TimeCreated | Sort-Object)[-1]
        }
    }
    catch { Write-Log "Account change check failed for event $eventId" -Level WARN }
}

#endregion

#region --- Audit Policy Change (4719) ---

Write-Log "Checking audit policy changes (Event 4719)..."
try {
    $auditChanges = Get-WinEvent -FilterHashtable (@{ Id = 4719 } + $filterBase) -ErrorAction SilentlyContinue
    if ($auditChanges) {
        Add-Alert -Severity 'CRITICAL' -Category 'Audit Policy Tampering' `
            -Description "Audit policy was modified $($auditChanges.Count) time(s) — possible evasion attempt" `
            -EventIDs '4719' -Count $auditChanges.Count
    }
    else { Write-Log "No audit policy changes detected" }
}
catch { Write-Log "Audit policy check error: $_" -Level WARN }

#endregion

#region --- New Service Installation (7045) ---

Write-Log "Checking new service installations (Event 7045)..."
try {
    $newServices = Get-WinEvent -FilterHashtable (@{ Id = 7045; LogName = 'System'; StartTime = $startTime }) -ErrorAction SilentlyContinue
    if ($newServices) {
        foreach ($event in $newServices) {
            $xml = [xml]$event.ToXml()
            $svcName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
            $svcFile = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ImagePath' }).'#text'
            Add-Alert -Severity 'HIGH' -Category 'New Service Installed' `
                -Description "Service '$svcName' installed — Path: $svcFile" `
                -EventIDs '7045' -Count 1 -FirstSeen $event.TimeCreated -LastSeen $event.TimeCreated
        }
    }
    else { Write-Log "No new service installations detected" }
}
catch { Write-Log "Service install check error: $_" -Level WARN }

#endregion

#region --- Output ---

$criticalCount = ($alerts | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
$highCount     = ($alerts | Where-Object { $_.Severity -eq 'HIGH' }).Count
$mediumCount   = ($alerts | Where-Object { $_.Severity -eq 'MEDIUM' }).Count

if ($alerts.Count -eq 0) {
    Write-Log "No alerts generated — environment looks clean for the last $HoursBack hours"
}
else {
    $csvPath = Join-Path $OutputPath "eventlog-alerts-$timestamp.csv"
    $alerts | Sort-Object { switch($_.Severity) { 'CRITICAL' {0} 'HIGH' {1} 'MEDIUM' {2} default {3} } } |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "Alert report saved: $csvPath"
    Write-Log "Summary — CRITICAL: $criticalCount | HIGH: $highCount | MEDIUM: $mediumCount | Total: $($alerts.Count)" -Level ALERT
}

# Optional email alert
if ($AlertEmail -and $SMTPServer -and $alerts.Count -gt 0) {
    try {
        $body = "Security Alert Summary — $env:COMPUTERNAME`n" +
                "Period: Last $HoursBack hours`n`n" +
                "CRITICAL: $criticalCount | HIGH: $highCount | MEDIUM: $mediumCount`n`n" +
                ($alerts | ForEach-Object { "[$($_.Severity)] $($_.Category): $($_.Description)" } | Out-String)

        Send-MailMessage -To $AlertEmail -From "eventlog-monitor@$env:COMPUTERNAME" `
            -Subject "[$env:COMPUTERNAME] Security Alerts — $criticalCount CRITICAL, $highCount HIGH" `
            -Body $body -SmtpServer $SMTPServer
        Write-Log "Alert email sent to $AlertEmail"
    }
    catch { Write-Log "Email send failed: $_" -Level WARN }
}

if ($criticalCount -gt 0) { exit 2 }
elseif ($highCount -gt 0) { exit 1 }
else { exit 0 }

#endregion
