#Requires -Version 5.1
<#
.SYNOPSIS
    Compares two OneDrive usage report CSVs to measure remediation progress.

.DESCRIPTION
    Identifies which affected users have self-healed (resumed syncing) and
    which still need remediation. Run this after each deployment batch.

.PARAMETER BaselineReport
    Path to the earlier CSV export (your Step 1 export — shows who was affected).

.PARAMETER CurrentReport
    Path to the latest CSV export (your Step 5 export — after remediation).

.PARAMETER CutoffDate
    Date the sync issue began. Users with no activity since this date are
    considered affected. Default: 2026-03-21.

.PARAMETER AffectedUsersFile
    Optional. Path to a .csv or .txt file containing the UPNs of known-affected
    users. If provided the comparison is narrowed to only those users.
    CSV: must contain a 'User Principal Name' column.
    TXT: one UPN per line.

.PARAMETER OutputPath
    CSV output path. Defaults to a timestamped file in the current directory.

.EXAMPLE
    # Compare two exports, deriving affected users automatically:
    .\Compare-OneDriveSyncReports.ps1 `
        -BaselineReport .\OneDriveUsage_20260518_090000.csv `
        -CurrentReport  .\OneDriveUsage_20260525_090000.csv

.EXAMPLE
    # Narrow to a specific known-affected list:
    .\Compare-OneDriveSyncReports.ps1 `
        -BaselineReport    .\OneDriveUsage_20260518_090000.csv `
        -CurrentReport     .\OneDriveUsage_20260525_090000.csv `
        -AffectedUsersFile .\affected_upns.txt
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BaselineReport,
    [Parameter(Mandatory)][string]$CurrentReport,
    [string]$CutoffDate        = '2026-03-21',
    [string]$AffectedUsersFile = '',
    [string]$OutputPath        = ".\SyncComparison_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = 'Stop'
$cutoff = [datetime]$CutoffDate

# ---------------------------------------------------------------------------
# Load reports
# ---------------------------------------------------------------------------
Write-Host "Loading baseline : $BaselineReport" -ForegroundColor Cyan
$baseline = Import-Csv -Path $BaselineReport

Write-Host "Loading current  : $CurrentReport" -ForegroundColor Cyan
$current  = Import-Csv -Path $CurrentReport

# Detect UPN column — handles BOM-prefixed variants that Graph API may produce
$upnCol = $baseline[0].PSObject.Properties.Name |
    Where-Object { $_ -match 'User Principal Name' } |
    Select-Object -First 1

if (-not $upnCol) {
    $foundHeaders = $baseline[0].PSObject.Properties.Name -join ', '
    Write-Error "Cannot find 'User Principal Name' column. Headers found: $foundHeaders"
    exit 1
}
Write-Host "UPN column       : '$upnCol'" -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Build fast lookup index of current report by UPN
# ---------------------------------------------------------------------------
$currentIndex = @{}
foreach ($row in $current) {
    $upn = $row.$upnCol
    if ($upn) { $currentIndex[$upn.ToLower()] = $row }
}

# ---------------------------------------------------------------------------
# Determine the set of affected users to track
# ---------------------------------------------------------------------------
if ($AffectedUsersFile -and (Test-Path $AffectedUsersFile)) {
    $ext = [System.IO.Path]::GetExtension($AffectedUsersFile).ToLower()
    if ($ext -eq '.csv') {
        $affectedUpns = (Import-Csv $AffectedUsersFile).$upnCol | Where-Object { $_ }
    } else {
        $affectedUpns = Get-Content $AffectedUsersFile | Where-Object { $_ -match '@' }
    }
    Write-Host "Using provided affected user list: $($affectedUpns.Count) users" -ForegroundColor Yellow
    $affectedSet  = $affectedUpns | ForEach-Object { $_.ToLower() }
    $affectedRows = $baseline | Where-Object { $affectedSet -contains $_.$upnCol.ToLower() }
} else {
    $affectedRows = $baseline | Where-Object {
        $lastActive = $null
        if (-not [string]::IsNullOrWhiteSpace($_.'Last Activity Date')) {
            try { $lastActive = [datetime]::Parse($_.'Last Activity Date') } catch { }
        }
        ($lastActive -eq $null) -or ($lastActive -lt $cutoff)
    }
    Write-Host "Derived $($affectedRows.Count) affected users from baseline (no activity since $CutoffDate)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Compare baseline vs current for each affected user
# ---------------------------------------------------------------------------
$results = $affectedRows | ForEach-Object {
    $upn        = $_.$upnCol
    $currentRow = $currentIndex[$upn.ToLower()]

    $baselineLastActive = $null
    if (-not [string]::IsNullOrWhiteSpace($_.'Last Activity Date')) {
        try { $baselineLastActive = [datetime]::Parse($_.'Last Activity Date') } catch { }
    }

    $currentLastActive = $null
    if ($currentRow -and -not [string]::IsNullOrWhiteSpace($currentRow.'Last Activity Date')) {
        try { $currentLastActive = [datetime]::Parse($currentRow.'Last Activity Date') } catch { }
    }

    $selfHealed = ($currentLastActive -ne $null) -and ($currentLastActive -ge $cutoff)

    [PSCustomObject]@{
        UPN                  = $upn
        DisplayName          = $_.'Owner Display Name'
        BaselineLastActivity = if ($baselineLastActive) { $baselineLastActive.ToString('yyyy-MM-dd') } else { 'Never' }
        CurrentLastActivity  = if ($currentLastActive)  { $currentLastActive.ToString('yyyy-MM-dd')  } else { 'None in period' }
        Status               = if ($selfHealed) { 'FIXED' } else { 'STILL BROKEN' }
        SelfHealed           = $selfHealed
        StorageGB            = if ($currentRow -and $currentRow.'Storage Used (Byte)') {
            [math]::Round([double]$currentRow.'Storage Used (Byte)' / 1GB, 2)
        } else { 0 }
    }
}

$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$total       = $results.Count
$fixed       = ($results | Where-Object { $_.Status -eq 'FIXED' }).Count
$stillBroken = ($results | Where-Object { $_.Status -eq 'STILL BROKEN' }).Count
$fixRate     = if ($total -gt 0) { [math]::Round($fixed / $total * 100, 1) } else { 0 }

Write-Host ""
Write-Host "===== Comparison Summary =====" -ForegroundColor Cyan
Write-Host "  Tracked users  : $total"       -ForegroundColor White
Write-Host "  Fixed          : $fixed"        -ForegroundColor Green
Write-Host "  Still broken   : $stillBroken"  -ForegroundColor Red
Write-Host "  Fix rate       : $fixRate%"     -ForegroundColor Yellow
Write-Host "  Output file    : $OutputPath"   -ForegroundColor White

if ($stillBroken -gt 0) {
    Write-Host ""
    Write-Host "Sample of users still not syncing (first 10):" -ForegroundColor Red
    $results | Where-Object { $_.Status -eq 'STILL BROKEN' } | Select-Object -First 10 |
        ForEach-Object { Write-Host "  $($_.UPN)  [last seen: $($_.BaselineLastActivity)]" }
}
