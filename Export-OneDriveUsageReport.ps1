#Requires -Version 5.1
<#
.SYNOPSIS
    Exports OneDrive for Business usage report via Microsoft Graph.
    Uses interactive web authentication — no client secret required.

.DESCRIPTION
    Authenticates via Connect-MgGraph using delegated permissions.
    A browser window will open for you to sign in before the report downloads.

    REQUIRED MODULE (install once):
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

    OPTIONAL — enables a cleaner report download method:
        Install-Module Microsoft.Graph.Reports -Scope CurrentUser

    APP REGISTRATION REQUIREMENTS:
        - Platform:    Mobile and desktop applications (enables public client flow)
        - Permission:  Microsoft Graph > Delegated > Reports.Read.All
        - Admin consent granted on that delegated permission
        No client secret is needed or used.

    REPORT OBFUSCATION:
        Ensure "Hide user details in all reports" is OFF in
        M365 Admin Centre > Settings > Services > Reports.
        If it is ON, UPNs will appear as hashed strings and the comparison
        script will not be able to match users across exports.

.PARAMETER TenantId
    Azure AD Tenant ID (GUID).

.PARAMETER ClientId
    App Registration Client ID / App ID (GUID).

.PARAMETER Period
    Report period. Use D90 for the initial baseline (covers March 21).
    Use D30 for validation exports after remediation.

.PARAMETER OutputPath
    CSV output path. Defaults to a timestamped file in the current directory.

.PARAMETER CutoffDate
    Date the sync issue began. Used to compute the AffectedByOutage column.

.EXAMPLE
    .\Export-OneDriveUsageReport.ps1 `
        -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -Period D90

.NOTES
    Graph usage reports have a 24-48 hour refresh delay.
    A D90 report run today (2026-05-18) covers back to approximately 2026-02-17,
    which includes the March 21 outage date.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]$Period     = 'D90',
    [string]$OutputPath = ".\OneDriveUsage_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$CutoffDate = '2026-03-21'
)

$ErrorActionPreference = 'Stop'
$cutoff = [datetime]$CutoffDate

# ---------------------------------------------------------------------------
# Module check
# ---------------------------------------------------------------------------
if (-not (Get-Module -Name Microsoft.Graph.Authentication -ListAvailable)) {
    Write-Error @"
The Microsoft.Graph.Authentication module is not installed.
Run this once in an elevated PowerShell session, then re-run this script:

    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
"@
    exit 1
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# Reports module is optional — provides a cleaner download path
$useReportsCmdlet = [bool](Get-Module -Name Microsoft.Graph.Reports -ListAvailable)
if ($useReportsCmdlet) {
    Import-Module Microsoft.Graph.Reports -ErrorAction SilentlyContinue
    Write-Host "Microsoft.Graph.Reports module detected — using Get-MgReportOneDriveUsageAccountDetail." -ForegroundColor Gray
} else {
    Write-Host "Microsoft.Graph.Reports not found — using Invoke-MgGraphRequest fallback." -ForegroundColor Gray
    Write-Host "To install the Reports module: Install-Module Microsoft.Graph.Reports -Scope CurrentUser" -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# Interactive authentication
# A browser window will open. Sign in with your admin account.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Write-Host "Your browser will open for authentication. Sign in and return here." -ForegroundColor DarkYellow
Write-Host ""

try {
    Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -Scopes "Reports.Read.All" -NoWelcome
} catch {
    # -NoWelcome was added in SDK v2 — fall back silently for older installs
    Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -Scopes "Reports.Read.All"
}

$context = Get-MgContext
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Connected as: $($context.Account)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Fetch report
# ---------------------------------------------------------------------------
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Fetching OneDrive usage report (period: $Period)..." -ForegroundColor Cyan

$rawCsv  = $null
$tempFile = $null

if ($useReportsCmdlet) {
    # Reports module cmdlet handles the redirect and encoding natively
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        Get-MgReportOneDriveUsageAccountDetail -Period $Period -OutFile $tempFile
        $rawCsv = Get-Content -Path $tempFile -Raw -Encoding UTF8
    } finally {
        if ($tempFile -and (Test-Path $tempFile)) {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
} else {
    # Invoke-MgGraphRequest follows the blob storage redirect automatically.
    # -OutputType String returns the raw CSV body.
    $rawCsv = Invoke-MgGraphRequest `
        -Uri    "https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period='$Period')" `
        -Method GET `
        -OutputType String
}

Disconnect-MgGraph | Out-Null
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Disconnected from Graph." -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Parse CSV (strip UTF-8 BOM that Graph sometimes prepends)
# ---------------------------------------------------------------------------
$cleanCsv = $rawCsv.TrimStart([char]0xFEFF)
$data     = $cleanCsv | ConvertFrom-Csv

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Processing $($data.Count) user records..." -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Enrich with computed columns
# ---------------------------------------------------------------------------
$enriched = $data | ForEach-Object {
    $lastActive = $null
    if (-not [string]::IsNullOrWhiteSpace($_.'Last Activity Date')) {
        try { $lastActive = [datetime]::Parse($_.'Last Activity Date') } catch { }
    }

    $daysSince = if ($lastActive) { [int]([datetime]::Today - $lastActive).TotalDays } else { -1 }
    $affected  = ($lastActive -eq $null) -or ($lastActive -lt $cutoff)

    $_ | Select-Object *,
        @{N='LastActivityParsed'; E={ if ($lastActive) { $lastActive.ToString('yyyy-MM-dd') } else { 'Never' } }},
        @{N='DaysSinceActivity';  E={ $daysSince }},
        @{N='AffectedByOutage';   E={ $affected }},
        @{N='ExportTimestamp';    E={ Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }}
}

$enriched | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$totalUsers    = $enriched.Count
$activeUsers   = ($enriched | Where-Object { $_.AffectedByOutage -eq $false }).Count
$affectedUsers = ($enriched | Where-Object { $_.AffectedByOutage -eq $true  }).Count

Write-Host ""
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Export complete." -ForegroundColor Green
Write-Host "  Output file        : $OutputPath"    -ForegroundColor White
Write-Host "  Total records      : $totalUsers"    -ForegroundColor White
Write-Host "  Active / healthy   : $activeUsers"   -ForegroundColor Green
Write-Host "  Affected by outage : $affectedUsers" -ForegroundColor Yellow
Write-Host ""
Write-Host "REMINDER: Graph reports have a 24-48 hour refresh delay." -ForegroundColor DarkYellow
Write-Host "REMINDER: If UPNs appear as hashed strings, disable 'Hide user details'" -ForegroundColor DarkYellow
Write-Host "          in M365 Admin Centre > Settings > Services > Reports." -ForegroundColor DarkYellow
