#Requires -Version 5.1
<#
.SYNOPSIS
    Exports OneDrive for Business usage report via Microsoft Graph API.

.DESCRIPTION
    Uses app-only (client credentials) authentication to pull the
    getOneDriveUsageAccountDetail report. Adds computed columns for
    easy identification of users affected by the March 2026 sync outage.

    PREREQUISITES:
    - App Registration in Entra ID with Reports.Read.All application permission
    - Admin consent granted on that permission
    - Report obfuscation disabled: M365 Admin Centre > Settings > Services > Reports
      "Hide user details in all reports" must be OFF, otherwise UPNs will be hashed.

.PARAMETER TenantId
    Azure AD Tenant ID (GUID).

.PARAMETER ClientId
    App Registration Client ID (GUID).

.PARAMETER ClientSecret
    App Registration Client Secret value.

.PARAMETER Period
    Report period. Use D90 for the initial baseline (covers March 21).
    Use D30 for validation exports after remediation.

.PARAMETER OutputPath
    CSV output path. Defaults to a timestamped file in the current directory.

.PARAMETER CutoffDate
    Date the sync issue began. Used to compute the AffectedByOutage column.

.EXAMPLE
    .\Export-OneDriveUsageReport.ps1 `
        -TenantId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientSecret "your-secret-value" `
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
    [Parameter(Mandatory)][string]$ClientSecret,
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]$Period     = 'D90',
    [string]$OutputPath = ".\OneDriveUsage_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$CutoffDate = '2026-03-21'
)

$ErrorActionPreference = 'Stop'
$cutoff = [datetime]$CutoffDate

# ---------------------------------------------------------------------------
# Authenticate
# ---------------------------------------------------------------------------
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Authenticating to Microsoft Graph..." -ForegroundColor Cyan

$tokenResponse = Invoke-RestMethod -Method Post `
    -Uri         "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -ContentType 'application/x-www-form-urlencoded' `
    -Body @{
        grant_type    = 'client_credentials'
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = 'https://graph.microsoft.com/.default'
    }

$headers   = @{ Authorization = "Bearer $($tokenResponse.access_token)" }
$reportUri = "https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period='$Period')"

# ---------------------------------------------------------------------------
# Fetch report
# The endpoint issues a 302 redirect to a temporary Azure blob CSV URL.
# We try MaximumRedirection first; if PS 5.1 throws on the redirect we
# extract the Location header and fetch the blob directly.
# ---------------------------------------------------------------------------
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Fetching report (period: $Period)..." -ForegroundColor Cyan

$rawCsv = $null
try {
    $response = Invoke-WebRequest -Uri $reportUri -Headers $headers `
                    -MaximumRedirection 10 -UseBasicParsing
    $rawCsv   = $response.Content
} catch {
    if ($_.Exception.Response) {
        $blobUri = $_.Exception.Response.Headers['Location']
        if (-not $blobUri) { throw "Could not retrieve report redirect URL: $_" }
        $rawCsv = (Invoke-WebRequest -Uri $blobUri -UseBasicParsing).Content
    } else {
        throw "Failed to retrieve report: $_"
    }
}

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
Write-Host "  Output file           : $OutputPath"          -ForegroundColor White
Write-Host "  Total records         : $totalUsers"          -ForegroundColor White
Write-Host "  Active / healthy      : $activeUsers"         -ForegroundColor Green
Write-Host "  Affected by outage    : $affectedUsers"       -ForegroundColor Yellow
Write-Host ""
Write-Host "REMINDER: Graph reports have a 24-48 hour refresh delay." -ForegroundColor DarkYellow
Write-Host "REMINDER: If UPNs appear as hashed strings, disable 'Hide user details'" -ForegroundColor DarkYellow
Write-Host "          in M365 Admin Centre > Settings > Services > Reports." -ForegroundColor DarkYellow
