#Requires -Version 5.1
<#
.SYNOPSIS
    Checks OneDrive for Business sync status on the current user's device.

.DESCRIPTION
    Examines the OneDrive process state, registry account configuration,
    sync diagnostic logs, Azure AD device join status, and PRT validity.
    Reports the overall health and a specific recommendation.

    USE AS INTUNE DETECTION SCRIPT:
        Set "Run as account" = User (NOT System)
        Exit 0 = Compliant  (OneDrive appears healthy — no remediation)
        Exit 1 = Non-compliant (remediation needed)

    USE STANDALONE:
        Run as the affected user, review full diagnostic output.

.NOTES
    This script MUST run in the context of the signed-in user.
    Running as SYSTEM will read the wrong registry hive and give false results.

    OverallHealth values and their meaning:
        OK             - OneDrive running and account configured
        NOT_SYNCING    - Not running or not signed in; safe to remediate
        POLICY_MISSING - SilentAccountConfig not deployed; deploy before resetting
        PRT_INVALID    - PRT expired/missing; reset will likely fail silently
        DEVICE_ERROR   - Device not Azure AD joined; cannot use silent sign-in
        BLOCKED        - CA or MFA policy blocking; fix policy before resetting
#>

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Error code reference
# ---------------------------------------------------------------------------
$ErrorDescriptions = @{
    '0x8004de40'  = 'No internet or proxy blocking OneDrive'
    '0x8004de80'  = 'Corporate identity required — account or tenant mismatch'
    '0x8004de86'  = 'Conditional Access policy blocking OneDrive sign-in'
    '0x8004def0'  = 'Authentication token expired or invalid'
    '0x8004de69'  = 'Single Sign-On (SSO) failed'
    '0x8004de8a'  = 'Account not supported in this configuration'
    '0x8004de9a'  = 'User account disabled or deleted in Azure AD'
    '0x8004de90'  = 'Organisation has disabled OneDrive for this user'
    '0x80049450'  = 'Non-commercial OneDrive cannot sync SharePoint/Business content'
    '0x80070185'  = 'Network path not found or connection dropped'
    'AADSTS50055' = 'User password has expired'
    'AADSTS50057' = 'User account is disabled'
    'AADSTS50072' = 'MFA required — cannot sign in silently'
    'AADSTS50076' = 'MFA required by Conditional Access policy'
    'AADSTS53003' = 'Access blocked by Conditional Access policy'
    'AADSTS70011' = 'Invalid OAuth scope — app configuration issue'
    'AADSTS90072' = 'Tenant not found or login endpoint unreachable'
}

# ---------------------------------------------------------------------------
# Build status object
# ---------------------------------------------------------------------------
$s = [PSCustomObject]@{
    Timestamp          = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    ComputerName       = $env:COMPUTERNAME
    UserName           = $env:USERNAME
    OneDriveRunning    = $false
    AccountConfigured  = $false
    UserEmail          = ''
    SyncFolder         = ''
    OneDriveVersion    = ''
    LogLastWritten     = ''
    SyncStatus         = 'Unknown'
    ErrorCode          = ''
    ErrorDescription   = ''
    PrtValid           = $false
    AzureAdJoined      = $false
    HybridJoined       = $false
    SilentConfigPolicy = $false
    OverallHealth      = 'UNKNOWN'
    Recommendation     = ''
}

# 1. Process check
$s.OneDriveRunning = [bool](Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue)

# 2. Registry — account configuration
$acctReg = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1' -ErrorAction SilentlyContinue
if ($acctReg) {
    $s.AccountConfigured = -not [string]::IsNullOrEmpty($acctReg.UserEmail)
    $s.UserEmail         = $acctReg.UserEmail
    $s.SyncFolder        = $acctReg.UserFolder
}

# 3. OneDrive version
foreach ($candidate in @(
    "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
    "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
    "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe"
)) {
    if (Test-Path $candidate) {
        $s.OneDriveVersion = (Get-Item $candidate).VersionInfo.FileVersion
        break
    }
}

# 4. SyncDiagnostics.log — sync status and error codes
$logFile = "$env:LOCALAPPDATA\Microsoft\OneDrive\logs\Business1\SyncDiagnostics.log"
if (Test-Path $logFile) {
    $logItem = Get-Item $logFile
    $s.LogLastWritten = $logItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')

    $logContent = Get-Content -Path $logFile -ErrorAction SilentlyContinue
    if ($logContent) {
        $tail = if ($logContent.Count -gt 300) { $logContent[-300..-1] } else { $logContent }
        foreach ($line in $tail) {
            if ($line -match 'Sync\s*Status\s*[:\|]\s*(.+)') {
                $s.SyncStatus = $matches[1].Trim()
            }
            # Capture hex error codes (e.g. 0x8004de86)
            if ($line -match '(0x[0-9A-Fa-f]{8})') {
                $s.ErrorCode = $matches[1]
            }
            # Capture AADSTS error codes
            if ($line -match '(AADSTS\d{5,6})') {
                $s.ErrorCode = $matches[1]
            }
        }
    }
}

# Infer status if log did not provide one
if ($s.SyncStatus -eq 'Unknown') {
    if (-not $s.OneDriveRunning)        { $s.SyncStatus = 'Not Running' }
    elseif (-not $s.AccountConfigured)  { $s.SyncStatus = 'Not Signed In' }
    else                                { $s.SyncStatus = 'Running — status undetermined from logs' }
}

# Resolve error description
if ($s.ErrorCode) {
    if ($ErrorDescriptions.ContainsKey($s.ErrorCode)) {
        $s.ErrorDescription = $ErrorDescriptions[$s.ErrorCode]
    } else {
        $s.ErrorDescription = "Unknown error — search docs.microsoft.com for $($s.ErrorCode)"
    }
}

# 5. Azure AD / PRT status via dsregcmd
$dsreg = & dsregcmd.exe /status 2>&1
if ($dsreg) {
    $s.AzureAdJoined = [bool]($dsreg | Select-String 'AzureAdJoined\s*:\s*YES' -Quiet)
    $s.HybridJoined  = [bool]($dsreg | Select-String 'DomainJoined\s*:\s*YES'  -Quiet) -and $s.AzureAdJoined
    $s.PrtValid      = [bool]($dsreg | Select-String 'AzureAdPrt\s*:\s*YES'    -Quiet)
}

# 6. SilentAccountConfig policy (must be HKLM — set by Intune/GPO, not per-user)
$silentPol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' `
                -Name 'SilentAccountConfig' -ErrorAction SilentlyContinue
$s.SilentConfigPolicy = ($silentPol -ne $null -and $silentPol.SilentAccountConfig -eq 1)

# ---------------------------------------------------------------------------
# Determine overall health and recommendation
# ---------------------------------------------------------------------------
$caBlocked = $s.ErrorCode -match '0x8004de86|AADSTS53003|AADSTS50072|AADSTS50076'

if ($caBlocked) {
    $s.OverallHealth  = 'BLOCKED'
    $s.Recommendation = "CA or MFA policy is blocking sign-in ($($s.ErrorCode): $($s.ErrorDescription)). Fix the policy before running reset — reset will not help."
} elseif (-not $s.AzureAdJoined) {
    $s.OverallHealth  = 'DEVICE_ERROR'
    $s.Recommendation = 'Device is not Azure AD joined. Re-register in Entra ID (dsregcmd /join). Silent sign-in cannot work until resolved.'
} elseif (-not $s.PrtValid) {
    $s.OverallHealth  = 'PRT_INVALID'
    $s.Recommendation = 'PRT is invalid. Have user sign out and back into Windows, or run: dsregcmd /refreshprt. Reset will likely fail silently without a valid PRT.'
} elseif (-not $s.SilentConfigPolicy) {
    $s.OverallHealth  = 'POLICY_MISSING'
    $s.Recommendation = 'SilentAccountConfig policy not deployed (HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\SilentAccountConfig = 1). Deploy via Intune before running Reset-OneDriveSync.ps1.'
} elseif (-not $s.OneDriveRunning -or -not $s.AccountConfigured) {
    $s.OverallHealth  = 'NOT_SYNCING'
    $s.Recommendation = 'Prerequisites look good. Run Reset-OneDriveSync.ps1 to restore sync silently.'
} else {
    $s.OverallHealth  = 'OK'
    $s.Recommendation = 'OneDrive appears configured and running. No remediation needed.'
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
Write-Output "===== OneDrive Sync Status ====="
Write-Output "Timestamp          : $($s.Timestamp)"
Write-Output "Computer           : $($s.ComputerName)"
Write-Output "User               : $($s.UserName)"
Write-Output "User Email         : $($s.UserEmail)"
Write-Output "OD Running         : $($s.OneDriveRunning)"
Write-Output "Account Configured : $($s.AccountConfigured)"
Write-Output "Sync Folder        : $($s.SyncFolder)"
Write-Output "OD Version         : $($s.OneDriveVersion)"
Write-Output "Log Last Written   : $($s.LogLastWritten)"
Write-Output "Sync Status        : $($s.SyncStatus)"
Write-Output "Error Code         : $($s.ErrorCode)"
Write-Output "Error Detail       : $($s.ErrorDescription)"
Write-Output "PRT Valid          : $($s.PrtValid)"
Write-Output "Azure AD Joined    : $($s.AzureAdJoined)"
Write-Output "Hybrid Joined      : $($s.HybridJoined)"
Write-Output "SilentAcctCfg Pol  : $($s.SilentConfigPolicy)"
Write-Output "Overall Health     : $($s.OverallHealth)"
Write-Output "Recommendation     : $($s.Recommendation)"
Write-Output "================================"

# ---------------------------------------------------------------------------
# Intune Detection Script exit codes
# Exit 0 = Compliant (no remediation needed)
# Exit 1 = Non-compliant (trigger remediation)
# ---------------------------------------------------------------------------
if ($s.OverallHealth -eq 'OK') {
    Write-Output "RESULT: Compliant"
    exit 0
}

Write-Output "RESULT: Non-compliant ($($s.OverallHealth)) — remediation needed"
exit 1
