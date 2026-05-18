#Requires -Version 5.1
<#
.SYNOPSIS
    Checks OneDrive for Business sync status on a device.

.DESCRIPTION
    Can run in two modes:

    USER MODE (default — Intune/SCCM remediation detection):
        Run as the signed-in user. No parameters needed.
        Reads HKCU and %LOCALAPPDATA% directly.
        Exit 0 = Compliant, Exit 1 = Non-compliant.

    MANAGEMENT MODE (-TargetUser specified, or auto-detected when running as admin):
        Run from a management/admin account on the same machine.
        Reads the target user's registry via HKU\<SID> and their profile path.
        Requires local admin rights on the target machine.
        PRT status cannot be verified from a different user context — reported
        as UNKNOWN. All other checks (registry, logs, process, device join) work fully.

.PARAMETER TargetUser
    Optional. The user to inspect when running from a management account.
    Accepts DOMAIN\username or just username.
    If omitted and the script is running as a different user than the console
    session, it auto-detects the interactively logged-in user.

.EXAMPLE
    # User mode — run as the affected user (Intune/SCCM):
    .\Get-OneDriveSyncStatus.ps1

.EXAMPLE
    # Management mode — explicit target:
    .\Get-OneDriveSyncStatus.ps1 -TargetUser "CONTOSO\jsmith"

.EXAMPLE
    # Management mode — auto-detect the logged-in user:
    .\Get-OneDriveSyncStatus.ps1 -TargetUser auto

.NOTES
    OverallHealth values:
        OK             - OneDrive running and account configured
        NOT_SYNCING    - Not running or not signed in; safe to remediate
        POLICY_MISSING - SilentAccountConfig not deployed; deploy before resetting
        PRT_UNKNOWN    - Running as management account; PRT must be verified separately
        PRT_INVALID    - PRT expired/missing (user mode only)
        DEVICE_ERROR   - Not Azure AD joined; cannot use silent sign-in
        BLOCKED        - CA or MFA policy blocking; fix policy before resetting
#>
param(
    [string]$TargetUser = ''
)

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
# Determine run mode and resolve target user context
# ---------------------------------------------------------------------------

# Get the interactively logged-in console user (works from any account)
$consoleUserRaw = (Get-WmiObject -Class Win32_ComputerSystem).UserName
# Returns DOMAIN\username or empty if no interactive session

$currentUser = $env:USERNAME
$managementMode = $false
$targetUsername = ''
$targetDomain   = ''
$targetSid      = ''
$targetProfile  = ''
$regBase        = 'HKCU:'
$localAppData   = $env:LOCALAPPDATA

if ($TargetUser -eq 'auto' -or ($TargetUser -eq '' -and $consoleUserRaw -and $consoleUserRaw -notmatch [regex]::Escape($currentUser))) {
    # Auto-detect: we are not the console user, switch to management mode
    $managementMode = $true
    $resolveFrom    = if ($TargetUser -eq 'auto' -or $TargetUser -eq '') { $consoleUserRaw } else { $TargetUser }
} elseif ($TargetUser -ne '' -and $TargetUser -ne 'auto') {
    # Explicit target specified
    $managementMode = $true
    $resolveFrom    = $TargetUser
}

if ($managementMode) {
    if ([string]::IsNullOrEmpty($resolveFrom)) {
        Write-Output "ERROR: Could not detect a logged-in console user. Specify -TargetUser explicitly."
        exit 1
    }

    # Parse DOMAIN\username
    if ($resolveFrom -match '\\') {
        $targetDomain   = $resolveFrom.Split('\')[0]
        $targetUsername = $resolveFrom.Split('\')[1]
    } else {
        $targetDomain   = $env:USERDOMAIN
        $targetUsername = $resolveFrom
    }

    # Resolve SID
    try {
        $ntAccount  = New-Object System.Security.Principal.NTAccount($targetDomain, $targetUsername)
        $targetSid  = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        # Try without domain prefix (local account or UPN format)
        try {
            $ntAccount  = New-Object System.Security.Principal.NTAccount($targetUsername)
            $targetSid  = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            Write-Output "ERROR: Cannot resolve SID for user '$resolveFrom'. Check the username and try again."
            exit 1
        }
    }

    # Resolve profile path from HKLM profile list
    $profileKey    = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$targetSid"
    $targetProfile = (Get-ItemProperty -Path $profileKey -ErrorAction SilentlyContinue).ProfileImagePath

    if (-not $targetProfile) {
        Write-Output "ERROR: Cannot find profile path for '$targetUsername' (SID: $targetSid)."
        Write-Output "       The user may not have a local profile on this machine."
        exit 1
    }

    # Verify the user's registry hive is loaded (requires them to be logged in)
    $hkuPath = "Registry::HKU\$targetSid"
    if (-not (Test-Path $hkuPath)) {
        Write-Output "ERROR: Registry hive for '$targetUsername' is not loaded."
        Write-Output "       The user must be actively logged in for management mode to read their registry."
        exit 1
    }

    $regBase      = $hkuPath
    $localAppData = "$targetProfile\AppData\Local"

    Write-Output "--- Management Mode: inspecting $targetDomain\$targetUsername (SID: $targetSid) ---"
    Write-Output "    Profile : $targetProfile"
    Write-Output ""
} else {
    $targetUsername = $currentUser
    $targetSid      = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $targetProfile  = $env:USERPROFILE
}

# ---------------------------------------------------------------------------
# Build status object
# ---------------------------------------------------------------------------
$s = [PSCustomObject]@{
    Timestamp          = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    ComputerName       = $env:COMPUTERNAME
    UserName           = $targetUsername
    ManagementMode     = $managementMode
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
    PrtVerified        = $true    # False when running in management mode
    AzureAdJoined      = $false
    HybridJoined       = $false
    SilentConfigPolicy = $false
    OverallHealth      = 'UNKNOWN'
    Recommendation     = ''
}

# ---------------------------------------------------------------------------
# 1. Process check
# WMI allows querying process owner from any account — works in both modes
# ---------------------------------------------------------------------------
$odProcs = Get-WmiObject -Class Win32_Process -Filter "Name='OneDrive.exe'" -ErrorAction SilentlyContinue
if ($odProcs) {
    $s.OneDriveRunning = [bool]($odProcs | Where-Object {
        $owner = $_.GetOwner()
        $owner.User -eq $targetUsername
    })
} else {
    $s.OneDriveRunning = $false
}

# ---------------------------------------------------------------------------
# 2. Registry — account configuration (via HKU\SID in management mode)
# ---------------------------------------------------------------------------
$acctRegPath = "$regBase\SOFTWARE\Microsoft\OneDrive\Accounts\Business1"
$acctReg     = Get-ItemProperty -Path $acctRegPath -ErrorAction SilentlyContinue
if ($acctReg) {
    $s.AccountConfigured = -not [string]::IsNullOrEmpty($acctReg.UserEmail)
    $s.UserEmail         = $acctReg.UserEmail
    $s.SyncFolder        = $acctReg.UserFolder
}

# ---------------------------------------------------------------------------
# 3. OneDrive version
# Per-user install lives in the user's LOCALAPPDATA; machine install in Program Files
# ---------------------------------------------------------------------------
foreach ($candidate in @(
    "$localAppData\Microsoft\OneDrive\OneDrive.exe",
    "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
    "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe"
)) {
    if (Test-Path $candidate) {
        $s.OneDriveVersion = (Get-Item $candidate).VersionInfo.FileVersion
        break
    }
}

# ---------------------------------------------------------------------------
# 4. SyncDiagnostics.log — sync status and error codes
# ---------------------------------------------------------------------------
$logFile = "$localAppData\Microsoft\OneDrive\logs\Business1\SyncDiagnostics.log"
if (Test-Path $logFile) {
    $logItem          = Get-Item $logFile
    $s.LogLastWritten = $logItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')

    $logContent = Get-Content -Path $logFile -ErrorAction SilentlyContinue
    if ($logContent) {
        $tail = if ($logContent.Count -gt 300) { $logContent[-300..-1] } else { $logContent }
        foreach ($line in $tail) {
            if ($line -match 'Sync\s*Status\s*[:\|]\s*(.+)') {
                $s.SyncStatus = $matches[1].Trim()
            }
            if ($line -match '(0x[0-9A-Fa-f]{8})') { $s.ErrorCode = $matches[1] }
            if ($line -match '(AADSTS\d{5,6})')     { $s.ErrorCode = $matches[1] }
        }
    }
}

# Infer status if log did not provide one
if ($s.SyncStatus -eq 'Unknown') {
    if (-not $s.OneDriveRunning)       { $s.SyncStatus = 'Not Running' }
    elseif (-not $s.AccountConfigured) { $s.SyncStatus = 'Not Signed In' }
    else                               { $s.SyncStatus = 'Running — status undetermined from logs' }
}

# Resolve error description
if ($s.ErrorCode) {
    $s.ErrorDescription = if ($ErrorDescriptions.ContainsKey($s.ErrorCode)) {
        $ErrorDescriptions[$s.ErrorCode]
    } else {
        "Unknown error — search docs.microsoft.com for $($s.ErrorCode)"
    }
}

# ---------------------------------------------------------------------------
# 5. Azure AD / PRT status via dsregcmd
#
# Device join info (AzureAdJoined, DomainJoined) is machine-wide — accurate
# from any account context.
#
# PRT (AzureAdPrt) is per-user. dsregcmd run from a management account shows
# the management account's PRT, not the target user's. In management mode we
# mark PrtVerified = false and skip the PRT health check.
# To verify PRT manually: log on as the user and run: dsregcmd /status
# ---------------------------------------------------------------------------
$dsreg = & dsregcmd.exe /status 2>&1
if ($dsreg) {
    $s.AzureAdJoined = [bool]($dsreg | Select-String 'AzureAdJoined\s*:\s*YES' -Quiet)
    $s.HybridJoined  = [bool]($dsreg | Select-String 'DomainJoined\s*:\s*YES'  -Quiet) -and $s.AzureAdJoined

    if (-not $managementMode) {
        $s.PrtValid    = [bool]($dsreg | Select-String 'AzureAdPrt\s*:\s*YES' -Quiet)
        $s.PrtVerified = $true
    } else {
        $s.PrtValid    = $false
        $s.PrtVerified = $false   # Cannot verify from management account
    }
}

# ---------------------------------------------------------------------------
# 6. SilentAccountConfig policy (HKLM — machine-wide, accurate from any context)
# ---------------------------------------------------------------------------
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
} elseif (-not $s.PrtVerified) {
    # Management mode — PRT cannot be checked; report everything else and flag for manual PRT check
    if (-not $s.SilentConfigPolicy) {
        $s.OverallHealth  = 'POLICY_MISSING'
        $s.Recommendation = 'SilentAccountConfig policy not deployed. Deploy via Intune before running Reset-OneDriveSync.ps1. Also verify PRT manually: run dsregcmd /status as the user.'
    } elseif (-not $s.OneDriveRunning -or -not $s.AccountConfigured) {
        $s.OverallHealth  = 'NOT_SYNCING'
        $s.Recommendation = 'OneDrive not running or not signed in. Safe to remediate. NOTE: PRT not verified from management account — confirm with dsregcmd /status as the user before deploying at scale.'
    } else {
        $s.OverallHealth  = 'PRT_UNKNOWN'
        $s.Recommendation = 'OneDrive appears running. PRT cannot be verified from a management account. Run dsregcmd /status as the target user to confirm (AzureAdPrt : YES).'
    }
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
Write-Output "Management Mode    : $($s.ManagementMode)"
Write-Output "OD Running         : $($s.OneDriveRunning)"
Write-Output "Account Configured : $($s.AccountConfigured)"
Write-Output "User Email         : $($s.UserEmail)"
Write-Output "Sync Folder        : $($s.SyncFolder)"
Write-Output "OD Version         : $($s.OneDriveVersion)"
Write-Output "Log Last Written   : $($s.LogLastWritten)"
Write-Output "Sync Status        : $($s.SyncStatus)"
Write-Output "Error Code         : $($s.ErrorCode)"
Write-Output "Error Detail       : $($s.ErrorDescription)"
Write-Output "Azure AD Joined    : $($s.AzureAdJoined)"
Write-Output "Hybrid Joined      : $($s.HybridJoined)"
Write-Output "PRT Valid          : $(if ($s.PrtVerified) { $s.PrtValid } else { 'UNKNOWN (management mode — verify manually)' })"
Write-Output "SilentAcctCfg Pol  : $($s.SilentConfigPolicy)"
Write-Output "Overall Health     : $($s.OverallHealth)"
Write-Output "Recommendation     : $($s.Recommendation)"
Write-Output "================================"

# ---------------------------------------------------------------------------
# Exit codes (Intune Detection Script / standalone)
# Exit 0 = Compliant / healthy
# Exit 1 = Non-compliant / needs attention
# ---------------------------------------------------------------------------
if ($s.OverallHealth -eq 'OK') {
    Write-Output "RESULT: Compliant"
    exit 0
}

Write-Output "RESULT: Non-compliant ($($s.OverallHealth)) — remediation needed"
exit 1
