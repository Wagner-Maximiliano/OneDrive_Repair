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
        as UNKNOWN. All other checks work fully.

    WHAT IS CHECKED:
        The script uses multiple signals to determine real sync activity,
        not just what the SyncDiagnostics.log status line says.

        SyncDiagnostics.log can show "Synced" even when OneDrive has been
        disconnected for months — it only means "no local pending changes",
        not "successfully connected to the cloud recently."

        More reliable signals used by this script:
          - SyncEngine log last write time  (most reliable activity indicator)
          - ODL log file last write time    (secondary activity indicator)
          - LastSyncAttempt / LastSuccessfulSync timestamps parsed from logs
          - DaysSinceActivity computed from the above

        If DaysSinceActivity exceeds -InactivityThresholdDays (default: 14),
        the device is flagged as STALE regardless of the SyncDiagnostics status.

.PARAMETER TargetUser
    Optional. User to inspect when running from a management account.
    Accepts DOMAIN\username or just username.
    Use 'auto' to auto-detect the interactively logged-in console user.

.PARAMETER InactivityThresholdDays
    Days of no sync engine activity before the device is flagged as STALE.
    Default: 14. Lower this if you want to catch shorter gaps.

.EXAMPLE
    # User mode (Intune / SCCM):
    .\Get-OneDriveSyncStatus.ps1

.EXAMPLE
    # Management mode — explicit target:
    .\Get-OneDriveSyncStatus.ps1 -TargetUser "CONTOSO\jsmith"

.EXAMPLE
    # Management mode — auto-detect console user:
    .\Get-OneDriveSyncStatus.ps1 -TargetUser auto

.EXAMPLE
    # Tighter threshold — flag anything inactive for more than 3 days:
    .\Get-OneDriveSyncStatus.ps1 -TargetUser "CONTOSO\jsmith" -InactivityThresholdDays 3

.NOTES
    OverallHealth values:
        OK             - OneDrive running, signed in, and recently active
        STALE          - Logs show "Synced" but no real activity for X days
        NOT_SYNCING    - Not running or account not configured
        POLICY_MISSING - SilentAccountConfig not deployed
        PRT_UNKNOWN    - Management mode; PRT must be verified manually
        PRT_INVALID    - PRT expired/missing (user mode only)
        DEVICE_ERROR   - Not Azure AD joined
        BLOCKED        - CA or MFA policy blocking sign-in
#>
param(
    [string]$TargetUser              = '',
    [int]   $InactivityThresholdDays = 14
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
$consoleUserRaw = (Get-WmiObject -Class Win32_ComputerSystem).UserName
$currentUser    = $env:USERNAME
$managementMode = $false
$targetUsername = ''
$targetDomain   = ''
$targetSid      = ''
$targetProfile  = ''
$regBase        = 'HKCU:'
$localAppData   = $env:LOCALAPPDATA

if ($TargetUser -eq 'auto' -or ($TargetUser -eq '' -and $consoleUserRaw -and $consoleUserRaw -notmatch [regex]::Escape($currentUser))) {
    $managementMode = $true
    $resolveFrom    = if ($TargetUser -eq 'auto' -or $TargetUser -eq '') { $consoleUserRaw } else { $TargetUser }
} elseif ($TargetUser -ne '' -and $TargetUser -ne 'auto') {
    $managementMode = $true
    $resolveFrom    = $TargetUser
}

if ($managementMode) {
    if ([string]::IsNullOrEmpty($resolveFrom)) {
        Write-Output "ERROR: Could not detect a logged-in console user. Specify -TargetUser explicitly."
        exit 1
    }

    if ($resolveFrom -match '\\') {
        $targetDomain   = $resolveFrom.Split('\')[0]
        $targetUsername = $resolveFrom.Split('\')[1]
    } else {
        $targetDomain   = $env:USERDOMAIN
        $targetUsername = $resolveFrom
    }

    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($targetDomain, $targetUsername)
        $targetSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        try {
            $ntAccount = New-Object System.Security.Principal.NTAccount($targetUsername)
            $targetSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            Write-Output "ERROR: Cannot resolve SID for user '$resolveFrom'. Check the username and try again."
            exit 1
        }
    }

    $profileKey    = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$targetSid"
    $targetProfile = (Get-ItemProperty -Path $profileKey -ErrorAction SilentlyContinue).ProfileImagePath
    if (-not $targetProfile) {
        Write-Output "ERROR: Cannot find profile path for '$targetUsername' (SID: $targetSid)."
        exit 1
    }

    $hkuPath = "Registry::HKU\$targetSid"
    if (-not (Test-Path $hkuPath)) {
        Write-Output "ERROR: Registry hive for '$targetUsername' is not loaded. User must be logged in."
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
    Timestamp                = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    ComputerName             = $env:COMPUTERNAME
    UserName                 = $targetUsername
    ManagementMode           = $managementMode
    OneDriveRunning          = $false
    AccountConfigured        = $false
    UserEmail                = ''
    SyncFolder               = ''
    OneDriveVersion          = ''
    # --- Activity signals ---
    SyncEngineLastActivity   = ''   # Last write of SyncEngine*.log files
    ODLLastActivity          = ''   # Last write of *.odl files
    LastKnownActivity        = ''   # Most recent of the above two
    DaysSinceActivity        = -1   # Integer days since LastKnownActivity
    LastSyncAttemptInLog     = ''   # Parsed from SyncDiagnostics.log if present
    # --- Status from logs ---
    SyncStatusFromLog        = ''   # Raw status string from SyncDiagnostics.log
    SyncStatus               = ''   # Final resolved status (may override log value)
    ErrorCode                = ''
    ErrorDescription         = ''
    # --- Device / policy ---
    PrtValid                 = $false
    PrtVerified              = $true
    AzureAdJoined            = $false
    HybridJoined             = $false
    SilentConfigPolicy       = $false
    # --- Conclusion ---
    OverallHealth            = 'UNKNOWN'
    Recommendation           = ''
}

$logsBase = "$localAppData\Microsoft\OneDrive\logs\Business1"

# ---------------------------------------------------------------------------
# 1. Process check (WMI — works from any account)
# ---------------------------------------------------------------------------
$odProcs = Get-WmiObject -Class Win32_Process -Filter "Name='OneDrive.exe'" -ErrorAction SilentlyContinue
if ($odProcs) {
    $s.OneDriveRunning = [bool]($odProcs | Where-Object {
        $owner = $_.GetOwner()
        $owner.User -eq $targetUsername
    })
}

# ---------------------------------------------------------------------------
# 2. Registry — account configuration
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
# 4. Activity signals — the reliable indicators of real sync activity
#
# SyncDiagnostics.log "Status: Synced" only means no local pending changes.
# It does NOT mean OneDrive successfully connected to the cloud recently.
# A disconnected OneDrive can show Synced indefinitely if the user has no
# local file changes.
#
# The signals below cannot be faked by cached state:
#   - SyncEngine*.log files are written only when the sync engine is active
#   - *.odl files are updated by any cloud communication from the client
#   - Parsed LastSyncAttempt timestamp from SyncDiagnostics content
# ---------------------------------------------------------------------------

# -- 4a. SyncEngine log recency --
$syncEngineLogs = Get-ChildItem -Path $logsBase -Filter 'SyncEngine*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending

if ($syncEngineLogs) {
    $s.SyncEngineLastActivity = $syncEngineLogs[0].LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
}

# -- 4b. ODL file recency (OneDrive binary activity logs) --
$odlFiles = Get-ChildItem -Path "$localAppData\Microsoft\OneDrive\logs" -Filter '*.odl' -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending

if ($odlFiles) {
    $s.ODLLastActivity = $odlFiles[0].LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
}

# -- 4c. Derive LastKnownActivity and DaysSinceActivity --
$activityCandidates = @()
if ($s.SyncEngineLastActivity) { $activityCandidates += [datetime]::Parse($s.SyncEngineLastActivity) }
if ($s.ODLLastActivity)        { $activityCandidates += [datetime]::Parse($s.ODLLastActivity) }

if ($activityCandidates) {
    $mostRecent              = ($activityCandidates | Sort-Object -Descending)[0]
    $s.LastKnownActivity     = $mostRecent.ToString('yyyy-MM-dd HH:mm:ss')
    $s.DaysSinceActivity     = [int]([datetime]::Now - $mostRecent).TotalDays
}

# -- 4d. Parse SyncDiagnostics.log for status string and last-sync timestamp --
$diagLog = "$logsBase\SyncDiagnostics.log"
if (Test-Path $diagLog) {
    $diagContent = Get-Content -Path $diagLog -ErrorAction SilentlyContinue
    if ($diagContent) {
        $tail = if ($diagContent.Count -gt 400) { $diagContent[-400..-1] } else { $diagContent }

        foreach ($line in $tail) {
            # Sync status string
            if ($line -match 'Sync\s*Status\s*[:\|]\s*(.+)') {
                $s.SyncStatusFromLog = $matches[1].Trim()
            }

            # Last sync / last attempt timestamps (various formats across OD versions)
            if ($line -match '(?:LastSyncAttempt|LastSuccessfulSync|Last Sync Time|LastSyncTime)\s*[:\|=]\s*(.+)') {
                $s.LastSyncAttemptInLog = $matches[1].Trim()
            }

            # Hex error codes
            if ($line -match '(0x[0-9A-Fa-f]{8})') { $s.ErrorCode = $matches[1] }

            # AADSTS error codes
            if ($line -match '(AADSTS\d{5,6})') { $s.ErrorCode = $matches[1] }
        }
    }
}

# -- 4e. Resolve final SyncStatus --
# Override the log's "Synced" claim if activity signals say otherwise
if ($s.DaysSinceActivity -ge 0 -and $s.DaysSinceActivity -gt $InactivityThresholdDays) {
    $s.SyncStatus = "STALE — No sync engine activity for $($s.DaysSinceActivity) days (log reports: '$($s.SyncStatusFromLog)')"
} elseif ($s.SyncStatusFromLog) {
    $s.SyncStatus = $s.SyncStatusFromLog
} elseif (-not $s.OneDriveRunning) {
    $s.SyncStatus = 'Not Running'
} elseif (-not $s.AccountConfigured) {
    $s.SyncStatus = 'Not Signed In'
} else {
    $s.SyncStatus = 'Unknown — no log data found'
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
# Device join info is machine-wide (accurate from any account).
# PRT is per-user — cannot be read from a management account.
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
        $s.PrtVerified = $false
    }
}

# ---------------------------------------------------------------------------
# 6. SilentAccountConfig policy (HKLM — machine-wide, accurate from any context)
# ---------------------------------------------------------------------------
$silentPol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' `
                -Name 'SilentAccountConfig' -ErrorAction SilentlyContinue
$s.SilentConfigPolicy = ($silentPol -ne $null -and $silentPol.SilentAccountConfig -eq 1)

# ---------------------------------------------------------------------------
# Determine overall health
# ---------------------------------------------------------------------------
$caBlocked  = $s.ErrorCode -match '0x8004de86|AADSTS53003|AADSTS50072|AADSTS50076'
$isStale    = $s.DaysSinceActivity -ge 0 -and $s.DaysSinceActivity -gt $InactivityThresholdDays

if ($caBlocked) {
    $s.OverallHealth  = 'BLOCKED'
    $s.Recommendation = "CA or MFA policy is blocking sign-in ($($s.ErrorCode): $($s.ErrorDescription)). Fix the policy before running reset — reset will not help."

} elseif (-not $s.AzureAdJoined) {
    $s.OverallHealth  = 'DEVICE_ERROR'
    $s.Recommendation = 'Device is not Azure AD joined. Re-register in Entra ID (dsregcmd /join). Silent sign-in cannot work until resolved.'

} elseif (-not $s.PrtVerified) {
    # Management mode — cannot check PRT
    if (-not $s.SilentConfigPolicy) {
        $s.OverallHealth  = 'POLICY_MISSING'
        $s.Recommendation = 'SilentAccountConfig policy not deployed. Deploy via Intune before resetting. Also verify PRT manually: run dsregcmd /status as the user.'
    } elseif (-not $s.OneDriveRunning -or -not $s.AccountConfigured -or $isStale) {
        $s.OverallHealth  = 'NOT_SYNCING'
        $s.Recommendation = "OneDrive not active ($($s.DaysSinceActivity) days since last activity). Safe to remediate. NOTE: PRT not verified — confirm with dsregcmd /status as the user before deploying at scale."
    } else {
        $s.OverallHealth  = 'PRT_UNKNOWN'
        $s.Recommendation = 'OneDrive appears recently active. PRT cannot be verified from a management account. Run dsregcmd /status as the target user to confirm (AzureAdPrt : YES).'
    }

} elseif (-not $s.PrtValid) {
    $s.OverallHealth  = 'PRT_INVALID'
    $s.Recommendation = 'PRT is invalid. Have user sign out and back into Windows, or run: dsregcmd /refreshprt. Reset will likely fail silently without a valid PRT.'

} elseif (-not $s.SilentConfigPolicy) {
    $s.OverallHealth  = 'POLICY_MISSING'
    $s.Recommendation = 'SilentAccountConfig policy not deployed (HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\SilentAccountConfig = 1). Deploy via Intune before running Reset-OneDriveSync.ps1.'

} elseif (-not $s.OneDriveRunning -or -not $s.AccountConfigured -or $isStale) {
    $s.OverallHealth  = 'NOT_SYNCING'
    $s.Recommendation = "OneDrive not active ($($s.DaysSinceActivity) days since last sync engine activity). Run Reset-OneDriveSync.ps1 to restore sync."

} else {
    $s.OverallHealth  = 'OK'
    $s.Recommendation = "OneDrive active $($s.DaysSinceActivity) day(s) ago. No remediation needed."
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
Write-Output "===== OneDrive Sync Status ====="
Write-Output "Timestamp                : $($s.Timestamp)"
Write-Output "Computer                 : $($s.ComputerName)"
Write-Output "User                     : $($s.UserName)"
Write-Output "Management Mode          : $($s.ManagementMode)"
Write-Output "--- Account ---"
Write-Output "OD Running               : $($s.OneDriveRunning)"
Write-Output "Account Configured       : $($s.AccountConfigured)"
Write-Output "User Email               : $($s.UserEmail)"
Write-Output "Sync Folder              : $($s.SyncFolder)"
Write-Output "OD Version               : $($s.OneDriveVersion)"
Write-Output "--- Activity (reliable signals) ---"
Write-Output "SyncEngine Last Activity : $($s.SyncEngineLastActivity)"
Write-Output "ODL Last Activity        : $($s.ODLLastActivity)"
Write-Output "Last Known Activity      : $($s.LastKnownActivity)"
Write-Output "Days Since Activity      : $(if ($s.DaysSinceActivity -ge 0) { $s.DaysSinceActivity } else { 'No log files found' })"
Write-Output "Last Sync Attempt (log)  : $($s.LastSyncAttemptInLog)"
Write-Output "Inactivity Threshold     : $InactivityThresholdDays days"
Write-Output "--- Status ---"
Write-Output "Sync Status (log)        : $($s.SyncStatusFromLog)"
Write-Output "Sync Status (resolved)   : $($s.SyncStatus)"
Write-Output "Error Code               : $($s.ErrorCode)"
Write-Output "Error Detail             : $($s.ErrorDescription)"
Write-Output "--- Device ---"
Write-Output "Azure AD Joined          : $($s.AzureAdJoined)"
Write-Output "Hybrid Joined            : $($s.HybridJoined)"
Write-Output "PRT Valid                : $(if ($s.PrtVerified) { $s.PrtValid } else { 'UNKNOWN (management mode — run dsregcmd /status as the user)' })"
Write-Output "SilentAcctCfg Policy     : $($s.SilentConfigPolicy)"
Write-Output "--- Conclusion ---"
Write-Output "Overall Health           : $($s.OverallHealth)"
Write-Output "Recommendation           : $($s.Recommendation)"
Write-Output "================================"

# Exit codes for Intune Detection Script
if ($s.OverallHealth -eq 'OK') {
    Write-Output "RESULT: Compliant"
    exit 0
}

Write-Output "RESULT: Non-compliant ($($s.OverallHealth)) — remediation needed"
exit 1
