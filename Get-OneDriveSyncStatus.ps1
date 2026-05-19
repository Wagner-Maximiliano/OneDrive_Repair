#Requires -Version 5.1
<#
.SYNOPSIS
    Checks OneDrive for Business sync status on a remote device.
    Designed to run from an admin / SCCM context — never as the target user.

.DESCRIPTION
    Always runs as an administrator. Automatically resolves the interactively
    logged-in user by inspecting the explorer.exe process owner, then reads
    that user's data via HKU\<SID> and their profile path.

    No HKCU access is used. No user context switching is required.

    PRT NOTICE:
        The Primary Refresh Token lives in the user's WAM memory and cannot
        be read from an admin/SCCM context. PRT is excluded from the overall
        health assessment. It is your responsibility to verify PRT health
        separately (e.g. ask the user to run: dsregcmd /status).

    SYNC STATUS ACCURACY:
        SyncDiagnostics.log can report "Synced" even when OneDrive has been
        disconnected for months. "Synced" only means no local pending changes
        — it does not mean the client has spoken to the cloud recently.

        This script uses two reliable activity signals instead:
          - SyncEngine*.log last write time  — written only when syncing
          - *.odl file last write time       — updated by any cloud contact
        If both are older than -InactivityThresholdDays (default 14), the
        device is flagged NOT_SYNCING regardless of the log status string.

.PARAMETER TargetUser
    Optional. Override the auto-detected user.
    Accepts DOMAIN\username or just username.
    Use when multiple users are logged in and you need a specific one.

.PARAMETER InactivityThresholdDays
    Days of silence before the device is flagged NOT_SYNCING. Default: 14.

.EXAMPLE
    # Auto-detect the logged-in user (typical SCCM deployment):
    .\Get-OneDriveSyncStatus.ps1

.EXAMPLE
    # Target a specific user when multiple sessions exist:
    .\Get-OneDriveSyncStatus.ps1 -TargetUser "CONTOSO\jsmith"

.EXAMPLE
    # Tighter threshold for the March 2026 outage investigation:
    .\Get-OneDriveSyncStatus.ps1 -InactivityThresholdDays 3

.NOTES
    OverallHealth values:
        OK             - OneDrive running, signed in, recently active
        NOT_SYNCING    - Not running, not signed in, or inactive > threshold
        STALE          - Log says Synced but no real activity for > threshold days
        POLICY_MISSING - SilentAccountConfig not deployed (HKLM)
        DEVICE_ERROR   - Device not Azure AD joined
        BLOCKED        - CA or MFA policy blocking sign-in (error code found in logs)
        NO_USER        - No interactive user detected on this machine
        ERROR          - Script could not resolve user / profile
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
# Resolve the target user
#
# Priority:
#   1. -TargetUser parameter (explicit override)
#   2. Owner of explorer.exe (most reliable — always the desktop user)
#   3. Win32_ComputerSystem.UserName (fallback)
# ---------------------------------------------------------------------------
$resolvedDomain   = ''
$resolvedUsername = ''
$detectionMethod  = ''

if ($TargetUser -ne '') {
    # Explicit override
    if ($TargetUser -match '\\') {
        $resolvedDomain   = $TargetUser.Split('\')[0]
        $resolvedUsername = $TargetUser.Split('\')[1]
    } else {
        $resolvedDomain   = $env:USERDOMAIN
        $resolvedUsername = $TargetUser
    }
    $detectionMethod = 'Parameter'
}

if (-not $resolvedUsername) {
    # explorer.exe process owner — the user running the desktop shell
    # Multiple explorer instances can exist (one per logged-in user); pick the
    # first non-SYSTEM, non-service account one.
    $explorerProcs = Get-WmiObject -Class Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue
    foreach ($proc in $explorerProcs) {
        $owner = $proc.GetOwner()
        if ($owner.User -and $owner.Domain -ne 'NT AUTHORITY' -and $owner.Domain -ne 'Window Manager') {
            $resolvedDomain   = $owner.Domain
            $resolvedUsername = $owner.User
            $detectionMethod  = 'Explorer process owner'
            break
        }
    }
}

if (-not $resolvedUsername) {
    # Fallback: Win32_ComputerSystem.UserName
    $csUser = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
    if ($csUser -and $csUser -match '\\') {
        $resolvedDomain   = $csUser.Split('\')[0]
        $resolvedUsername = $csUser.Split('\')[1]
        $detectionMethod  = 'Win32_ComputerSystem'
    }
}

if (-not $resolvedUsername) {
    Write-Output "===== OneDrive Sync Status ====="
    Write-Output "Computer      : $env:COMPUTERNAME"
    Write-Output "Overall Health: NO_USER"
    Write-Output "Recommendation: No interactive user detected on this machine. Nothing to check."
    Write-Output "================================"
    Write-Output "RESULT: Non-compliant (NO_USER)"
    exit 1
}

# ---------------------------------------------------------------------------
# Resolve SID and profile path
# ---------------------------------------------------------------------------
$targetSid     = ''
$targetProfile = ''

try {
    $ntAccount = New-Object System.Security.Principal.NTAccount($resolvedDomain, $resolvedUsername)
    $targetSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
} catch {
    # Domain prefix failed — try bare username (local account or cached UPN)
    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($resolvedUsername)
        $targetSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        Write-Output "===== OneDrive Sync Status ====="
        Write-Output "Computer      : $env:COMPUTERNAME"
        Write-Output "User          : $resolvedDomain\$resolvedUsername"
        Write-Output "Overall Health: ERROR"
        Write-Output "Recommendation: Cannot resolve SID for detected user. Check domain connectivity."
        Write-Output "================================"
        Write-Output "RESULT: Non-compliant (ERROR)"
        exit 1
    }
}

# Profile path from HKLM profile list (works without the user being logged in)
$targetProfile = (Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$targetSid" `
    -ErrorAction SilentlyContinue).ProfileImagePath

if (-not $targetProfile) {
    Write-Output "===== OneDrive Sync Status ====="
    Write-Output "Computer      : $env:COMPUTERNAME"
    Write-Output "User          : $resolvedDomain\$resolvedUsername (SID: $targetSid)"
    Write-Output "Overall Health: ERROR"
    Write-Output "Recommendation: Profile path not found for this user on this machine."
    Write-Output "================================"
    Write-Output "RESULT: Non-compliant (ERROR)"
    exit 1
}

# Verify hive is loaded — user must be logged in for registry reads
$hkuPath = "Registry::HKU\$targetSid"
if (-not (Test-Path $hkuPath)) {
    Write-Output "===== OneDrive Sync Status ====="
    Write-Output "Computer      : $env:COMPUTERNAME"
    Write-Output "User          : $resolvedDomain\$resolvedUsername (SID: $targetSid)"
    Write-Output "Overall Health: ERROR"
    Write-Output "Recommendation: User registry hive is not loaded. User must be actively logged in."
    Write-Output "================================"
    Write-Output "RESULT: Non-compliant (ERROR)"
    exit 1
}

$localAppData = "$targetProfile\AppData\Local"
$logsBase     = "$localAppData\Microsoft\OneDrive\logs\Business1"

# ---------------------------------------------------------------------------
# Build status object
# ---------------------------------------------------------------------------
$s = [PSCustomObject]@{
    Timestamp              = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    ComputerName           = $env:COMPUTERNAME
    UserName               = "$resolvedDomain\$resolvedUsername"
    UserDetectionMethod    = $detectionMethod
    UserSID                = $targetSid
    OneDriveRunning        = $false
    AccountConfigured      = $false
    UserEmail              = ''
    SyncFolder             = ''
    OneDriveVersion        = ''
    SyncEngineLastActivity = ''
    ODLLastActivity        = ''
    LastKnownActivity      = ''
    DaysSinceActivity      = -1
    LastSyncAttemptInLog   = ''
    SyncStatusFromLog      = ''
    SyncStatus             = ''
    ErrorCode              = ''
    ErrorDescription       = ''
    AzureAdJoined          = $false
    HybridJoined           = $false
    SilentConfigPolicy     = $false
    OverallHealth          = 'UNKNOWN'
    Recommendation         = ''
}

# ---------------------------------------------------------------------------
# 1. Process check — WMI with owner filter (accurate from admin context)
# ---------------------------------------------------------------------------
$odProcs = Get-WmiObject -Class Win32_Process -Filter "Name='OneDrive.exe'" -ErrorAction SilentlyContinue
if ($odProcs) {
    $s.OneDriveRunning = [bool]($odProcs | Where-Object {
        $o = $_.GetOwner()
        $o.User -eq $resolvedUsername
    })
}

# ---------------------------------------------------------------------------
# 2. Registry — account configuration via HKU\<SID>
# ---------------------------------------------------------------------------
$acctReg = Get-ItemProperty -Path "$hkuPath\SOFTWARE\Microsoft\OneDrive\Accounts\Business1" -ErrorAction SilentlyContinue
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
# 4. Activity signals
#
# SyncDiagnostics.log "Synced" = no local pending changes, NOT cloud connected.
# These two signals can only be non-zero if OneDrive is actually doing work:
#   SyncEngine*.log — written continuously while the sync engine is running
#   *.odl files     — updated by any cloud API call from the OD client
# ---------------------------------------------------------------------------

# SyncEngine log recency
$syncEngineLogs = Get-ChildItem -Path $logsBase -Filter 'SyncEngine*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending
if ($syncEngineLogs) {
    $s.SyncEngineLastActivity = $syncEngineLogs[0].LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
}

# ODL file recency
$odlFiles = Get-ChildItem -Path "$localAppData\Microsoft\OneDrive\logs" -Filter '*.odl' -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending
if ($odlFiles) {
    $s.ODLLastActivity = $odlFiles[0].LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
}

# Most recent activity across both signals
$activityDates = @()
if ($s.SyncEngineLastActivity) { $activityDates += [datetime]::Parse($s.SyncEngineLastActivity) }
if ($s.ODLLastActivity)        { $activityDates += [datetime]::Parse($s.ODLLastActivity) }

if ($activityDates) {
    $mostRecent          = ($activityDates | Sort-Object -Descending)[0]
    $s.LastKnownActivity = $mostRecent.ToString('yyyy-MM-dd HH:mm:ss')
    $s.DaysSinceActivity = [int]([datetime]::Now - $mostRecent).TotalDays
}

# Parse SyncDiagnostics.log for status string and any embedded timestamps
$diagLog = "$logsBase\SyncDiagnostics.log"
if (Test-Path $diagLog) {
    $diagContent = Get-Content -Path $diagLog -ErrorAction SilentlyContinue
    if ($diagContent) {
        $tail = if ($diagContent.Count -gt 400) { $diagContent[-400..-1] } else { $diagContent }
        foreach ($line in $tail) {
            if ($line -match 'Sync\s*Status\s*[:\|]\s*(.+)') {
                $s.SyncStatusFromLog = $matches[1].Trim()
            }
            if ($line -match '(?:LastSyncAttempt|LastSuccessfulSync|Last Sync Time|LastSyncTime)\s*[:\|=]\s*(.+)') {
                $s.LastSyncAttemptInLog = $matches[1].Trim()
            }
            if ($line -match '(0x[0-9A-Fa-f]{8})') { $s.ErrorCode = $matches[1] }
            if ($line -match '(AADSTS\d{5,6})')     { $s.ErrorCode = $matches[1] }
        }
    }
}

# Resolve final sync status — activity signals override the log status string
$isStale = $s.DaysSinceActivity -ge 0 -and $s.DaysSinceActivity -gt $InactivityThresholdDays
if ($isStale) {
    $s.SyncStatus = "No sync activity for $($s.DaysSinceActivity) days (log reports: '$($s.SyncStatusFromLog)')"
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
        "Unknown — search docs.microsoft.com for $($s.ErrorCode)"
    }
}

# ---------------------------------------------------------------------------
# 5. Device join status via dsregcmd
# Device-level fields (AzureAdJoined, DomainJoined) are machine-wide and
# accurate from any account. PRT is per-user and cannot be read here —
# it is excluded from the health assessment entirely.
# ---------------------------------------------------------------------------
$dsreg = & dsregcmd.exe /status 2>&1
if ($dsreg) {
    $s.AzureAdJoined = [bool]($dsreg | Select-String 'AzureAdJoined\s*:\s*YES' -Quiet)
    $s.HybridJoined  = [bool]($dsreg | Select-String 'DomainJoined\s*:\s*YES'  -Quiet) -and $s.AzureAdJoined
}

# ---------------------------------------------------------------------------
# 6. SilentAccountConfig policy (HKLM — machine-wide)
# ---------------------------------------------------------------------------
$silentPol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' `
                -Name 'SilentAccountConfig' -ErrorAction SilentlyContinue
$s.SilentConfigPolicy = ($silentPol -ne $null -and $silentPol.SilentAccountConfig -eq 1)

# ---------------------------------------------------------------------------
# Overall health — PRT is NOT included; cannot be verified from admin context
# ---------------------------------------------------------------------------
$caBlocked = $s.ErrorCode -match '0x8004de86|AADSTS53003|AADSTS50072|AADSTS50076'

if ($caBlocked) {
    $s.OverallHealth  = 'BLOCKED'
    $s.Recommendation = "CA or MFA policy is blocking sign-in ($($s.ErrorCode): $($s.ErrorDescription)). Fix the policy before running reset — reset will not help."

} elseif (-not $s.AzureAdJoined) {
    $s.OverallHealth  = 'DEVICE_ERROR'
    $s.Recommendation = 'Device is not Azure AD joined. Re-register in Entra ID (dsregcmd /join). Silent sign-in cannot work until resolved.'

} elseif (-not $s.SilentConfigPolicy) {
    $s.OverallHealth  = 'POLICY_MISSING'
    $s.Recommendation = 'SilentAccountConfig policy not deployed (HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\SilentAccountConfig = 1). Deploy via Intune/GPO before running Reset-OneDriveSync.ps1.'

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
Write-Output "User Detected Via        : $($s.UserDetectionMethod)"
Write-Output "User SID                 : $($s.UserSID)"
Write-Output "--- Account ---"
Write-Output "OD Running               : $($s.OneDriveRunning)"
Write-Output "Account Configured       : $($s.AccountConfigured)"
Write-Output "User Email               : $($s.UserEmail)"
Write-Output "Sync Folder              : $($s.SyncFolder)"
Write-Output "OD Version               : $($s.OneDriveVersion)"
Write-Output "--- Activity ---"
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
Write-Output "SilentAcctCfg Policy     : $($s.SilentConfigPolicy)"
Write-Output "PRT                      : Not assessed (admin context — verify manually: dsregcmd /status as user)"
Write-Output "--- Conclusion ---"
Write-Output "Overall Health           : $($s.OverallHealth)"
Write-Output "Recommendation           : $($s.Recommendation)"
Write-Output "================================"

if ($s.OverallHealth -eq 'OK') {
    Write-Output "RESULT: Compliant"
    exit 0
}

Write-Output "RESULT: Non-compliant ($($s.OverallHealth)) — remediation needed"
exit 1
