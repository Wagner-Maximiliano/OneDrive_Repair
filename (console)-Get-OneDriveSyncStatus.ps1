# ==============================================================================
# OneDrive Sync Status — Console Paste Version
# Paste this entire file into a PowerShell console window.
# PowerShell will buffer the input until the final closing } and then execute.
#
# CONFIGURATION: Edit the two variables in the block below before pasting.
# ==============================================================================

& {

# ── Configuration ─────────────────────────────────────────────────────────────
$TargetUser              = ''   # Leave blank to auto-detect the logged-in user
                                # Or set to 'DOMAIN\username' for a specific user
$InactivityThresholdDays = 14   # Days of no sync activity before flagging NOT_SYNCING
# ──────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = 'SilentlyContinue'

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

# ------------------------------------------------------------------------------
# Resolve the logged-in user
# 1. $TargetUser variable above (if set)
# 2. Owner of explorer.exe  (most reliable — always the desktop user)
# 3. Win32_ComputerSystem.UserName (fallback)
# ------------------------------------------------------------------------------
$resolvedDomain   = ''
$resolvedUsername = ''
$detectionMethod  = ''

if ($TargetUser -ne '') {
    if ($TargetUser -match '\\') {
        $resolvedDomain   = $TargetUser.Split('\')[0]
        $resolvedUsername = $TargetUser.Split('\')[1]
    } else {
        $resolvedDomain   = $env:USERDOMAIN
        $resolvedUsername = $TargetUser
    }
    $detectionMethod = 'Manual (variable)'
}

if (-not $resolvedUsername) {
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
    Write-Output "Recommendation: No interactive user detected. Set TargetUser at the top and re-paste."
    Write-Output "================================"
    return
}

# ------------------------------------------------------------------------------
# Resolve SID
# ------------------------------------------------------------------------------
$targetSid = ''
try {
    $ntAccount = New-Object System.Security.Principal.NTAccount($resolvedDomain, $resolvedUsername)
    $targetSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
} catch {
    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($resolvedUsername)
        $targetSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        Write-Output "===== OneDrive Sync Status ====="
        Write-Output "Computer      : $env:COMPUTERNAME"
        Write-Output "User          : $resolvedDomain\$resolvedUsername"
        Write-Output "Overall Health: ERROR"
        Write-Output "Recommendation: Cannot resolve SID. Check domain connectivity or set TargetUser manually."
        Write-Output "================================"
        return
    }
}

# ------------------------------------------------------------------------------
# Resolve profile path
# ------------------------------------------------------------------------------
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
    return
}

$hkuPath      = "Registry::HKU\$targetSid"
$localAppData = "$targetProfile\AppData\Local"
$logsBase     = "$localAppData\Microsoft\OneDrive\logs\Business1"

if (-not (Test-Path $hkuPath)) {
    Write-Output "===== OneDrive Sync Status ====="
    Write-Output "Computer      : $env:COMPUTERNAME"
    Write-Output "User          : $resolvedDomain\$resolvedUsername (SID: $targetSid)"
    Write-Output "Overall Health: ERROR"
    Write-Output "Recommendation: Registry hive not loaded — user must be actively logged in."
    Write-Output "================================"
    return
}

# ------------------------------------------------------------------------------
# Build status object
# ------------------------------------------------------------------------------
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

# 1. Process check
$odProcs = Get-WmiObject -Class Win32_Process -Filter "Name='OneDrive.exe'" -ErrorAction SilentlyContinue
if ($odProcs) {
    $s.OneDriveRunning = [bool]($odProcs | Where-Object {
        $o = $_.GetOwner(); $o.User -eq $resolvedUsername
    })
}

# 2. Registry via HKU\<SID>
$acctReg = Get-ItemProperty -Path "$hkuPath\SOFTWARE\Microsoft\OneDrive\Accounts\Business1" -ErrorAction SilentlyContinue
if ($acctReg) {
    $s.AccountConfigured = -not [string]::IsNullOrEmpty($acctReg.UserEmail)
    $s.UserEmail         = $acctReg.UserEmail
    $s.SyncFolder        = $acctReg.UserFolder
}

# 3. OneDrive version
foreach ($candidate in @(
    "$localAppData\Microsoft\OneDrive\OneDrive.exe",
    "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
    "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe"
)) {
    if (Test-Path $candidate) { $s.OneDriveVersion = (Get-Item $candidate).VersionInfo.FileVersion; break }
}

# 4. Activity signals — reliable indicators of real sync activity
#    SyncEngine*.log is written only while the sync engine is actively running.
#    *.odl files are updated by any cloud API call from the OneDrive client.
#    Both being old = OneDrive has not spoken to the cloud in a long time,
#    regardless of what SyncDiagnostics.log says.

$syncEngineLogs = Get-ChildItem -Path $logsBase -Filter 'SyncEngine*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending
if ($syncEngineLogs) { $s.SyncEngineLastActivity = $syncEngineLogs[0].LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }

$odlFiles = Get-ChildItem -Path "$localAppData\Microsoft\OneDrive\logs" -Filter '*.odl' -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending
if ($odlFiles) { $s.ODLLastActivity = $odlFiles[0].LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }

$activityDates = @()
if ($s.SyncEngineLastActivity) { $activityDates += [datetime]::Parse($s.SyncEngineLastActivity) }
if ($s.ODLLastActivity)        { $activityDates += [datetime]::Parse($s.ODLLastActivity) }
if ($activityDates) {
    $mostRecent          = ($activityDates | Sort-Object -Descending)[0]
    $s.LastKnownActivity = $mostRecent.ToString('yyyy-MM-dd HH:mm:ss')
    $s.DaysSinceActivity = [int]([datetime]::Now - $mostRecent).TotalDays
}

$diagLog = "$logsBase\SyncDiagnostics.log"
if (Test-Path $diagLog) {
    $diagContent = Get-Content -Path $diagLog -ErrorAction SilentlyContinue
    if ($diagContent) {
        $tail = if ($diagContent.Count -gt 400) { $diagContent[-400..-1] } else { $diagContent }
        foreach ($line in $tail) {
            if ($line -match 'Sync\s*Status\s*[:\|]\s*(.+)')                                                        { $s.SyncStatusFromLog   = $matches[1].Trim() }
            if ($line -match '(?:LastSyncAttempt|LastSuccessfulSync|Last Sync Time|LastSyncTime)\s*[:\|=]\s*(.+)') { $s.LastSyncAttemptInLog = $matches[1].Trim() }
            if ($line -match '(0x[0-9A-Fa-f]{8})')  { $s.ErrorCode = $matches[1] }
            if ($line -match '(AADSTS\d{5,6})')      { $s.ErrorCode = $matches[1] }
        }
    }
}

$isStale = $s.DaysSinceActivity -ge 0 -and $s.DaysSinceActivity -gt $InactivityThresholdDays
if ($isStale) {
    $s.SyncStatus = "No sync activity for $($s.DaysSinceActivity) days (log reports: '$($s.SyncStatusFromLog)')"
} elseif ($s.SyncStatusFromLog)      { $s.SyncStatus = $s.SyncStatusFromLog }
elseif (-not $s.OneDriveRunning)     { $s.SyncStatus = 'Not Running' }
elseif (-not $s.AccountConfigured)   { $s.SyncStatus = 'Not Signed In' }
else                                 { $s.SyncStatus = 'Unknown — no log data found' }

if ($s.ErrorCode) {
    $s.ErrorDescription = if ($ErrorDescriptions.ContainsKey($s.ErrorCode)) { $ErrorDescriptions[$s.ErrorCode] } `
                          else { "Unknown — search docs.microsoft.com for $($s.ErrorCode)" }
}

# 5. Device join (machine-wide — accurate from any account)
$dsreg = & dsregcmd.exe /status 2>&1
if ($dsreg) {
    $s.AzureAdJoined = [bool]($dsreg | Select-String 'AzureAdJoined\s*:\s*YES' -Quiet)
    $s.HybridJoined  = [bool]($dsreg | Select-String 'DomainJoined\s*:\s*YES'  -Quiet) -and $s.AzureAdJoined
}

# 6. SilentAccountConfig policy (HKLM — machine-wide)
$silentPol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -Name 'SilentAccountConfig' -ErrorAction SilentlyContinue
$s.SilentConfigPolicy = ($silentPol -ne $null -and $silentPol.SilentAccountConfig -eq 1)

# Overall health (PRT excluded — cannot be read from admin context)
$caBlocked = $s.ErrorCode -match '0x8004de86|AADSTS53003|AADSTS50072|AADSTS50076'

if     ($caBlocked)                                                             { $s.OverallHealth = 'BLOCKED';        $s.Recommendation = "CA or MFA policy blocking sign-in ($($s.ErrorCode): $($s.ErrorDescription)). Fix the policy — reset will not help." }
elseif (-not $s.AzureAdJoined)                                                  { $s.OverallHealth = 'DEVICE_ERROR';   $s.Recommendation = 'Device not Azure AD joined. Re-register in Entra ID (dsregcmd /join).' }
elseif (-not $s.SilentConfigPolicy)                                             { $s.OverallHealth = 'POLICY_MISSING'; $s.Recommendation = 'SilentAccountConfig not deployed. Set HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\SilentAccountConfig = 1 via Intune/GPO.' }
elseif (-not $s.OneDriveRunning -or -not $s.AccountConfigured -or $isStale)    { $s.OverallHealth = 'NOT_SYNCING';    $s.Recommendation = "OneDrive not active ($($s.DaysSinceActivity) days since last activity). Run Reset-OneDriveSync.ps1." }
else                                                                             { $s.OverallHealth = 'OK';             $s.Recommendation = "OneDrive active $($s.DaysSinceActivity) day(s) ago. No action needed." }

# ------------------------------------------------------------------------------
# Output
# ------------------------------------------------------------------------------
Write-Output ""
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

} # end & { }
