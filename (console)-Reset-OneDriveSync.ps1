# ==============================================================================
# OneDrive Silent Reset — Console Paste Version
# Paste this entire file into a PowerShell console window.
# PowerShell buffers until the final closing } then executes as one unit.
#
# Runs from a domain admin account — does NOT need to be run as the user.
#
# HOW IT LAUNCHES ONEDRIVE AS THE USER:
#   Uses the Task Scheduler COM object (the same approach confirmed working
#   in your local test). Creates a one-shot task with LogonType = 3
#   (TASK_LOGON_INTERACTIVE_TOKEN) which runs inside the user's live desktop
#   session using their existing token — no password needed.
#   The task is created, fired, and deleted automatically.
# ==============================================================================

& {

# ── Configuration ─────────────────────────────────────────────────────────────
$ForceFullReset     = $false  # $true = skip soft restart, go straight to /reset
$SoftRestartWaitSec = 60      # Seconds to wait after soft restart for sign-in
$FullResetWaitSec   = 90      # Seconds to wait after full /reset for sign-in
# ──────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = 'SilentlyContinue'

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')][$Level] $Msg"
}

Write-Log "=== OneDrive Silent Reset (Admin Console) ==="
Write-Log "Running as : $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME"

# ------------------------------------------------------------------------------
# Resolve the logged-in user from explorer.exe process owner
# ------------------------------------------------------------------------------
$explorerProc = Get-WmiObject -Class Win32_Process -Filter "Name='explorer.exe'" |
    Where-Object { ($_.GetOwner()).Domain -ne 'NT AUTHORITY' } |
    Select-Object -First 1

if (-not $explorerProc) {
    Write-Log "No interactive user found on this machine." 'ERROR'
    return
}

$owner    = $explorerProc.GetOwner()
$domain   = $owner.Domain
$username = $owner.User
Write-Log "Target user : $domain\$username"

# Resolve SID and profile path
$ntAccount   = New-Object System.Security.Principal.NTAccount($domain, $username)
$sid         = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
$profilePath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction SilentlyContinue).ProfileImagePath

if (-not $profilePath) {
    Write-Log "Cannot find profile path for $username (SID: $sid)." 'ERROR'
    return
}

$hkuPath      = "Registry::HKU\$sid"
$localAppData = "$profilePath\AppData\Local"
Write-Log "Profile     : $profilePath"

# ------------------------------------------------------------------------------
# Find OneDrive.exe — per-user install (LOCALAPPDATA) takes priority
# ------------------------------------------------------------------------------
$odExe = $null
foreach ($candidate in @(
    "$localAppData\Microsoft\OneDrive\OneDrive.exe",
    "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
    "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe"
)) {
    if (Test-Path $candidate) { $odExe = $candidate; break }
}

if (-not $odExe) {
    Write-Log "OneDrive.exe not found on this device." 'ERROR'
    return
}
Write-Log "OneDrive    : $odExe"

# ------------------------------------------------------------------------------
# Pre-flight: Azure AD join status
# ------------------------------------------------------------------------------
$dsreg     = & dsregcmd.exe /status 2>&1
$aadJoined = [bool]($dsreg | Select-String 'AzureAdJoined\s*:\s*YES' -Quiet)
Write-Log "AAD Joined  : $aadJoined"

if (-not $aadJoined) {
    Write-Log "Device is not Azure AD joined. Silent re-auth is not possible. Aborting." 'ERROR'
    return
}

# Pre-flight: SilentAccountConfig
$silentPol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' `
                -Name 'SilentAccountConfig' -ErrorAction SilentlyContinue
if (-not ($silentPol -and $silentPol.SilentAccountConfig -eq 1)) {
    Write-Log "SilentAccountConfig not deployed — silent sign-in may prompt the user." 'WARN'
} else {
    Write-Log "SilentAcctCfg: Deployed"
}

Write-Log "PRT status  : Cannot verify from admin context. Confirm: dsregcmd /status as user." 'WARN'

# ------------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------------

function Stop-OneDriveSafely {
    Write-Log "Stopping OneDrive..."
    $procs = Get-WmiObject -Class Win32_Process -Filter "Name='OneDrive.exe'" |
        Where-Object { ($_.GetOwner()).User -eq $username }
    if ($procs) {
        $procs | ForEach-Object { $_.Terminate() | Out-Null }
        Start-Sleep -Seconds 4
        # Force kill anything still hanging
        Get-WmiObject -Class Win32_Process -Filter "Name='OneDrive.exe'" |
            Where-Object { ($_.GetOwner()).User -eq $username } |
            ForEach-Object { $_.Terminate() | Out-Null }
        Start-Sleep -Seconds 2
    }
    Write-Log "OneDrive stopped."
}

function Start-OneDriveAsUser {
    param([string]$Arguments)
    # Uses Task Scheduler COM object with TASK_LOGON_INTERACTIVE_TOKEN (3).
    # This runs the task inside the user's live desktop session using their
    # existing token — no password needed.
    $taskName = "OD_Reset_$(Get-Random)"
    $scheduler = $null
    $folder    = $null
    try {
        $scheduler = New-Object -ComObject 'Schedule.Service'
        $scheduler.Connect()
        $folder  = $scheduler.GetFolder('\')
        $taskDef = $scheduler.NewTask(0)

        $taskDef.Settings.DisallowStartIfOnBatteries = $false
        $taskDef.Settings.StopIfGoingOnBatteries     = $false
        $taskDef.Settings.Hidden                     = $true
        $taskDef.Settings.ExecutionTimeLimit         = 'PT5M'

        $action           = $taskDef.Actions.Create(0)
        $action.Path      = $odExe
        $action.Arguments = $Arguments

        $taskDef.Principal.UserId    = "$domain\$username"
        $taskDef.Principal.LogonType = 3   # TASK_LOGON_INTERACTIVE_TOKEN
        $taskDef.Principal.RunLevel  = 0   # Least privilege (not elevated)

        $task = $folder.RegisterTaskDefinition($taskName, $taskDef, 6, "$domain\$username", $null, 3)
        $task.Run($null) | Out-Null

        Write-Log "OneDrive launched in user session (args: $Arguments)"
        return $true

    } catch {
        Write-Log "Failed to launch OneDrive via COM task: $_" 'ERROR'
        return $false
    } finally {
        # Brief pause then clean up the task — process is already running by this point
        Start-Sleep -Seconds 3
        try { if ($folder) { $folder.DeleteTask($taskName, 0) | Out-Null } } catch { }
    }
}

function Test-SignedIn {
    $reg = Get-ItemProperty -Path "$hkuPath\SOFTWARE\Microsoft\OneDrive\Accounts\Business1" -ErrorAction SilentlyContinue
    return ($reg -ne $null -and -not [string]::IsNullOrEmpty($reg.UserEmail))
}

function Wait-ForSignIn {
    param([int]$MaxSeconds)
    $elapsed = 0
    while ($elapsed -lt $MaxSeconds) {
        Start-Sleep -Seconds 5
        $elapsed += 5
        if (Test-SignedIn) { return $true }
    }
    return $false
}

# Log pre-reset account
$preEmail = (Get-ItemProperty "$hkuPath\SOFTWARE\Microsoft\OneDrive\Accounts\Business1" -ErrorAction SilentlyContinue).UserEmail
Write-Log "Pre-reset account: $preEmail"

# ==============================================================================
# Attempt 1: Soft Restart
# Stop and restart OneDrive — no /reset, no re-index, no forced re-auth.
# Fixes cases where OneDrive crashed and simply never restarted.
# ==============================================================================
if (-not $ForceFullReset) {
    Write-Log "--- Attempt 1: Soft Restart ---"
    Stop-OneDriveSafely
    Start-Sleep -Seconds 2

    if (Start-OneDriveAsUser -Arguments '/background') {
        Write-Log "Waiting up to $SoftRestartWaitSec seconds for sign-in..."
        if (Wait-ForSignIn -MaxSeconds $SoftRestartWaitSec) {
            $email = (Get-ItemProperty "$hkuPath\SOFTWARE\Microsoft\OneDrive\Accounts\Business1" -ErrorAction SilentlyContinue).UserEmail
            Write-Log "Soft restart succeeded. Signed in as: $email"
            Write-Log "=== Complete (Soft Restart — no re-index required) ==="
            return
        }
    }
    Write-Log "Soft restart did not restore sign-in within $SoftRestartWaitSec seconds. Escalating to full reset." 'WARN'
}

# ==============================================================================
# Attempt 2: Full Reset
# /reset clears auth tokens and sync state. Files on disk are NOT deleted.
# OneDrive re-scans existing files after sign-in — no re-download needed.
# For large OneDrives the re-scan may take hours — this is normal.
# ==============================================================================
Write-Log "--- Attempt 2: Full Reset ---"
Stop-OneDriveSafely

Write-Log "Running OneDrive /reset in user session..."
if (-not (Start-OneDriveAsUser -Arguments '/reset')) {
    Write-Log "Failed to launch /reset. Aborting." 'ERROR'
    return
}
# /reset exits quickly but background cleanup continues — wait before restarting
Start-Sleep -Seconds 10

Write-Log "Starting OneDrive after reset..."
if (-not (Start-OneDriveAsUser -Arguments '/background')) {
    Write-Log "Failed to start OneDrive after reset." 'ERROR'
    return
}

Write-Log "Waiting up to $FullResetWaitSec seconds for silent sign-in..."
if (Wait-ForSignIn -MaxSeconds $FullResetWaitSec) {
    $postEmail = (Get-ItemProperty "$hkuPath\SOFTWARE\Microsoft\OneDrive\Accounts\Business1" -ErrorAction SilentlyContinue).UserEmail
    Write-Log "Full reset succeeded. Signed in as: $postEmail"
    Write-Log "NOTE: OneDrive will re-scan existing files — may show 'Syncing' for some time." 'INFO'
    Write-Log "=== Complete (Full Reset) ==="
    return
}

# ==============================================================================
# Both attempts failed
# ==============================================================================
Write-Log "OneDrive did not sign in automatically within the wait period." 'ERROR'
Write-Log "Common causes:" 'ERROR'
Write-Log "  1. SilentAccountConfig = 1 not deployed to HKLM via Intune/GPO" 'ERROR'
Write-Log "  2. PRT is invalid — verify: dsregcmd /status as the user" 'ERROR'
Write-Log "  3. CA policy requiring MFA for OneDrive — check Entra Sign-in logs" 'ERROR'
Write-Log "  4. Proxy or firewall blocking login.microsoftonline.com" 'ERROR'
Write-Log "Run (console)-Get-OneDriveSyncStatus.ps1 for a detailed diagnosis." 'ERROR'
Write-Log "=== Reset Incomplete ==="

} # end & { }
