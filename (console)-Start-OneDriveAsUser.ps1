# ==============================================================================
# OneDrive Silent Restart — Console Paste Version
# Paste this entire file into a PowerShell console window.
# PowerShell will buffer until the final closing } then execute as one unit.
#
# What this does:
#   Finds the interactively logged-in user, then uses the Task Scheduler COM
#   object to launch OneDrive.exe /background inside their desktop session.
#   This triggers silent sign-in via WAM/PRT without any user interaction.
#
# Why COM instead of New-ScheduledTask* cmdlets:
#   The PowerShell scheduled task cmdlets serialise settings to XML before
#   registering. Certain principal/trigger combinations produce XML that
#   Windows rejects with "missing a required element or attribute". The COM
#   object builds the task in memory, bypassing XML validation entirely.
# ==============================================================================

& {

$ErrorActionPreference = 'SilentlyContinue'

# ------------------------------------------------------------------------------
# 1. Find the interactively logged-in user via explorer.exe process owner
# ------------------------------------------------------------------------------
$explorerProc = Get-WmiObject -Class Win32_Process -Filter "Name='explorer.exe'" |
    Where-Object { ($_.GetOwner()).Domain -ne 'NT AUTHORITY' } |
    Select-Object -First 1

if (-not $explorerProc) {
    Write-Output "ERROR: No interactive user found on this machine."
    return
}

$owner    = $explorerProc.GetOwner()
$username = "$($owner.Domain)\$($owner.User)"
Write-Output "Target user   : $username"

# ------------------------------------------------------------------------------
# 2. Resolve OneDrive.exe — per-user install takes priority over machine install
# ------------------------------------------------------------------------------
$ntAccount   = New-Object System.Security.Principal.NTAccount($owner.Domain, $owner.User)
$sid         = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
$profilePath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" `
                    -ErrorAction SilentlyContinue).ProfileImagePath

$odExe = $null
foreach ($candidate in @(
    "$profilePath\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
    "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
    "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe"
)) {
    if (Test-Path $candidate) { $odExe = $candidate; break }
}

if (-not $odExe) {
    Write-Output "ERROR: OneDrive.exe not found on this machine."
    return
}
Write-Output "OneDrive path : $odExe"

# ------------------------------------------------------------------------------
# 3. Stop any existing OneDrive process for this user before restarting
# ------------------------------------------------------------------------------
$existing = Get-WmiObject -Class Win32_Process -Filter "Name='OneDrive.exe'" |
    Where-Object { ($_.GetOwner()).User -eq $owner.User }

if ($existing) {
    Write-Output "Stopping existing OneDrive process..."
    $existing | ForEach-Object { $_.Terminate() | Out-Null }
    Start-Sleep -Seconds 3
}

# ------------------------------------------------------------------------------
# 4. Launch OneDrive in the user's session via Task Scheduler COM object
#
#    TASK_LOGON_INTERACTIVE_TOKEN (3):
#      Runs the task using the user's existing interactive session token.
#      No password is stored or required — Windows uses the live session.
#      This is the only method that gives the process proper access to
#      WAM and the PRT for silent OneDrive sign-in.
# ------------------------------------------------------------------------------
$taskName = "OD_SilentRestart_$(Get-Random)"

try {
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $folder  = $scheduler.GetFolder('\')
    $taskDef = $scheduler.NewTask(0)

    # Settings
    $taskDef.Settings.DisallowStartIfOnBatteries = $false
    $taskDef.Settings.StopIfGoingOnBatteries     = $false
    $taskDef.Settings.ExecutionTimeLimit         = 'PT2M'
    $taskDef.Settings.DeleteExpiredTaskAfter     = 'PT5M'
    $taskDef.Settings.Hidden                     = $true

    # Action — run OneDrive in background
    $action           = $taskDef.Actions.Create(0)   # TASK_ACTION_EXEC
    $action.Path      = $odExe
    $action.Arguments = '/background'

    # Principal — TASK_LOGON_INTERACTIVE_TOKEN = 3, TASK_RUNLEVEL_LUA = 0
    $taskDef.Principal.UserId    = $username
    $taskDef.Principal.LogonType = 3   # Interactive token — no password needed
    $taskDef.Principal.RunLevel  = 0   # Least privilege (not elevated)

    # Register — 6 = TASK_CREATE_OR_UPDATE, $null password (uses session token)
    $task = $folder.RegisterTaskDefinition($taskName, $taskDef, 6, $username, $null, 3)

    Write-Output "Task registered. Starting OneDrive in user session..."
    $task.Run($null) | Out-Null

} catch {
    Write-Output "ERROR: Failed to register or start scheduled task: $_"
    return
}

# ------------------------------------------------------------------------------
# 5. Wait and check result
# ------------------------------------------------------------------------------
Write-Output "Waiting 25 seconds for OneDrive to start and authenticate..."
Start-Sleep -Seconds 25

$odRunning = Get-WmiObject -Class Win32_Process -Filter "Name='OneDrive.exe'" |
    Where-Object { ($_.GetOwner()).User -eq $owner.User }

if ($odRunning) {
    Write-Output "SUCCESS : OneDrive is running as $username"

    # Check if the account signed back in
    $hkuAcct = Get-ItemProperty -Path "Registry::HKU\$sid\SOFTWARE\Microsoft\OneDrive\Accounts\Business1" `
                   -ErrorAction SilentlyContinue
    if ($hkuAcct -and $hkuAcct.UserEmail) {
        Write-Output "Signed in as : $($hkuAcct.UserEmail)"
    } else {
        Write-Output "WARNING : OneDrive is running but account sign-in not yet detected in registry."
        Write-Output "          Silent sign-in may still be in progress, or SilentAccountConfig policy is missing."
    }
} else {
    Write-Output "WARNING : OneDrive process not detected after 25 seconds."
    Write-Output "          Check that SilentAccountConfig = 1 is deployed and the user's PRT is valid."
}

# ------------------------------------------------------------------------------
# 6. Clean up the scheduled task
# ------------------------------------------------------------------------------
try {
    $folder.DeleteTask($taskName, 0) | Out-Null
    Write-Output "Scheduled task cleaned up."
} catch { }

}
