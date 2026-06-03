
& {

# ── Find the logged-in user ──────────────────────────────────────────────────
$explorerProc = Get-WmiObject -Class Win32_Process -Filter "Name='explorer.exe'" |
    Where-Object { ($_.GetOwner()).Domain -ne 'NT AUTHORITY' } |
    Select-Object -First 1

if (-not $explorerProc) {
    Write-Output "No interactive user found on this machine."
    return
}

$owner    = $explorerProc.GetOwner()
$username = "$($owner.Domain)\$($owner.User)"
Write-Output "Target user: $username"

# ── Resolve OneDrive.exe path from user's profile ────────────────────────────
$ntAccount   = New-Object System.Security.Principal.NTAccount($owner.Domain, $owner.User)
$sid         = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
$profilePath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction SilentlyContinue).ProfileImagePath

$odExe = "$profilePath\AppData\Local\Microsoft\OneDrive\OneDrive.exe"
if (-not (Test-Path $odExe)) {
    $odExe = "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe"
}
if (-not (Test-Path $odExe)) {
    Write-Output "OneDrive.exe not found. Check installation path."
    return
}
Write-Output "OneDrive path: $odExe"

# ── Create a one-shot scheduled task that runs as the user ───────────────────
# -LogonType Interactive ensures it runs inside the user's active desktop
# session, which gives it access to their token and WAM for silent sign-in.

$taskName  = "OD_SilentRestart_$(Get-Random)"
$action    = New-ScheduledTaskAction -Execute $odExe -Argument '/background'
$trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
$principal = New-ScheduledTaskPrincipal -UserId $username -LogonType Interactive -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet `
                -DeleteExpiredTaskAfter (New-TimeSpan -Minutes 5) `
                -ExecutionTimeLimit     (New-TimeSpan -Minutes 2)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Start-ScheduledTask -TaskName $taskName
Write-Output "Task fired. Waiting 20 seconds for OneDrive to start..."

Start-Sleep -Seconds 20

# ── Check if OneDrive is now running as the user ─────────────────────────────
$odRunning = Get-WmiObject -Class Win32_Process -Filter "Name='OneDrive.exe'" |
    Where-Object { ($_.GetOwner()).User -eq $owner.User }

if ($odRunning) {
    Write-Output "SUCCESS: OneDrive is running as $username"
} else {
    Write-Output "WARNING: OneDrive process not detected after 20 seconds. May still be starting, or silent sign-in failed."
}

# ── Clean up the task ────────────────────────────────────────────────────────
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Output "Scheduled task cleaned up."

}
