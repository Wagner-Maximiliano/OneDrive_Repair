#Requires -Version 5.1
<#
.SYNOPSIS
    Silently resets OneDrive for Business and restores automatic sync.

.DESCRIPTION
    Attempts a soft restart first (stop and start OneDrive.exe with no data loss
    or re-index). If sign-in is not restored within the wait period it escalates
    to a full /reset followed by a background restart.

    After a full /reset, OneDrive re-scans existing files rather than
    re-downloading them — local files are NOT deleted or moved.

    USE AS INTUNE REMEDIATION SCRIPT:
        Pair with Get-OneDriveSyncStatus.ps1 as the Detection script.
        Set "Run as account" = User (NOT System)
        Exit 0 = Remediation succeeded
        Exit 1 = Remediation failed (check output for reason)

    USE STANDALONE:
        Run as the affected user for one-at-a-time testing.

.PARAMETER ForceFullReset
    Skip the soft restart attempt and go straight to /reset.
    Use when you already know soft restart will not help.

.PARAMETER SoftRestartWaitSec
    Seconds to wait after soft restart before declaring it failed.
    Default: 60

.PARAMETER FullResetWaitSec
    Seconds to wait after full /reset for OneDrive to silently sign back in.
    Default: 90

.NOTES
    PREREQUISITES — all three must be in place before deploying at scale:

    1. SilentAccountConfig = 1 deployed via Intune or GPO:
       HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\SilentAccountConfig (DWORD = 1)
       Intune path: Device Config > Admin Templates > OneDrive >
       "Silently sign in users to the OneDrive sync app with their Windows credentials"

    2. Device must have a valid PRT (Primary Refresh Token).
       Verify with: dsregcmd /status  ->  AzureAdPrt : YES
       If PRT is invalid, user may receive a sign-in prompt despite this script.

    3. No Conditional Access policy requiring MFA for OneDrive on hybrid-joined
       or compliant devices. Run Get-OneDriveSyncStatus.ps1 first — if it reports
       OverallHealth = BLOCKED, fix the CA policy before running this script.

    This script MUST run in the context of the signed-in user (not SYSTEM).
#>
param(
    [switch]$ForceFullReset,
    [int]$SoftRestartWaitSec = 60,
    [int]$FullResetWaitSec   = 90
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')][$Level] $Msg"
}

function Get-OneDriveExe {
    foreach ($p in @(
        "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
        "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
        "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe"
    )) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Stop-OneDriveSafely {
    $procs = Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue
    if ($procs) {
        # Attempt graceful close first
        $procs | ForEach-Object { $_.CloseMainWindow() | Out-Null }
        Start-Sleep -Seconds 4
        # Force kill anything still running
        Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
    }
}

function Test-SignedIn {
    $reg = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1' -ErrorAction SilentlyContinue
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

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
Write-Log "=== OneDrive Silent Reset | $env:COMPUTERNAME | $env:USERNAME ==="

$odExe = Get-OneDriveExe
if (-not $odExe) {
    Write-Log "OneDrive.exe not found. OneDrive may not be installed on this device." 'ERROR'
    exit 1
}
Write-Log "OneDrive executable : $odExe"

# PRT and join status
$dsreg      = & dsregcmd.exe /status 2>&1
$aadJoined  = [bool]($dsreg | Select-String 'AzureAdJoined\s*:\s*YES' -Quiet)
$prtValid   = [bool]($dsreg | Select-String 'AzureAdPrt\s*:\s*YES'    -Quiet)

Write-Log "Azure AD Joined     : $aadJoined"
Write-Log "PRT Valid           : $prtValid"

if (-not $aadJoined) {
    Write-Log "Device is not Azure AD joined. Silent re-authentication is not possible. Aborting." 'ERROR'
    Write-Log "Re-register the device in Entra ID before running this script." 'ERROR'
    exit 1
}

if (-not $prtValid) {
    Write-Log "PRT is invalid. Silent sign-in may fail and user could see a prompt." 'WARN'
    Write-Log "Consider running 'dsregcmd /refreshprt' or having user re-sign into Windows first." 'WARN'
    # Proceed — the reset may still work via WAM fallback; we log the risk
}

# SilentAccountConfig policy
$silentPol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' `
                -Name 'SilentAccountConfig' -ErrorAction SilentlyContinue
if (-not ($silentPol -and $silentPol.SilentAccountConfig -eq 1)) {
    Write-Log "SilentAccountConfig policy not found or not set to 1." 'WARN'
    Write-Log "Silent sign-in relies on WAM fallback only — user may see a sign-in prompt." 'WARN'
    Write-Log "Deploy the policy via Intune before running at scale." 'WARN'
}

# ---------------------------------------------------------------------------
# Attempt 1: Soft restart
# No /reset — just stop and restart OneDrive.exe
# Fixes cases where OneDrive crashed and never restarted
# No file re-index, no re-authentication required if tokens are still cached
# ---------------------------------------------------------------------------
if (-not $ForceFullReset) {
    Write-Log "--- Attempt 1: Soft Restart ---"
    Stop-OneDriveSafely
    Start-Sleep -Seconds 2
    Start-Process -FilePath $odExe -ArgumentList '/background' -WindowStyle Hidden

    Write-Log "Waiting up to $SoftRestartWaitSec seconds for sign-in..."
    if (Wait-ForSignIn -MaxSeconds $SoftRestartWaitSec) {
        $email = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1').UserEmail
        Write-Log "Soft restart succeeded. Signed in as: $email"
        Write-Log "=== Complete (Soft Restart — no re-index required) ==="
        exit 0
    }

    Write-Log "Soft restart did not restore sign-in within $SoftRestartWaitSec seconds. Escalating to full reset." 'WARN'
}

# ---------------------------------------------------------------------------
# Attempt 2: Full reset
# /reset clears authentication tokens and sync state.
# Existing synced files are NOT deleted from the local drive.
# OneDrive will re-scan and re-index all files after sign-in (no re-download).
# For large OneDrives this re-index may take hours — this is normal.
# ---------------------------------------------------------------------------
Write-Log "--- Attempt 2: Full Reset ---"

$preEmail = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1' -ErrorAction SilentlyContinue).UserEmail
Write-Log "Pre-reset account : $preEmail"

Stop-OneDriveSafely

Write-Log "Running OneDrive /reset..."
# /reset exits quickly; background cleanup continues for several seconds
Start-Process -FilePath $odExe -ArgumentList '/reset' -WindowStyle Hidden -Wait
Start-Sleep -Seconds 10

Write-Log "Starting OneDrive in background..."
Start-Process -FilePath $odExe -ArgumentList '/background' -WindowStyle Hidden

Write-Log "Waiting up to $FullResetWaitSec seconds for silent sign-in..."
if (Wait-ForSignIn -MaxSeconds $FullResetWaitSec) {
    $postEmail = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1' -ErrorAction SilentlyContinue).UserEmail
    Write-Log "Full reset succeeded. Signed in as: $postEmail"
    Write-Log "NOTE: OneDrive will now re-scan existing files. This may show as 'Syncing' for some time." 'INFO'
    Write-Log "=== Complete (Full Reset) ==="
    exit 0
}

# ---------------------------------------------------------------------------
# Both attempts failed
# ---------------------------------------------------------------------------
Write-Log "OneDrive did not sign in automatically within the wait period." 'ERROR'
Write-Log "Common causes:" 'ERROR'
Write-Log "  1. SilentAccountConfig = 1 not deployed to HKLM via Intune/GPO" 'ERROR'
Write-Log "  2. PRT is invalid — run: dsregcmd /status (check AzureAdPrt)" 'ERROR'
Write-Log "  3. CA policy requiring MFA for OneDrive — check Entra Sign-in logs" 'ERROR'
Write-Log "  4. Proxy or firewall blocking login.microsoftonline.com" 'ERROR'
Write-Log "Run Get-OneDriveSyncStatus.ps1 on this device for a detailed diagnosis." 'ERROR'
Write-Log "=== Reset Incomplete ==="
exit 1
