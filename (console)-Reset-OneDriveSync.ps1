# ==============================================================================
# OneDrive Silent Reset V2 — Console Paste Version
# Paste this entire file into a PowerShell console window.
# PowerShell buffers until the final closing } then executes as one unit.
#
# Runs from a domain admin account — does NOT need to be run as the user.
#
# HOW IT LAUNCHES ONEDRIVE AS THE USER WITHOUT SCHEDULED TASKS:
#   It borrows the logged-in user's process token from their explorer.exe
#   and uses CreateProcessWithTokenW (Windows API) to launch OneDrive inside
#   their live desktop session. This only requires SeImpersonatePrivilege,
#   which domain admins already hold. No password needed.
# ==============================================================================

& {

# ── Configuration ─────────────────────────────────────────────────────────────
$ForceFullReset     = $false  # $true = skip soft restart, go straight to /reset
$SoftRestartWaitSec = 60      # Seconds to wait after soft restart
$FullResetWaitSec   = 90      # Seconds to wait after full /reset for sign-in
# ──────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = 'SilentlyContinue'

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')][$Level] $Msg"
}

Write-Log "=== OneDrive Silent Reset V2 (Admin Console) ==="
Write-Log "Running as   : $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME"

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

$owner     = $explorerProc.GetOwner()
$domain    = $owner.Domain
$username  = $owner.User
$explorerPid = [uint32]$explorerProc.ProcessId

Write-Log "Target user  : $domain\$username (explorer PID: $explorerPid)"

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
Write-Log "Profile      : $profilePath"

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
Write-Log "OneDrive     : $odExe"

# ------------------------------------------------------------------------------
# Pre-flight: Azure AD join status
# ------------------------------------------------------------------------------
$dsreg     = & dsregcmd.exe /status 2>&1
$aadJoined = [bool]($dsreg | Select-String 'AzureAdJoined\s*:\s*YES' -Quiet)

Write-Log "AAD Joined   : $aadJoined"

if (-not $aadJoined) {
    Write-Log "Device is not Azure AD joined. Silent re-auth is not possible. Aborting." 'ERROR'
    return
}

# Pre-flight: SilentAccountConfig
$silentPol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' `
                -Name 'SilentAccountConfig' -ErrorAction SilentlyContinue
if (-not ($silentPol -and $silentPol.SilentAccountConfig -eq 1)) {
    Write-Log "SilentAccountConfig not set — silent sign-in may prompt the user." 'WARN'
    Write-Log "Deploy HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\SilentAccountConfig = 1 via Intune." 'WARN'
} else {
    Write-Log "SilentAcctCfg: Deployed"
}

# PRT cannot be read from admin context — log a reminder only
Write-Log "PRT status   : Cannot verify from admin context. Confirm with: dsregcmd /status (as user)" 'WARN'

# ------------------------------------------------------------------------------
# Load Windows API via Add-Type
#
# CreateProcessWithTokenW:
#   Launches a process using a duplicated user token.
#   Requires SeImpersonatePrivilege — domain admins have this by default.
#   The token is obtained from the user's explorer.exe process.
#   No password is needed; the token comes from their live session.
# ------------------------------------------------------------------------------
Write-Log "Loading Windows API..."

try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class ODLauncher {

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwAccess, bool bInherit, uint dwPid);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr hProcess, uint dwAccess, out IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool DuplicateTokenEx(
        IntPtr hToken, uint dwAccess, IntPtr lpAttr,
        int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(
        IntPtr hToken, uint dwLogonFlags,
        string lpAppName, string lpCmdLine,
        uint dwCreationFlags, IntPtr lpEnv,
        string lpDir, ref STARTUPINFO lpSI,
        out PROCESS_INFORMATION lpPI);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct STARTUPINFO {
        public int    cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int    dwX, dwY, dwXSize, dwYSize;
        public int    dwXCountChars, dwYCountChars, dwFillAttribute;
        public int    dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdIn, hStdOut, hStdErr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public int    dwProcessId, dwThreadId;
    }

    // Launch a process as the user who owns the given explorer PID.
    // Returns the new process ID, or throws on failure.
    public static int LaunchAsUser(uint explorerPid, string exePath, string arguments) {
        IntPtr hProc  = IntPtr.Zero;
        IntPtr hToken = IntPtr.Zero;
        IntPtr hDup   = IntPtr.Zero;
        try {
            // Open explorer with PROCESS_QUERY_INFORMATION (0x0400)
            hProc = OpenProcess(0x0400, false, explorerPid);
            if (hProc == IntPtr.Zero)
                throw new Exception("OpenProcess failed. Error: " + Marshal.GetLastWin32Error());

            // Get its token with TOKEN_DUPLICATE|TOKEN_QUERY (0x000A)
            if (!OpenProcessToken(hProc, 0x000A, out hToken))
                throw new Exception("OpenProcessToken failed. Error: " + Marshal.GetLastWin32Error());

            // Duplicate as a primary token (TokenPrimary=1, SecurityImpersonation=2)
            if (!DuplicateTokenEx(hToken, 0x10000000, IntPtr.Zero, 2, 1, out hDup))
                throw new Exception("DuplicateTokenEx failed. Error: " + Marshal.GetLastWin32Error());

            // Build STARTUPINFO — STARTF_USESHOWWINDOW=1, SW_HIDE=0
            var si = new STARTUPINFO();
            si.cb       = Marshal.SizeOf(si);
            si.dwFlags  = 1;
            si.wShowWindow = 0;

            PROCESS_INFORMATION pi;
            string cmdLine = "\"" + exePath + "\" " + arguments;

            // CREATE_NO_WINDOW = 0x08000000
            if (!CreateProcessWithTokenW(hDup, 0, null, cmdLine, 0x08000000,
                    IntPtr.Zero, null, ref si, out pi))
                throw new Exception("CreateProcessWithTokenW failed. Error: " + Marshal.GetLastWin32Error());

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return pi.dwProcessId;
        }
        finally {
            if (hProc  != IntPtr.Zero) CloseHandle(hProc);
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
            if (hDup   != IntPtr.Zero) CloseHandle(hDup);
        }
    }
}
'@ -ErrorAction Stop

    Write-Log "API loaded   : OK"

} catch {
    Write-Log "Failed to load Windows API: $_" 'ERROR'
    return
}

# ------------------------------------------------------------------------------
# Helper functions — kept as close as possible to Reset-OneDriveSync.ps1
# ------------------------------------------------------------------------------

function Stop-OneDriveSafely {
    Write-Log "Stopping OneDrive..."
    # Use WMI to stop the specific user's OneDrive (accurate from admin context)
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
    try {
        $newPid = [ODLauncher]::LaunchAsUser($explorerPid, $odExe, $Arguments)
        Write-Log "OneDrive launched in user session (PID: $newPid, args: $Arguments)"
        return $true
    } catch {
        Write-Log "Failed to launch OneDrive as user: $_" 'ERROR'
        return $false
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

# Pre-reset account info
$preEmail = (Get-ItemProperty "$hkuPath\SOFTWARE\Microsoft\OneDrive\Accounts\Business1" -ErrorAction SilentlyContinue).UserEmail
Write-Log "Pre-reset account: $preEmail"

# ==============================================================================
# Attempt 1: Soft Restart
# Stop and restart OneDrive — no /reset, no re-index, no re-auth if tokens cached
# Fixes cases where OneDrive crashed and simply never restarted
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
# /reset clears auth tokens and sync state — files on disk are NOT deleted.
# OneDrive re-scans existing files after sign-in (no re-download).
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

Write-Log "Starting OneDrive in background..."
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
Write-Log "  2. PRT is invalid — verify with: dsregcmd /status (as the user)" 'ERROR'
Write-Log "  3. CA policy requiring MFA for OneDrive — check Entra Sign-in logs" 'ERROR'
Write-Log "  4. Proxy or firewall blocking login.microsoftonline.com" 'ERROR'
Write-Log "Run (console)-Get-OneDriveSyncStatus.ps1 on this device for a detailed diagnosis." 'ERROR'
Write-Log "=== Reset Incomplete ==="

} # end & { }
