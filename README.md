# OneDrive Repair Toolkit

PowerShell 5.1 scripts for diagnosing and remediating enterprise-wide OneDrive sync failures.


---

## Scripts

| Script | Purpose | Run as |
|--------|---------|--------|
| `Export-OneDriveUsageReport.ps1` | Pull OneDrive usage report from Microsoft Graph API | Admin workstation |
| `Compare-OneDriveSyncReports.ps1` | Compare two exports to measure remediation progress | Admin workstation |
| `Get-OneDriveSyncStatus.ps1` | Diagnose sync state on an individual device | **User context** |
| `Reset-OneDriveSync.ps1` | Silently reset OneDrive and restore sync | **User context** |

---

## Deployment Order

```
[ ] 1. Disable report obfuscation
        M365 Admin Centre > Settings > Services > Reports
        "Hide user details in all reports" = OFF

[ ] 2. Create App Registration (Cloud App Admin role is sufficient)
        Entra Portal > App Registrations > New
        Permission: Microsoft Graph > Application > Reports.Read.All
        Grant admin consent, create a client secret

[ ] 3. Run Export-OneDriveUsageReport.ps1 (Period D90) — save as BASELINE

[ ] 4. Deploy SilentAccountConfig policy via Intune — do this BEFORE any reset
        Device Config > Admin Templates > OneDrive >
        "Silently sign in users to the OneDrive sync app with their Windows credentials" = Enabled
        Intune registry equivalent: HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\SilentAccountConfig = 1

[ ] 5. Wait 24h for policy to apply

[ ] 6. Test Get-OneDriveSyncStatus.ps1 on 3-5 affected machines manually
        IF OverallHealth = BLOCKED  → fix CA policy before proceeding
        IF OverallHealth = PRT_INVALID → investigate device registration health
        IF OverallHealth = NOT_SYNCING → safe to proceed with reset

[ ] 7. Test Reset-OneDriveSync.ps1 on 1-2 machines, confirm imperceptible to user

[ ] 8. Deploy via Intune Remediation (or SCCM):
        Detection:   Get-OneDriveSyncStatus.ps1   (Run as: User)
        Remediation: Reset-OneDriveSync.ps1        (Run as: User)

[ ] 9. Wait 48h (Graph report refresh delay)

[10] Run Export-OneDriveUsageReport.ps1 (Period D30) — save as CURRENT
[11] Run Compare-OneDriveSyncReports.ps1 to measure fix rate
```

---

## Script 1 — Export-OneDriveUsageReport.ps1

```powershell
.\Export-OneDriveUsageReport.ps1 `
    -TenantId     "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ClientId     "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ClientSecret "your-secret-value" `
    -Period       D90
```

**Output columns include:**
- `User Principal Name`, `Last Activity Date`, `Storage Used (Byte)`
- `LastActivityParsed` — formatted date or "Never"
- `DaysSinceActivity` — integer days since last sync (-1 = never)
- `AffectedByOutage` — True if no activity since 2026-03-21

> Use `D90` for the baseline (covers March 21). Use `D30` for post-remediation validation.

---

## Script 2 — Compare-OneDriveSyncReports.ps1

```powershell
# Automatic — derives affected users from baseline:
.\Compare-OneDriveSyncReports.ps1 `
    -BaselineReport .\OneDriveUsage_20260518_090000.csv `
    -CurrentReport  .\OneDriveUsage_20260525_090000.csv

# Narrow to a known list (txt = one UPN per line, or csv with UPN column):
.\Compare-OneDriveSyncReports.ps1 `
    -BaselineReport    .\OneDriveUsage_20260518_090000.csv `
    -CurrentReport     .\OneDriveUsage_20260525_090000.csv `
    -AffectedUsersFile .\affected_upns.txt
```

**Output:** CSV with `Status` column (`FIXED` / `STILL BROKEN`) and console summary showing fix rate %.

---

## Script 3 — Get-OneDriveSyncStatus.ps1

**Must run as the signed-in user — NOT as SYSTEM.**

```powershell
.\Get-OneDriveSyncStatus.ps1
```

`OverallHealth` values:

| Value | Meaning | Action |
|-------|---------|--------|
| `OK` | OneDrive running and configured | No action |
| `NOT_SYNCING` | Not running or not signed in | Run Reset script |
| `POLICY_MISSING` | `SilentAccountConfig` not deployed | Deploy policy first |
| `PRT_INVALID` | PRT expired or missing | Fix device registration |
| `DEVICE_ERROR` | Not Azure AD joined | Re-register device |
| `BLOCKED` | CA or MFA policy blocking | Fix CA policy first |

**As Intune Detection Script:** exit 0 = compliant, exit 1 = needs remediation.

---

## Script 4 — Reset-OneDriveSync.ps1

**Must run as the signed-in user — NOT as SYSTEM.**

```powershell
# Normal (soft restart first, full reset only if needed):
.\Reset-OneDriveSync.ps1

# Skip soft restart, go straight to full /reset:
.\Reset-OneDriveSync.ps1 -ForceFullReset
```

**What it does:**
1. Validates Azure AD join and PRT status — aborts if device not joined
2. **Soft restart:** stops and restarts `OneDrive.exe /background` — no re-index, no re-auth
3. If soft restart doesn't restore sign-in within 60s → **Full reset:** runs `/reset`, restarts in background, waits for silent sign-in via PRT/WAM
4. Reports success or detailed failure reason

> After a full `/reset`, existing files are **not deleted**. OneDrive re-scans them locally (no re-download). Large OneDrives may show "Syncing" for several hours — this is normal.

**As Intune Remediation Script:** exit 0 = success, exit 1 = failed.

---

## Intune Deployment (Remediation Scripts)

1. Intune > Devices > Scripts and remediations > Create
2. **Detection script:** upload `Get-OneDriveSyncStatus.ps1`
3. **Remediation script:** upload `Reset-OneDriveSync.ps1`
4. **Run as account:** `User` ← critical, do not leave as System
5. **Run in 64-bit PowerShell:** Yes
6. Scope to a pilot group first (5–10 affected users), validate, then expand

---

## Prerequisites Checklist

- [ ] `SilentAccountConfig = 1` deployed via Intune/GPO **before** running Reset script
- [ ] Devices are Azure AD / Hybrid joined with valid PRT (`dsregcmd /status`)
- [ ] No CA policy requiring MFA for OneDrive on compliant/hybrid-joined devices
- [ ] Graph report obfuscation disabled in M365 Admin Centre
- [ ] App Registration created with `Reports.Read.All` application permission

---

## Common Error Codes

| Code | Meaning | Fix |
|------|---------|-----|
| `0x8004de86` | CA policy blocking | Review Conditional Access |
| `AADSTS53003` | CA policy blocking | Review Conditional Access |
| `AADSTS50072` / `50076` | MFA required | Exclude OneDrive from MFA for compliant devices |
| `0x8004def0` | Token expired | Reset + valid PRT required |
| `0x8004de69` | SSO failed | Check AAD Connect health |
| `0x8004de40` | No internet / proxy | Check network/proxy config |
