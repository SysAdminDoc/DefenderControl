# CLAUDE.md - DefenderControl

## Overview
WPF GUI tool to fully disable or re-enable Microsoft Defender on Windows 10/11. Multi-phase approach with system restore point creation. v3.0.

## Tech Stack
- PowerShell 5.1, WPF GUI

## Key Details
- ~1,475 lines, single-file
- Multi-phase disable: Set-MpPreference, GP registry keys, service disabling (4 escalation methods including token impersonation), PPL flag stripping, scheduled task disabling, SmartScreen, context menu removal
- Full Enable button reverses all changes
- Creates System Restore Point before acting
- Warns if Tamper Protection is on

## Build/Run
```powershell
# Run as Administrator
.\DefenderControl.ps1
```

## Version
3.0

## Gotchas
- Tamper Protection must be disabled manually in Windows Security before the script can fully disable Defender
- Service permission escalation uses 4 fallback methods (Set-Service, sc.exe sdset, takeown/icacls, token impersonation)
