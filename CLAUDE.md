# CLAUDE.md - DefenderControl

## Overview
WPF GUI tool to fully disable or re-enable Microsoft Defender on Windows 10/11. Multi-phase approach with system restore point creation. v3.1.0.

## Tech Stack
- PowerShell 5.1, WPF GUI

## Key Details
- ~1,700 lines, single-file
- Multi-phase disable: Set-MpPreference, GP registry keys, service disabling (4 escalation methods including token impersonation), PPL flag stripping, scheduled task disabling, SmartScreen, context menu removal
- Full Enable button reverses all changes
- Creates System Restore Point before acting
- **Live Status Dashboard**: Grid showing Real-Time Protection, Tamper Protection, Cloud Protection, Firewall, WinDefend service status, Last Definition Update, Anti-Spyware status with colored ON/OFF indicators
- **Tamper Protection Guidance**: Prominent red warning panel with step-by-step instructions when Tamper Protection is detected ON. Includes "Open Windows Security" button.
- **Scheduled Re-Enable**: ComboBox (1h/2h/4h/8h/24h) + Schedule button creates a SYSTEM scheduled task to auto re-enable Defender. Self-cleaning task with cancel support.
- Embedded log panel with RichTextBox, verbose toggle, export, clear
- Full dark ComboBox ControlTemplate (popup + togglebutton + items) for proper dark mode

## Build/Run
```powershell
# Run as Administrator
.\DefenderControl.ps1
```

## Version
3.1.0

## Version History
- **3.1.0** - Live status dashboard, Tamper Protection guidance panel, scheduled re-enable, dashboard refresh button
- **3.0** - Initial WPF GUI with async disable/enable, log panel, dry run mode

## Gotchas
- Tamper Protection must be disabled manually in Windows Security before the script can fully disable Defender
- Service permission escalation uses 4 fallback methods (Set-Service, sc.exe sdset, takeown/icacls, token impersonation)
- ComboBox in WPF dark mode requires full ControlTemplate - style setters alone leave white dropdowns
- Dashboard uses a separate `DashQueue` concurrent queue to push status from background runspaces to UI thread
- Scheduled re-enable encodes the enable script as Base64 EncodedCommand for clean task creation
