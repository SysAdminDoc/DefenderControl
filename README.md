# Defender Control

A professional PowerShell WPF utility to comprehensively disable or re-enable Microsoft Defender on Windows 10/11. Dark-themed GUI with fully async operations, detailed logging, and complete reversibility.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1-blue?logo=powershell&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Why This Exists

Sometimes you need Defender completely out of the way — deploying custom imaging software, running legacy tools that trigger false positives, benchmarking without AV overhead, or configuring kiosk systems. The built-in Windows UI only lets you temporarily disable real-time protection, and it re-enables itself within minutes.

Defender Control performs a thorough multi-phase disable that persists across reboots by targeting preferences, group policy registry keys, services, scheduled tasks, PPL flags, and more. Everything is fully reversible with a single click.

> **Windows Firewall is completely untouched.** This tool only manages Defender antivirus components.

---

## Features

- **10-Phase Disable** — Preferences, group policy, notifications, scheduled tasks, services, PPL flags, context menus, SmartScreen, and process termination
- **7-Phase Enable** — Full restoration to Windows defaults with signature update and verification
- **Fully Async GUI** — All operations run in background runspaces; the window never freezes
- **4-Level Permission Escalation** — Direct write → .NET handle with ownership → reg.exe → SYSTEM scheduled task
- **PPL Flag Stripping** — Removes Protected Process Light from Defender services so they don't survive reboot
- **System Restore Point** — Automatically created before disabling for easy rollback
- **Dry Run Mode** — Simulate the entire operation without making any changes
- **Verbose Toggle** — Filter log output between important-only and full diagnostic detail
- **Export Log** — Save the full operation log to a text file for troubleshooting or documentation
- **Reboot Button** — Appears after operations that need a restart
- **OS Build Awareness** — Detects Win10/11, warns on deprecated GP keys (Win11 22H2+), blocks unsupported versions
- **Self-Elevation** — Automatically requests Administrator via UAC
- **Orphan Cleanup** — Removes leftover scheduled tasks from interrupted previous runs

---

## Requirements

| Requirement | Details |
|---|---|
| **OS** | Windows 10 (1809+) or Windows 11 |
| **PowerShell** | Windows PowerShell 5.1 (not PowerShell 7) |
| **Privileges** | Administrator (auto-elevates via UAC) |
| **Tamper Protection** | Should be OFF for full effectiveness (see below) |

---

## Usage

### Quick Start

1. Download `DefenderControl.ps1`
2. Right-click → **Run with PowerShell** (or it will self-elevate)
3. Disable Tamper Protection first if you haven't already
4. Click **Disable Defender** or **Enable Defender**
5. Reboot when prompted

### Tamper Protection

For the disable operation to fully persist, Tamper Protection must be turned off **manually** — Microsoft does not allow programmatic control of this setting.

**Windows Security → Virus & Threat Protection → Manage Settings → Tamper Protection → Off**

The tool detects Tamper Protection status and warns you if it's still on. Operations will still run, but Windows will silently revert many registry changes.

### Dry Run Mode

Check the **Dry Run** checkbox before clicking Disable or Enable. The tool will log exactly what it *would* do without making any changes. Useful for auditing or understanding the scope before committing.

### Command Line

```powershell
# Run directly
powershell.exe -ExecutionPolicy Bypass -File "DefenderControl.ps1"
```

---

## What It Does

### Disable Operation (10 Phases)

| Phase | Action |
|---|---|
| 1 | **System Restore Point** — Creates a restore point before making changes |
| 2 | **Tamper Protection Check** — Detects and warns if Tamper Protection is blocking changes |
| 3 | **Preferences** — Disables 25 `Set-MpPreference` settings, adds wildcard exclusions for drives/extensions/processes |
| 4 | **Group Policy Registry** — Sets 19 policy keys (DisableAntiSpyware, DisableRealtimeMonitoring, SpynetReporting, etc.) |
| 5 | **Notifications & Systray** — Suppresses all Defender notifications, hides system tray icon, disables SecurityHealth autostart |
| 6 | **Scheduled Tasks** — Disables 5 Defender tasks (Cache Maintenance, Cleanup, Scan, Verification, ExploitGuard) |
| 7 | **Services** — Sets `Start=4` (Disabled) for 8 services with permission escalation, strips PPL flags from 4 core services |
| 8 | **Context Menus** — Removes "Scan with Microsoft Defender" from right-click menus |
| 9 | **Additional** — Disables SmartScreen, suppresses signature auto-updates |
| 10 | **Processes** — Kills non-protected processes, logs PPL status for MsMpEng |

### Enable Operation (7 Phases)

| Phase | Action |
|---|---|
| 1 | **Remove Policies** — Deletes entire Defender policy registry tree |
| 2 | **Restore Preferences** — Restores 24 settings to defaults, clears all exclusions |
| 3 | **Restore Services** — Sets default start types, restores PPL flags, starts services |
| 4 | **Scheduled Tasks** — Re-enables all 5 tasks |
| 5 | **Context Menus & Systray** — Restores context menu GUIDs, autostart, notifications, SmartScreen |
| 6 | **Signature Update** — Triggers `Update-MpSignature` |
| 7 | **Verify** — Queries `Get-MpComputerStatus` to confirm restoration |

---

## What It Does NOT Do

- Does **not** touch Windows Firewall
- Does **not** delete Defender binaries or Windows components
- Does **not** modify boot configuration or safe mode settings
- Does **not** disable Windows Update
- All changes are **fully reversible** via the Enable button or System Restore

---

## Permission Escalation

Defender service registry keys (WinDefend, WdFilter, etc.) are protected even from Administrators. The tool uses a 4-level escalation chain:

1. **Direct write** via `Set-ItemProperty` — works for unprotected keys
2. **Take ownership + .NET handle** — P/Invoke `SeTakeOwnershipPrivilege`, set owner to Administrators SID, grant FullControl, write via `RegistryKey.SetValue()`
3. **reg.exe** — Command-line registry editor sometimes bypasses PowerShell permission constraints
4. **SYSTEM scheduled task** — Creates a one-shot task running as SYSTEM to execute `reg.exe add`, verifies the write, then cleans up

The log shows exactly which method succeeded for each key.

---

## Known Limitations

- **MsMpEng.exe** (Antimalware Service Executable) runs as a Protected Process Light (PPL) and **cannot be killed** in the current session. Once services are disabled and PPL flags are stripped, it will not restart after reboot.

- **Tamper Protection** will silently revert registry changes if left on. The tool detects this and warns you, but cannot programmatically disable it.

- **Windows Home editions** lack Group Policy support. Phase 4 registry keys will still be written but may have reduced effectiveness.

- **Checkpoint-Computer** (System Restore) is throttled to one restore point per 24 hours by Windows. If one was created recently, the tool logs a warning and continues.

- **Some heavily locked service keys** may resist all 4 escalation methods. In this case, the only remaining option is Safe Mode, which is outside the scope of this tool.

---

## Log Colors

| Color | Meaning |
|---|---|
| 🔵 Blue | Informational messages |
| 🟢 Green | Successful operations |
| 🟠 Orange | Warnings (non-fatal) |
| 🔴 Red | Errors (operation failed) |
| 🟣 Purple | Phase headers |
| ⚫ Gray | Verbose diagnostics |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is intended for system administrators, IT professionals, and power users who understand the security implications of disabling endpoint protection. Disabling Defender leaves your system vulnerable to malware.

**Use at your own risk.** Always ensure you have alternative security measures in place when Defender is disabled.
