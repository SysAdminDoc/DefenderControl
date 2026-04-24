# DefenderControl Roadmap

PowerShell WPF Defender disable/enable utility with 4-level permission escalation and PPL flag stripping. Tracks work beyond the current release.

## Planned Features

### Core Operations
- Unified undo manifest (JSON, mirror Debloat-Win11) so `Enable` can replay the exact inverse of a specific `Disable` run
- Atomic transaction log — every registry write appends a before/after pair so partial failures are fully reversible
- Phase-level `-Only` / `-Skip` flags mirroring the 10-phase pipeline for surgical control
- Verification suite after `Disable`: runs `Get-MpComputerStatus` and a synthetic EICAR test (opt-in) to confirm real-time is actually off
- Safe Mode bootstrap: self-schedule a one-shot task that runs the script in Safe Mode for keys that resist all 4 escalation methods

### UI
- Restyle WPF to Catppuccin Mocha (match DefenderShield / DisableDefender) instead of the current palette
- Dashboard tiles showing PPL status per service (MsMpEng, WdFilter, WdBoot, WdNisDrv)
- Live telemetry counter (how many ETW Microsoft-Antimalware events observed in last N seconds) to visually prove real-time is off/on
- Tamper Protection hand-holding: one-click launch of `ms-settings:windowsdefender` with on-screen instructions
- Log pane: per-line filter chips (Phase / Method / Service), copy-as-markdown for bug reports

### CLI
- Full CLI parity with the GUI: `-Mode Disable|Enable|Status|Verify`, `-DryRun`, `-Silent`, `-NoRestorePoint`, `-NoReboot`
- Structured JSON output with `-Json` for piping into other automation
- Exit codes: 0 success, 1 partial, 2 blocked by Tamper Protection, 3 blocked by Safe Mode needed
- `Install-Module DefenderControl` PSGallery publish path

### Safety
- Firewall integrity pre/post guard (adopt DisableDefender's refuse-list pattern) — abort if mpssvc/BFE get touched
- Pre-flight network check: warn when Defender is disabled and no third-party AV is detected (Registry: `HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av`)
- Auto-reboot suppression when BitLocker recovery-key prompt would interrupt
- Health scan mode: enumerate every known Defender component and report current state without modifying

### Integrations
- Intune Win32 detection script + remediation pair
- Group Policy ADMX template stub that disables Defender via GPO — for shops that want GPO-first deployment
- Event Log source (`DefenderControl`) so SIEM pipelines can track every disable/enable action

### Packaging
- Authenticode-sign the `.ps1` + GUI launcher; publish SHA256SUMS alongside each release
- Portable ZIP release asset with the script + README + LICENSE bundled
- Per-release changelog bullets that match the CLAUDE.md version strings

## Competitive Research

- **DisableDefender (sibling repo)** — Adjacent project in the same repo family; share the refuse-list firewall guard, the 4-level escalation code, and the Catppuccin theme.
- **DefenderControl by Sordum** (closed-source reference tool) — Benchmark for the "single button" UX; DefenderControl here wins on auditability (open source + logs) and loses on polish — close that gap with the Catppuccin rework.
- **Windows-Defender-Remover (ionuttbara)** — Aggressive removal via DISM; reference for the nuclear path, but `DefenderControl` positions as the reversible sibling — keep the boundaries clear.
- **Powershell-Scripts / privacy.sexy** — Comprehensive catalog of Defender keys; use as a source of truth for Phase 4 coverage and auto-sync missing keys weekly via an Action.

## Nice-to-Haves

- Optional watchdog scheduled task that re-applies disable settings after every reboot (opt-in, for kiosk/imaging machines)
- "Explain mode" — hover any registry key in the log to see the admx.help description
- Preset profiles (Developer, Kiosk, Medical Imaging, VM Host) that pick the right subset of phases
- Diff view comparing two Status snapshots so a support engineer can see what changed between runs
- HTML report export of an entire run suitable for attaching to an incident ticket
- Remote mode (`-ComputerName`) via WinRM to operate on a fleet (with opt-in only and heavy warning)

## Open-Source Research (Round 2)

### Related OSS Projects
- **ionuttbara/windows-defender-remover** — https://github.com/ionuttbara/windows-defender-remover — Covers the full Defender surface: Security App, VBS, SmartScreen, Web-Threat, App Guard, Driver Block List, Settings-app page. Also ships ISO-maker flow.
- **es3n1n/defendnot** — https://github.com/es3n1n/defendnot — Undocumented WSC (Windows Security Center) API trick: registers a fake AV so Defender auto-disables itself. Requires binary-on-disk persistence.
- **pgkt04/defender-control** — https://github.com/pgkt04/defender-control — Open-source spiritual successor to Sordum's now-discontinued tool.
- **zoicware/DefenderProTools** — https://github.com/zoicware/DefenderProTools — DISM + TrustedInstaller approach for removing Defender from ISOs; brute-force registry nuke.
- **S12cybersecurity/WinDefenderKiller** — https://github.com/S12cybersecurity/WinDefenderKiller — Registry disable + BYOVD process termination; reference for advanced bypass research.
- **Nolan-Burkhart/defender-disabler** — https://github.com/Nolan-Burkhart/defender-disabler — Minimal C++ registry-only reference implementation.
- **disable-windows-defender/disable-windows-defender.github.io** — https://github.com/disable-windows-defender/disable-windows-defender.github.io — Pure `.reg` file pair (disable/restore); useful as a minimum-viable fallback baked into DefenderControl.

### Features to Borrow
- WSC-API fake-AV registration approach as an alternate disable strategy, with clear trade-offs documented (needs persistent binary, flagged as `VirTool:Win64/Defnot.A`) — borrow from `defendnot`. Ship as opt-in "Method B".
- TrustedInstaller-mediated key writes for tamper-protection-enabled systems — borrow from `DefenderProTools` and Sordum's PowerRun technique. Keep the user's existing ACL-takeover path and add TI as fallback.
- ISO-maker integration so images can be pre-hardened — borrow from `ionuttbara/windows-defender-remover`.
- Expanded disable surface beyond just Defender AV: SmartScreen, Web-Threat service, Driver Block List, App Guard, VBS — borrow from `ionuttbara/windows-defender-remover` checklist.
- BYOVD (bring-your-own-vulnerable-driver) preflight warning documented in README even if not shipped — borrow from `WinDefenderKiller`.
- "Disable + Restore" paired `.reg` file export so users can apply/undo without the GUI — borrow from `disable-windows-defender.github.io`.
- Build-from-source instructions prominently documented because `.exe` releases are flagged by AV — borrow from `ionuttbara/windows-defender-remover` README.

### Patterns & Architectures Worth Studying
- `defendnot`'s WSC API reverse-engineering: undocumented COM interface, NDA-gated docs; novel primitive worth adding to DefenderControl's method matrix.
- `ionuttbara/windows-defender-remover`'s service/feature checklist — use as a coverage matrix for DefenderControl's 10-phase disable to spot gaps.
- Sordum Defender Control's 4-axis approach (direct keys + policy keys + Systray stop + mpcmdrun block + service startup edits) as the minimum table of ops — already mostly in DefenderControl; verify parity.
- `r12w4n/disable-defender`'s wrapper pattern (orchestrates external tools rather than reimplementing) — alternate distribution model if upstream maintenance burden becomes too high.
