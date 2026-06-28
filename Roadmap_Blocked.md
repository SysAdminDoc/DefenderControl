# Blocked / Deferred Roadmap Items

Items moved here from ROADMAP.md because they are blocked by external dependencies, require infrastructure not available, or are deferred pending a larger effort.

## Blocked

### Publish v3.3.0 Release Asset
- Create the GitHub `v3.3.0` release and attach `dist\DefenderControl-v3.3.0.zip` plus `dist\SHA256SUMS.txt`
- **Blocker:** GitHub CLI token for `SysAdminDoc` is invalid; release creation requires re-authentication or a valid token

### Authenticode Signing
- Sign the `.ps1` + GUI launcher; publish SHA256SUMS alongside each release
- **Blocker:** Requires a code signing certificate (purchased or organizational)

### Install-Module PSGallery Publish
- `Install-Module DefenderControl` PSGallery publish path
- **Blocker:** Requires PSGallery account setup, module manifest, packaging pipeline

### Safe Mode Bootstrap
- Self-schedule a one-shot task that runs the script in Safe Mode for keys that resist all 4 escalation methods
- **Blocker:** Needs elevated test VM for validation; modifying boot configuration is high-risk

### Auto-Reboot Suppression (BitLocker)
- Suppress reboot when BitLocker recovery-key prompt would interrupt
- **Blocker:** Requires BitLocker-enabled test environment

### Intune Win32 Detection Script
- Detection script + remediation pair for Intune deployment
- **Blocker:** Requires Intune-enrolled test environment

### Group Policy ADMX Template
- ADMX template stub that disables Defender via GPO for GPO-first deployment shops
- **Blocker:** Requires AD/GPO test environment for validation

## Deferred (Large Effort)

### Catppuccin Mocha Restyle
- Restyle WPF to Catppuccin Mocha palette (match DefenderShield / DisableDefender)
- **Reason:** Bigger UI rework; all color constants, XAML resources, and brush references need updating

### Phase-Level -Only / -Skip Flags
- Flags mirroring the 10-phase pipeline for surgical control
- **Reason:** Requires runspace variable injection + GUI list UI; refactoring Queue-* family for CLI path

### Live Telemetry Counter
- How many ETW Microsoft-Antimalware events observed in last N seconds to visually prove real-time is off/on
- **Reason:** Requires ETW trace session management, complex implementation

### Log Pane Filter Chips
- Per-line filter chips (Phase / Method / Service), copy-as-markdown for bug reports
- **Reason:** Requires WPF custom control development; part of larger UI rework

### CLI -Mode Disable / -Mode Enable
- Full CLI parity for mutating operations
- **Reason:** Requires refactoring runspace plumbing so logging works without WPF. The `Queue-*` family currently assumes a `$LogQueue` WPF queue. Approach: add a `Write-OpLog` abstraction that routes to console OR queue. Significant refactor.
