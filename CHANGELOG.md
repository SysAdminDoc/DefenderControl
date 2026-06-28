# Changelog

All notable changes to DefenderControl will be documented in this file.

## Unreleased

## [v3.3.2] - 2026-06-28

### Fixed
- Undo manifest replay is now lossless for registry transactions: manifests
  record prior value existence and registry value kind, and Enable replays
  transactions in reverse order to restore set, remove, and prior-absence cases.

## [v3.3.1] - 2026-06-27

### Fixed
- Background runspace failures now surface in the GUI log/status, write a
  crash log under `%ProgramData%\DefenderControl\logs\`, and emit Application
  event ID 9001 when event logging is available.

## [v3.3.0] - 2026-06-19

### Added
- **Portable ZIP release asset**: `.factory/build-release.ps1` cleans `dist/`,
  bundles `DefenderControl.ps1`, `README.md`, and `LICENSE` into
  `DefenderControl-v3.3.0.zip`, and writes release checksums beside the ZIP.
- **PPL status dashboard tiles**: live dashboard now shows Protected Process
  Light (PPL) status for MsMpEng (WinDefend), WdFilter/WdBoot (combined tile),
  and WdNisDrv. Color-coded: green = Protected, red = Stripped, gray = Not Set,
  orange = Partial (mixed state across WdFilter and WdBoot).
- **Event Log source for SIEM**: registers an `DefenderControl` event log source
  under the Application log. Every Disable/Enable operation writes structured
  events (IDs 1001-1004 for Disable, 2001-2004 for Enable) so SIEM pipelines
  can track every action. Non-fatal if registration fails (e.g. non-admin
  first-run).
- **Atomic transaction log**: every registry write via `Set-RegValue`,
  `Remove-RegValue`, and `Set-ProtectedRegValue` now records a before/after
  pair (timestamp, operation, path, name, before-value, after-value, method,
  success) into a concurrent queue that gets persisted into the manifest JSON
  under `transactionLog[]`.
- **Unified undo manifest replay**: the Enable operation now searches for the
  latest Disable manifest in `%ProgramData%\DefenderControl\manifests\` and
  replays its transaction log to restore original registry values before
  applying defaults. The replay summary (source file, restored count, failed
  count) is recorded in the Enable manifest under `undoReplay`.

## [v3.2.1] - 2026-04-24

### Fixed
- Running the script from PowerShell 7 (pwsh.exe) no longer errors out with
  "Wrong PowerShell Edition". The script now detects PS 7 / Core and
  auto-relaunches itself under Windows PowerShell 5.1 (`powershell.exe`) with
  all original arguments preserved. CLI mode waits synchronously so stdout /
  stderr / exit codes return to the caller; GUI mode fires a new window. If
  the caller isn't already elevated, the re-launch also handles UAC.

## [v3.2.0] - 2026-04-24

### Added
- CLI mode with `-Mode Status|Health|Verify|Manifest` for read-only state
- `-Json` flag emits stable JSON (single object) for automation pipelines
- `-Silent`, `-DryRun`, `-NoRestorePoint`, `-NoReboot`, `-Help` CLI flags
- Stable CLI exit codes: 0 success / 1 partial / 2 tamper-blocked / 3 safe-mode / 4 usage
- `Get-DefenderState` shared query function used by GUI dashboard and CLI
- Extended Health mode: per-service PPL flag enumeration, scheduled task state,
  policy-key values, third-party AV detection via Security Center
- **Firewall integrity guard**: Disable/Enable both snapshot Get-NetFirewallProfile
  state + mpssvc/BFE service state before the first change and verify after the
  last change. Any divergence is logged as an ERROR so the "firewall untouched"
  guarantee is now machine-checked, not just documented.
- **Third-party AV pre-flight**: Phase 0 of Disable queries the Security Center
  WMI namespace (`root\SecurityCenter2`) and warns prominently when no
  non-Microsoft AV is registered. The operation still proceeds so air-gapped /
  sandbox use cases aren't blocked.
- **Undo/audit manifest**: every Disable/Enable persists a JSON manifest under
  `%ProgramData%\DefenderControl\manifests\<operation>-<timestamp>.json` with
  schema version, dry-run flag, firewall before/after, third-party AV list,
  phases completed. `-Mode Manifest` prints the latest manifest; `-Json` emits
  raw.
- **Verification suite**: `-Mode Verify` is now a pass/fail assertion pass
  rather than a Health alias. `-Expect Enabled` asserts RTP/AV/service/GP match
  the "fully enabled" shape; `-Expect Disabled` asserts at least one signal
  confirms disable; `-Expect Auto` (default) infers from current effective
  state. JSON output shape:
  `{expectation, overall, failCount, checks: [{name, expected, actual, result}]}`.
- **EICAR synthetic detection test**: opt-in via `-Mode Verify -Eicar -Force`.
  Writes the standard EICAR AV-signature test string to a GUID-keyed file under
  `$env:TEMP\DefenderControl-Verify`, waits 2.5s, and reports whether Defender
  quarantined it. The check is gated behind `-Force` and the path is always
  cleaned up on exit.
- New exit code `5` for verification failure (distinct from `1` partial).

### Changed
- Self-elevation now forwards all original arguments through the UAC re-launch
  so CLI invocations survive elevation
- WPF assemblies no longer load when running in CLI mode (faster startup)

### Fixed
- README hero image referenced a deleted `icon.svg` asset

## [v3.1.0] - 2026-03-18

- Live status dashboard, Tamper Protection guidance, scheduled re-enable, log panel

## [v3.0.0] - initial

- Initial WPF GUI with async disable/enable, log panel, dry run mode
