# Changelog

All notable changes to DefenderControl will be documented in this file.

## Unreleased

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
