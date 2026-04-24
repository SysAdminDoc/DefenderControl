# Changelog

All notable changes to DefenderControl will be documented in this file.

## Unreleased

### Added
- CLI mode with `-Mode Status|Health|Verify` for read-only state enumeration
- `-Json` flag emits stable JSON (single object) for automation pipelines
- `-Silent`, `-DryRun`, `-NoRestorePoint`, `-NoReboot`, `-Help` CLI flags
- Stable CLI exit codes: 0 success / 1 partial / 2 tamper-blocked / 3 safe-mode / 4 usage
- `Get-DefenderState` shared query function used by GUI dashboard and CLI
- Extended Health mode: per-service PPL flag enumeration, scheduled task state,
  policy-key values, third-party AV detection via Security Center

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
