# DefenderControl Roadmap

PowerShell WPF Defender disable/enable utility with 4-level permission escalation and PPL flag stripping. Tracks work beyond the current release.

## Current Status

No actionable roadmap items remain. Blocked or deferred items are tracked in `Roadmap_Blocked.md`.

## Research-Driven Additions

- [ ] P0 - Make undo manifest replay lossless
  Why: Replay skips removed values and absent-before values, and direct replay can fail on protected keys.
  Evidence: `DefenderControl.ps1:1464`, `DefenderControl.ps1:1479`, `DefenderControl.ps1:2432`
  Touches: `Set-RegValue`, `Remove-RegValue`, `Set-ProtectedRegValue`, `Save-DefenderControlManifest`, enable replay logic
  Acceptance: Transaction entries record value kind and existed-before state; replay restores set, remove, absence, and protected-key cases with test coverage.
  Complexity: M

- [ ] P1 - Add Defender for Endpoint and passive-mode preflight
  Why: Microsoft documents `AMRunningMode`, `ForceDefenderPassiveMode`, EDR Block Mode, and managed Tamper Protection behavior that can change disable/enable results.
  Evidence: Microsoft Defender Antivirus compatibility docs; `DefenderControl.ps1:318` state model lacks these fields.
  Touches: `Get-DefenderState`, Health/Verify JSON, dashboard tiles, manifests, disable pre-flight warnings
  Acceptance: Health JSON and GUI show Normal/Passive/EDR Block/Disabled, MDE/passive-mode registry signals, platform version, and a clear managed-device warning before mutation.
  Complexity: M

- [ ] P1 - Add support bundle export
  Why: Users need one artifact for failed disables/enables, and Microsoft provides `MpCmdRun.exe -GetFiles` for Defender diagnostics.
  Evidence: Microsoft Defender diagnostic collection docs; existing manual log export in `DefenderControl.ps1:2839`
  Touches: `DefenderControl.ps1` export handler, manifests, event-log helper, CLI read-only surface
  Acceptance: GUI and CLI can generate a ZIP containing Health JSON, latest manifest, operation log, recent DefenderControl event-log entries, and optional `MpSupportFiles.cab`.
  Complexity: M

- [ ] P1 - Formalize local validation harness
  Why: Current `.factory` scripts cover isolated state/verify paths but not runspace shared-function parity, linting, or transaction replay.
  Evidence: `.factory\test-state.ps1`; `.factory\test-verify.ps1`; Pester and PSScriptAnalyzer docs
  Touches: `.factory`, `DefenderControl.ps1`
  Acceptance: One local test command runs parse checks, SharedFunctions extraction/parity checks, verify/state tests, transaction replay tests, and PSScriptAnalyzer with documented suppressions.
  Complexity: M

- [ ] P2 - Add WPF accessibility metadata
  Why: The dashboard is color-heavy and the XAML lacks broad `AutomationProperties.Name` coverage.
  Evidence: `DefenderControl.ps1:981`; Microsoft WPF AutomationProperties guidance
  Touches: XAML here-string in `DefenderControl.ps1`
  Acceptance: Main buttons, checkboxes, combo boxes, dashboard values, warning panel, and log controls expose stable automation names and non-color state text.
  Complexity: S

- [ ] P2 - Add manifest retention and redaction controls
  Why: Manifests and logs include host, AV provider, registry, and phase data, but no retention or redaction workflow exists.
  Evidence: `DefenderControl.ps1:1644`; `DefenderControl.ps1:1673`; `DefenderControl.ps1:2839`
  Touches: manifest writer, manifest CLI mode, log export, support bundle export
  Acceptance: Users can list, prune, and export redacted manifests/logs; default retention is documented in-app and in CLI output.
  Complexity: M
