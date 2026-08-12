# DefenderControl Roadmap

Actionable work only. Historical and completed roadmap material is archived in CHANGELOG.md; blocked work is kept in Roadmap_Blocked.md.

## Actionable Items

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
