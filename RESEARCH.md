# Research - Defender Control

## Executive Summary
Defender Control is a portable PowerShell 5.1/WPF utility for reversible Microsoft Defender disable/enable workflows on Windows 10/11. Its strongest current shape is the safety work already present: async GUI operations, restore-point creation, firewall integrity checks, third-party AV warnings, manifests, verification mode, PPL dashboard, event-log writes, and a ZIP build harness. Top opportunities, in order: publish the already-built v3.3.0 release asset, stop swallowing background worker crashes, make manifest replay fully lossless, detect Microsoft Defender for Endpoint/passive-mode constraints before mutation, add first-class support bundles, formalize local Pester/PSScriptAnalyzer validation, add WPF accessibility metadata, and add manifest retention/redaction.

## Product Map
- Core workflows: GUI status refresh, dry-run disable, reversible enable, scheduled re-enable, read-only CLI status/health/verify/manifest output.
- User personas: local administrators, imaging/kiosk technicians, benchmarkers, lab operators, and power users who understand the risk of operating without Defender.
- Platforms and distribution: Windows 10 1809+ and Windows 11, Windows PowerShell 5.1, single `.ps1` plus portable ZIP built by `.factory/build-release.ps1`.
- Key integrations and data flows: Defender PowerShell cmdlets, protected HKLM service/policy registry writes, Task Scheduler SYSTEM tasks, Windows Security Center WMI, Windows Event Log, `%ProgramData%\DefenderControl\manifests\`.

## Competitive Landscape
- ConfigureDefender: strong at policy presets, ASR/Controlled Folder Access/cloud-level exposure, and explaining GPO/Home-edition caveats. Learn from its capability matrix and policy conflict warnings; avoid drifting from Defender Control's disable/enable focus into a general Defender hardening console.
- Defender Remover: strong at showing demand for deep removal, ISO/OOBE flows, command arguments, and Windows-update drift recovery. Learn from its update-drift FAQ; avoid destructive component removal and Security UI deletion because this repo promises reversibility.
- Sordum Defender Control: strong at a tiny status-first portable UI, one-click Defender settings launch, many languages, and clear color status. Learn from its repair/status simplicity; avoid encrypted/passworded distribution and false-positive workaround advice that adds Defender exclusions for the tool itself.
- DefenderUI: strong at surfacing hidden Defender features, profiles, multilingual UI, silent install/management, WDAC/Sandbox tie-ins. Learn from its diagnostics and enterprise-management posture; avoid WDAC policy management because it changes the product category.
- Chris Titus Tech WinUtil and SophiApp: strong at presets, package-manager distribution, and broad Windows tweak ergonomics. Learn from repeatable preset reporting and portable delivery; avoid broad debloat/privacy tweaks because this repo intentionally touches Defender only.
- O&O ShutUp10++: strong at recommendations, portable execution, Windows 10/11 privacy setting grouping, and Premium continuous setting restore after Windows updates. Learn from recommendation tiers and post-update drift monitoring; avoid background resident monitoring unless explicitly implemented as an opt-in maintenance task.

## Security, Privacy, and Reliability
- [Verified] Public releases are stale: GitHub shows latest release `v3.2.1`, while repo files and tags are `v3.3.0`; local `dist\DefenderControl-v3.3.0.zip` exists but is not the public install asset.
- [Verified] Background worker exceptions are swallowed at `DefenderControl.ps1:1749`, so a runspace crash can leave only an enabled refresh button with no durable failure record.
- [Verified] Undo replay at `DefenderControl.ps1:2432` skips removed entries and entries with `Before = $null`, and uses direct `Set-ItemProperty`; future protected-key or absence-restoration cases can fail to restore the exact prior state.
- [Verified] Manifest and log data include host name, OS build, third-party AV names, registry paths, and phase results; there is no visible retention/redaction control.
- [Verified] Microsoft documents that tamper-protected settings can appear to change but be blocked, and that Group Policy changes can be ignored under Tamper Protection; the app warns, but does not distinguish consumer Tamper Protection from managed Defender for Endpoint state.
- [Verified] `Get-DefenderState` does not include `AMRunningMode`, `ForceDefenderPassiveMode`, onboarded/managed Defender for Endpoint indicators, or platform version, even though Microsoft documents passive, active, disabled, and EDR Block Mode states.
- [Likely] Accessibility is thin: the XAML buttons and dashboard rely mostly on visible text/color and have no `AutomationProperties.Name` coverage.

## Architecture Assessment
- Keep the single-file distribution, but add local tests that parse both the main script and `$script:SharedFunctions`; runspace-only syntax errors are the highest-risk maintenance pattern called out in the repo working notes.
- `Start-BackgroundWork` should route `EndInvoke` exceptions to the GUI log, status strip, event log, and a crash log under `%ProgramData%\DefenderControl\logs\`.
- Transaction logging should store `ExistedBefore`, registry value kind, protected-write method, and replay action so absence and removals can be restored deterministically.
- `Get-DefenderState`, Health mode, dashboard, manifests, and Verify mode should share one expanded state model for Tamper Protection, `AMRunningMode`, Security Center provider, MDE/passive mode, platform version, and GPO conflict signals.
- `.factory/test-state.ps1` and `.factory/test-verify.ps1` are useful, but not enough for a safety-critical single script; add Pester tests plus PSScriptAnalyzer with targeted suppressions for known queue verb warnings.
- Add a "Support Bundle" command that collects current Health JSON, latest manifest, exported operation log, event-log entries, and optionally Microsoft `MpCmdRun.exe -GetFiles` output.

## Rejected Ideas
- Component removal / Windows Security app removal: rejected because Defender Remover's approach conflicts with this repo's reversible, no-binary-deletion promise.
- ISO/OOBE customization: rejected for now because it changes distribution from a live host utility to image engineering; Defender Remover already covers that niche.
- Fake third-party AV/WSC registration: rejected because community research shows it is undocumented, fragile, and commonly classified as malware-like behavior.
- WDAC/Sandbox management: rejected because DefenderUI Pro covers that adjacent hardening space and it would dilute the Defender disable/enable workflow.
- Always-on background drift monitor: rejected as a default because this repo is portable and nonresident; an opt-in scheduled verification task is a better fit.
- Broad Windows privacy/debloat presets: rejected because WinUtil, SophiApp, and O&O ShutUp10++ already serve that domain and Defender Control explicitly avoids non-Defender mutations.
- Full i18n pass: deferred unless the UI is reorganized first; Sordum and DefenderUI prove multilingual demand, but the current audience and single-script maintenance model favor safety work first.
- Plugin ecosystem, mobile, multi-user, and migration features: rejected because the tool is a local elevated Windows maintenance utility with no server-side data model or cross-device state.

## Sources
### Project
- https://github.com/SysAdminDoc/DefenderControl
- https://github.com/SysAdminDoc/DefenderControl/releases
- https://github.com/SysAdminDoc/DefenderControl/releases/tag/v3.2.1

### Competitors and Adjacent Tools
- https://github.com/AndyFul/ConfigureDefender
- https://github.com/ionuttbara/windows-defender-remover
- https://www.sordum.org/9480/defender-control-v2-1/
- https://www.defenderui.com/
- https://github.com/ChrisTitusTech/winutil
- https://github.com/Sophia-Community/SophiApp
- https://www.oo-software.com/en/shutup10

### Platform and Tooling
- https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection
- https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility
- https://learn.microsoft.com/en-us/defender-endpoint/collect-diagnostic-data
- https://pester.dev/docs/quick-start
- https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/overview?view=ps-modules
- https://learn.microsoft.com/en-us/accessibility-tools-docs/items/wpf/control_automationproperties

### Community and Security Signal
- https://www.reddit.com/r/WindowsHelp/comments/1hzsshp/win11_24h2_defender_keeps_enabling_itself_over/
- https://serverfault.com/questions/873522/how-do-i-completely-turn-off-windows-defender-from-powershell
- https://stackoverflow.com/questions/48960190/powershell-set-mppreference-disablerealtimemonitoring-true-not-working-correct
- https://news.ycombinator.com/item?id=43959403
- https://learn.microsoft.com/en-us/answers/questions/4008641/cannot-enable-tamper-protection-as-it-is-managed-b
- https://learn.microsoft.com/en-us/answers/questions/3882884/cannot-turn-off-tamper-protection
- https://techcommunity.microsoft.com/discussions/windowsserver/turning-off-tamper-protection-on-workstations/4480979
- https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/defense_evasion_disabling_windows_defender_powershell
- https://www.alteredsecurity.com/post/disabling-tamper-protection-and-other-defender-mde-components

## Open Questions
- Which Windows builds and Defender platform versions are available for validation, especially Windows 11 24H2/25H2 and managed Defender for Endpoint devices?
- Is publishing the `v3.3.0` GitHub release blocked by credentials only, or was it intentionally held back after tagging?
