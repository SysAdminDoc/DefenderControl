<#
.SYNOPSIS
    Defender Control v3.3.3 - Comprehensive Microsoft Defender Disable/Enable Utility

.DESCRIPTION
    Professional WPF GUI + CLI tool to fully disable or re-enable Microsoft Defender
    on Windows 10/11. Uses a multi-phase approach covering preferences, group policy
    registry keys, services (with permission escalation), scheduled tasks, context
    menus, notifications, SmartScreen, and Protected Process Light (PPL) flags.

    WHAT THIS TOOL DOES:
      - Disables real-time protection, cloud delivery, behavior monitoring, etc.
      - Sets group policy registry keys to prevent Defender from re-enabling
      - Disables and stops Defender services (WinDefend, WdFilter, WdBoot, etc.)
      - Strips PPL flags so protected processes don't survive reboot
      - Disables scheduled tasks, context menus, notifications, SmartScreen
      - Creates a System Restore Point before disabling (recommended)
      - Live status dashboard showing all Defender component states
      - Tamper Protection detection with step-by-step disable guidance
      - Scheduled re-enable: auto re-enable Defender after 1-24 hours
      - CLI: read-only Status / Health / Verify / Manifest / SupportBundle modes with JSON output

    WHAT THIS TOOL DOES NOT DO:
      - Does NOT touch Windows Firewall (completely unaffected)
      - Does NOT delete Defender binaries or components
      - All changes are fully reversible via the Enable button

    REQUIREMENTS:
      - Windows 10 (1809+) or Windows 11
      - Windows PowerShell 5.1 (not PowerShell 7 - WPF requires it)
      - Administrator privileges (self-elevates via UAC)
      - Tamper Protection should be OFF for full effectiveness:
        Windows Security > Virus & Threat Protection > Manage Settings > Tamper Protection

    KNOWN LIMITATIONS:
      - MsMpEng.exe (Antimalware Service) is PPL-protected and cannot be killed
        in the current session. It will not restart after reboot once disabled.
      - If Tamper Protection is ON, registry changes will be reverted by Windows.
        The tool detects this and warns you.
      - Some operations on heavily locked service keys may require Safe Mode as
        a last resort (the tool tries 4 escalation methods before giving up).

.PARAMETER Mode
    When supplied, runs in CLI (no-GUI) mode. Values:
      Status  - read-only snapshot of Defender state (exit 0)
      Health  - extended read-only enumeration (services, PPL, tasks, policy keys)
      Verify  - pass/fail assertion against enabled or disabled Defender state
      SupportBundle - collect health, manifest, operation log, and event data into a ZIP
      Disable - reserved (CLI disable not yet implemented; use GUI)
      Enable  - reserved (CLI enable not yet implemented; use GUI)

.PARAMETER Json
    Emit a single JSON object to stdout instead of human-readable text.
    Only valid with -Mode. JSON is stable across releases; keys never renamed.

.PARAMETER Silent
    Suppress non-essential output in CLI mode.

.PARAMETER DryRun
    Simulate changes without applying them (GUI and CLI both honor this).

.PARAMETER NoRestorePoint
    Skip creation of the System Restore Point (CLI-only).

.PARAMETER NoReboot
    Suppress the reboot prompt even when changes require it (CLI-only).

.PARAMETER OutputPath
    Destination ZIP path for -Mode SupportBundle. Defaults to the current user's Desktop.

.PARAMETER MpSupportFiles
    With -Mode SupportBundle or the GUI, run MpCmdRun.exe -GetFiles and include the
    resulting Microsoft Defender diagnostic CAB when available.

.PARAMETER Help
    Print CLI usage and exit.

.NOTES
    Author : SysAdminDoc
    License: MIT
    Repo   : https://github.com/SysAdminDoc/DefenderControl

    CLI exit codes:
      0 - success
      1 - partial success (some operations failed)
      2 - blocked by Tamper Protection
      3 - Safe Mode required for the requested operation
      4 - usage error / unsupported OS / missing elevation
      5 - verification failure

.LINK
    https://github.com/SysAdminDoc/DefenderControl
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Disable','Enable','Status','Health','Verify','Manifest','SupportBundle')]
    [string]$Mode,

    [string]$OutputPath,

    [switch]$ListManifests,
    [switch]$PruneManifests,
    [switch]$Redact,
    [ValidateRange(1,3650)]
    [int]$RetentionDays = 30,

    [ValidateSet('Enabled','Disabled','Auto')]
    [string]$Expect = 'Auto',

    [switch]$DryRun,
    [switch]$Silent,
    [switch]$Json,
    [switch]$Help,
    [switch]$NoRestorePoint,
    [switch]$NoReboot,
    [switch]$Eicar,
    [switch]$Force,
    [switch]$MpSupportFiles
)

# ==================================================================================
#  CLI EXIT CODES (shared by GUI + CLI)
# ==================================================================================
$script:EXIT_OK             = 0
$script:EXIT_PARTIAL        = 1
$script:EXIT_TAMPER_BLOCKED = 2
$script:EXIT_SAFEMODE       = 3
$script:EXIT_USAGE          = 4
$script:EXIT_VERIFY_FAIL    = 5

$script:IsCliMode = [bool]$Mode -or $Help.IsPresent

# ==================================================================================
#  -Help short-circuits before any assemblies or elevation
# ==================================================================================
if ($Help.IsPresent) {
    $usage = @'
Defender Control - CLI Usage

    DefenderControl.ps1                          Launch the WPF GUI
    DefenderControl.ps1 -Mode Status             Print current Defender state
    DefenderControl.ps1 -Mode Status -Json       Emit state as JSON
    DefenderControl.ps1 -Mode Health             Extended read-only state enum
    DefenderControl.ps1 -Mode Health -Json       Extended state as JSON
    DefenderControl.ps1 -Mode Manifest            Print the latest undo manifest
    DefenderControl.ps1 -Mode Manifest -Json      Latest manifest as JSON
    DefenderControl.ps1 -Mode Manifest -ListManifests
                                                   List manifests and retention policy
    DefenderControl.ps1 -Mode Manifest -PruneManifests -RetentionDays 30
                                                   Prune old manifests safely
    DefenderControl.ps1 -Mode Manifest -Redact -OutputPath redacted.zip
                                                   Export redacted manifests and logs
    DefenderControl.ps1 -Mode SupportBundle       Create a diagnostic support ZIP
    DefenderControl.ps1 -Mode SupportBundle -MpSupportFiles
                                                   Include MpCmdRun diagnostic CAB
    DefenderControl.ps1 -Mode Verify              Assert Defender state matches
                                                  an expected shape (auto-inferred)
    DefenderControl.ps1 -Mode Verify -Expect Enabled   Assert fully enabled
    DefenderControl.ps1 -Mode Verify -Expect Disabled  Assert fully disabled
    DefenderControl.ps1 -Mode Verify -Eicar -Force     Include EICAR detection test
                                                       (writes + cleans a harmless
                                                       AV-signature test file)
    DefenderControl.ps1 -Help                    Show this usage

Flags:
    -Silent         Suppress non-essential CLI output
    -DryRun         Simulate without applying (GUI + CLI)
    -NoRestorePoint Skip restore-point creation (CLI-only)
    -NoReboot       Suppress reboot prompt (CLI-only)
    -Expect         Verify assertion target: Enabled | Disabled | Auto (default)
    -Eicar          Opt-in EICAR synthetic detection test (Verify-only)
    -Force          Required with -Eicar to actually write the test file
    -OutputPath     SupportBundle destination ZIP (default: Desktop)
    -MpSupportFiles Include MpCmdRun.exe -GetFiles output in SupportBundle
    -ListManifests  List all audit manifests and the retention policy
    -PruneManifests Remove manifests outside the retention window / count
    -Redact         Export a ZIP with redacted manifest and operation logs
    -RetentionDays  Prune age limit in days (default: 30; max files: 50)

Exit codes:
    0 success   1 partial   2 tamper-blocked   3 safe-mode-needed
    4 usage-error   5 verify-fail

Note: -Mode Disable|Enable are reserved; use the GUI for mutating operations.
'@
    [Console]::Out.WriteLine($usage)
    exit $script:EXIT_OK
}

# ==================================================================================
#  ARG-FORWARD HELPER (reused by both edition-rehost and self-elevation)
# ==================================================================================
function Get-ForwardedArgString {
    $fwd = New-Object System.Collections.Generic.List[string]
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        $name = $kv.Key
        $val  = $kv.Value
        if ($val -is [System.Management.Automation.SwitchParameter]) {
            if ($val.IsPresent) { $fwd.Add("-$name") | Out-Null }
        } else {
            $fwd.Add("-$name") | Out-Null
            $fwd.Add('"' + ($val -replace '"','\"') + '"') | Out-Null
        }
    }
    $base = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($fwd.Count -gt 0) { return $base + " " + ($fwd -join ' ') }
    return $base
}

# ==================================================================================
#  POWERSHELL EDITION CHECK -- auto-relaunch under Windows PowerShell 5.1
# ==================================================================================
# WPF (PresentationFramework) requires Windows PowerShell 5.1; PS 7 / Core does
# not ship it on all installs. Instead of erroring out, we silently re-spawn
# the script under powershell.exe (WinPS 5.1), preserving all original args.
if ($PSVersionTable.PSEdition -eq 'Core') {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    $argList = Get-ForwardedArgString
    $winPs = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $winPs)) { $winPs = 'powershell.exe' }  # fall back to PATH

    try {
        if ($script:IsCliMode) {
            # CLI: wait synchronously so stdout/stderr + exit code return to caller.
            $spArgs = @{
                FilePath     = $winPs
                ArgumentList = $argList
                Wait         = $true
                PassThru     = $true
                NoNewWindow  = $true
            }
            if (-not $isAdmin) { $spArgs.Remove('NoNewWindow'); $spArgs['Verb'] = 'RunAs' }
            $proc = Start-Process @spArgs
            exit $proc.ExitCode
        } else {
            # GUI: fire-and-forget new window
            $spArgs = @{ FilePath = $winPs; ArgumentList = $argList }
            if (-not $isAdmin) { $spArgs['Verb'] = 'RunAs' }
            Start-Process @spArgs
        }
    } catch {
        if ($script:IsCliMode) {
            [Console]::Error.WriteLine("DefenderControl: requires Windows PowerShell 5.1 and $winPs could not be launched: $($_.Exception.Message)")
            exit $script:EXIT_USAGE
        }
        Add-Type -AssemblyName PresentationFramework
        [System.Windows.MessageBox]::Show(
            "This tool requires Windows PowerShell 5.1.`n`nCould not auto-launch powershell.exe.`n`nManual: powershell.exe -File `"$PSCommandPath`"",
            "Could not re-launch under Windows PowerShell", "OK", "Error") | Out-Null
    }
    exit
}

# ==================================================================================
#  SELF-ELEVATION (forwards original args so CLI mode survives UAC re-launch)
# ==================================================================================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {

    $argList = Get-ForwardedArgString
    try {
        Start-Process powershell.exe -ArgumentList $argList -Verb RunAs
    } catch {
        if ($script:IsCliMode) {
            [Console]::Error.WriteLine("DefenderControl: Administrator privileges required.")
            exit $script:EXIT_USAGE
        } else {
            Add-Type -AssemblyName PresentationFramework
            [System.Windows.MessageBox]::Show(
                "This tool requires Administrator privileges.`nPlease right-click and Run as Administrator.",
                "Elevation Required", "OK", "Error") | Out-Null
        }
    }
    exit
}

# ==================================================================================
#  ASSEMBLIES & CONSTANTS
# ==================================================================================
if (-not $script:IsCliMode) {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms
}

$script:Version    = "3.3.3"
$script:ManifestRetentionDays = 30
$script:ManifestMaxCount = 50
$script:DryRun     = [bool]$DryRun
$script:ShowVerbose = $true

# ==================================================================================
#  WINDOWS VERSION CHECK
# ==================================================================================
$script:OSBuild   = [System.Environment]::OSVersion.Version.Build
$script:OSName    = if ($script:OSBuild -ge 22000) { "Windows 11" }
                    elseif ($script:OSBuild -ge 10240) { "Windows 10" }
                    else { "Unknown" }
$script:OSDetail  = "$script:OSName (Build $script:OSBuild)"

if ($script:OSBuild -lt 10240) {
    if ($script:IsCliMode) {
        [Console]::Error.WriteLine("DefenderControl: requires Windows 10 (1809+) or Windows 11. Detected: $script:OSDetail")
        exit $script:EXIT_USAGE
    }
    [System.Windows.MessageBox]::Show(
        "This tool requires Windows 10 (1809+) or Windows 11.`n`nDetected: $script:OSDetail",
        "Unsupported Windows Version", "OK", "Error") | Out-Null
    exit
}
if ($script:OSBuild -lt 17763 -and -not $script:IsCliMode) {
    [System.Windows.MessageBox]::Show(
        "This tool requires Windows 10 version 1809 or later.`n`nDetected: $script:OSDetail`n`nSome features may not work correctly on older builds.",
        "Old Windows Build", "OK", "Warning") | Out-Null
}

# PowerShell edition check happened earlier (auto-relaunches under WinPS 5.1).
# By this point we are guaranteed to be on Windows PowerShell 5.1.

# ==================================================================================
#  EVENT LOG SOURCE (for SIEM integration)
# ==================================================================================
$script:EventLogSource = 'DefenderControl'
$script:EventLogName   = 'Application'
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($script:EventLogSource)) {
        [System.Diagnostics.EventLog]::CreateEventSource($script:EventLogSource, $script:EventLogName)
    }
    $script:EventLogReady = $true
} catch {
    # Non-fatal — event logging is best-effort
    $script:EventLogReady = $false
}

function Write-DefenderControlEvent {
    param(
        [string]$Message,
        [int]$EventId = 1000,
        [System.Diagnostics.EventLogEntryType]$EntryType = [System.Diagnostics.EventLogEntryType]::Information
    )
    if (-not $script:EventLogReady) { return }
    try {
        [System.Diagnostics.EventLog]::WriteEntry($script:EventLogSource, $Message, $EntryType, $EventId)
    } catch {}
}

function Write-DefenderControlCrashLog {
    param(
        [Parameter(Mandatory)][System.Exception]$Exception,
        [System.Management.Automation.PowerShell]$PowerShell
    )

    $logDir = Join-Path $env:ProgramData 'DefenderControl\logs'
    try {
        if (-not (Test-Path -LiteralPath $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $path = Join-Path $logDir "Crash-$stamp.log"
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add("Defender Control v$script:Version - Background Worker Crash")
        $lines.Add("Timestamp: $(Get-Date -Format 'o')")
        $lines.Add("Computer: $env:COMPUTERNAME")
        $lines.Add("OS: $script:OSDetail")
        $lines.Add("")
        $lines.Add("Exception:")
        $lines.Add($Exception.ToString())

        if ($PowerShell -and $PowerShell.Streams -and $PowerShell.Streams.Error.Count -gt 0) {
            $lines.Add("")
            $lines.Add("PowerShell error stream:")
            foreach ($err in $PowerShell.Streams.Error) {
                $lines.Add($err.ToString())
            }
        }

        [System.IO.File]::WriteAllLines($path, $lines.ToArray(), [System.Text.Encoding]::UTF8)
        return $path
    } catch {
        return $null
    }
}

# ==================================================================================
#  CLI MODE: read-only state enumeration + dispatch
# ==================================================================================
function Get-DefenderState {
    # Pure query function shared by GUI dashboard and CLI.
    # Returns a hashtable; callers decide how to render it.
    [CmdletBinding()]
    param(
        [switch]$Extended
    )

    $state = [ordered]@{
        Version                    = $script:Version
        Timestamp                  = (Get-Date).ToString('o')
        Computer                   = $env:COMPUTERNAME
        OS                         = $script:OSDetail
        OSBuild                    = $script:OSBuild
        RealTimeProtectionEnabled  = $null
        AntivirusEnabled           = $null
        AntispywareEnabled         = $null
        BehaviorMonitorEnabled     = $null
        IoavProtectionEnabled      = $null
        NISEnabled                 = $null
        OnAccessProtectionEnabled  = $null
        AMServiceEnabled           = $null
        IsTamperProtected          = $null
        AMRunningMode              = $null
        DefenderMode               = 'Unknown'
        AMProductVersion           = $null
        DefenderPlatformVersion    = $null
        AMEngineVersion            = $null
        AMServiceVersion           = $null
        AntivirusSignatureLastUpdated = $null
        DefenderEffectivelyEnabled = $false
        PolicyDisableAntiSpyware   = $null
        WinDefendStatus            = $null
        WinDefendStartType         = $null
        FirewallProfilesEnabled    = $null
        MpStatusQueryError         = $null
        ForceDefenderPassiveMode   = $null
        MDEStatusKeyPresent        = $false
        MDEOnboardingState         = $null
        MDESenseIsRunning          = $null
        MDEOrgIdPresent            = $false
        MDEOnboarded               = $false
        ManagedDefenderProductType = $null
        TPExclusions               = $null
        ManagedTamperProtection    = $false
        ManagedDevice              = $false
        ManagedDeviceWarning       = $null
    }

    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $state.RealTimeProtectionEnabled = [bool]$mp.RealTimeProtectionEnabled
        $state.AntivirusEnabled          = [bool]$mp.AntivirusEnabled
        $state.AntispywareEnabled        = [bool]$mp.AntispywareEnabled
        $state.BehaviorMonitorEnabled    = [bool]$mp.BehaviorMonitorEnabled
        $state.IoavProtectionEnabled     = [bool]$mp.IoavProtectionEnabled
        $state.NISEnabled                = [bool]$mp.NISEnabled
        $state.OnAccessProtectionEnabled = [bool]$mp.OnAccessProtectionEnabled
        $state.AMServiceEnabled          = [bool]$mp.AMServiceEnabled
        $state.IsTamperProtected         = [bool]$mp.IsTamperProtected
        $amRunningMode = $mp.PSObject.Properties['AMRunningMode']
        if ($amRunningMode) { $state.AMRunningMode = "$($amRunningMode.Value)" }
        $amProductVersion = $mp.PSObject.Properties['AMProductVersion']
        if ($amProductVersion) {
            $state.AMProductVersion = "$($amProductVersion.Value)"
            $state.DefenderPlatformVersion = $state.AMProductVersion
        }
        $amEngineVersion = $mp.PSObject.Properties['AMEngineVersion']
        if ($amEngineVersion) { $state.AMEngineVersion = "$($amEngineVersion.Value)" }
        $amServiceVersion = $mp.PSObject.Properties['AMServiceVersion']
        if ($amServiceVersion) { $state.AMServiceVersion = "$($amServiceVersion.Value)" }
        if ($mp.AntivirusSignatureLastUpdated) {
            $state.AntivirusSignatureLastUpdated = $mp.AntivirusSignatureLastUpdated.ToString('o')
        }
    } catch {
        $state.MpStatusQueryError = $_.Exception.Message
    }

    try {
        $asReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' `
            -Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue
        if ($null -ne $asReg) { $state.PolicyDisableAntiSpyware = [int]$asReg.DisableAntiSpyware }
    } catch {}

    $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if ($svc) {
        $state.WinDefendStatus = "$($svc.Status)"
        try {
            $svcStart = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' `
                -Name 'Start' -ErrorAction SilentlyContinue).Start
            $startMap = @{ 0='Boot'; 1='System'; 2='Automatic'; 3='Manual'; 4='Disabled' }
            if ($null -ne $svcStart -and $startMap.ContainsKey([int]$svcStart)) {
                $state.WinDefendStartType = $startMap[[int]$svcStart]
            } else {
                $state.WinDefendStartType = "$($svc.StartType)"
            }
        } catch { $state.WinDefendStartType = "$($svc.StartType)" }
    } else {
        $state.WinDefendStatus    = 'NotFound'
        $state.WinDefendStartType = 'NotFound'
    }

    # Defender for Endpoint / passive-mode signals are read-only. These values
    # explain why Defender may not respond to local disable requests on a
    # managed device.
    $passivePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
    $mdeStatusPath     = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
    $managedPath       = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
    $featuresPath      = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
    try {
        $passiveReg = Get-ItemProperty -LiteralPath $passivePolicyPath -Name 'ForceDefenderPassiveMode' -ErrorAction SilentlyContinue
        if ($null -ne $passiveReg) { $state.ForceDefenderPassiveMode = [int]$passiveReg.ForceDefenderPassiveMode }
    } catch {}
    try {
        if (Test-Path -LiteralPath $mdeStatusPath) {
            $state.MDEStatusKeyPresent = $true
            $mdeStatus = Get-ItemProperty -LiteralPath $mdeStatusPath -ErrorAction SilentlyContinue
            if ($mdeStatus) {
                $onboarding = $mdeStatus.PSObject.Properties['OnboardingState']
                if ($onboarding) { $state.MDEOnboardingState = [int]$onboarding.Value }
                $senseRunning = $mdeStatus.PSObject.Properties['SenseIsRunning']
                if ($senseRunning) { $state.MDESenseIsRunning = [int]$senseRunning.Value }
                $orgId = $mdeStatus.PSObject.Properties['OrgId']
                if ($orgId -and -not [string]::IsNullOrWhiteSpace("$($orgId.Value)")) { $state.MDEOrgIdPresent = $true }
            }
        }
    } catch {}
    try {
        $managedReg = Get-ItemProperty -LiteralPath $managedPath -Name 'ManagedDefenderProductType' -ErrorAction SilentlyContinue
        if ($null -ne $managedReg) { $state.ManagedDefenderProductType = [int]$managedReg.ManagedDefenderProductType }
    } catch {}
    try {
        $tpReg = Get-ItemProperty -LiteralPath $featuresPath -Name 'TPExclusions' -ErrorAction SilentlyContinue
        if ($null -ne $tpReg) { $state.TPExclusions = [int]$tpReg.TPExclusions }
    } catch {}

    if ($state.AMRunningMode -match 'EDR\s*Block') {
        $state.DefenderMode = 'EDR Block Mode'
    } elseif ($state.AMRunningMode -match 'Passive') {
        $state.DefenderMode = 'Passive'
    } elseif ($state.AMRunningMode -match '^Normal$') {
        $state.DefenderMode = 'Normal'
    } elseif ($state.AMRunningMode -match 'Disabled') {
        $state.DefenderMode = 'Disabled'
    } elseif (
        $state.AMServiceEnabled -eq $false -or
        $state.AntivirusEnabled -eq $false -or
        $state.WinDefendStartType -eq 'Disabled' -or
        $state.PolicyDisableAntiSpyware -eq 1
    ) {
        $state.DefenderMode = 'Disabled'
    }

    $state.MDEOnboarded = (
        $state.MDEOnboardingState -eq 1 -or
        $state.MDEOrgIdPresent -eq $true
    )
    $managedProduct = $state.ManagedDefenderProductType -in @(6, 7)
    $managedTamper = ($managedProduct -or $state.TPExclusions -eq 1)
    $state.ManagedTamperProtection = $managedTamper
    $state.ManagedDevice = (
        $state.MDEOnboarded -or
        $state.ForceDefenderPassiveMode -eq 1 -or
        $managedProduct -or
        $state.TPExclusions -eq 1
    )
    if ($state.ManagedDevice) {
        $signals = New-Object System.Collections.Generic.List[string]
        if ($state.MDEOnboarded) { $signals.Add('MDE onboarding') | Out-Null }
        if ($state.ForceDefenderPassiveMode -eq 1) { $signals.Add('passive-mode policy') | Out-Null }
        if ($managedProduct) { $signals.Add("ManagedDefenderProductType=$($state.ManagedDefenderProductType)") | Out-Null }
        if ($state.TPExclusions -eq 1) { $signals.Add('tamper-protected exclusions') | Out-Null }
        $state.ManagedDeviceWarning = "Managed Defender or device-management signals detected ($($signals -join ', ')). Local changes may be ignored or reverted; consult your security administrator before disabling Defender."
    }
    $state.DefenderEndpoint = [ordered]@{
        Mode                       = $state.DefenderMode
        AMRunningMode              = $state.AMRunningMode
        PlatformVersion            = $state.DefenderPlatformVersion
        ForceDefenderPassiveMode  = $state.ForceDefenderPassiveMode
        MDEStatusKeyPresent       = $state.MDEStatusKeyPresent
        MDEOnboardingState        = $state.MDEOnboardingState
        MDESenseIsRunning         = $state.MDESenseIsRunning
        MDEOrgIdPresent           = $state.MDEOrgIdPresent
        MDEOnboarded              = $state.MDEOnboarded
        ManagedDefenderProductType = $state.ManagedDefenderProductType
        TPExclusions              = $state.TPExclusions
        ManagedTamperProtection   = $state.ManagedTamperProtection
        ManagedDevice             = $state.ManagedDevice
    }

    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        $fwMap = [ordered]@{}
        foreach ($p in $fw) { $fwMap[$p.Name] = [bool]$p.Enabled }
        $state.FirewallProfilesEnabled = $fwMap
    } catch {
        $state.FirewallProfilesEnabled = $null
    }

    # Effective-enabled summary: RTP + AV on, WinDefend running, no GP disable
    $state.DefenderEffectivelyEnabled = (
        $state.RealTimeProtectionEnabled -eq $true -and
        $state.AntivirusEnabled -eq $true -and
        $state.WinDefendStatus -eq 'Running' -and
        $state.WinDefendStartType -ne 'Disabled' -and
        $state.PolicyDisableAntiSpyware -ne 1
    )

    if ($Extended.IsPresent) {
        # Extended: service start types + PPL flags + scheduled tasks + policy keys
        $services = @('WinDefend','WdFilter','WdBoot','WdNisDrv','WdNisSvc','SecurityHealthService','wscsvc','Sense')
        $svcTable = [ordered]@{}
        foreach ($s in $services) {
            $entry = [ordered]@{ Status='NotFound'; StartType='NotFound'; PPL=$null }
            $o = Get-Service -Name $s -ErrorAction SilentlyContinue
            if ($o) {
                $entry.Status = "$($o.Status)"
                try {
                    $start = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$s" `
                        -Name 'Start' -ErrorAction SilentlyContinue).Start
                    $map = @{ 0='Boot'; 1='System'; 2='Automatic'; 3='Manual'; 4='Disabled' }
                    if ($null -ne $start -and $map.ContainsKey([int]$start)) { $entry.StartType = $map[[int]$start] }
                } catch {}
                try {
                    $launch = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$s" `
                        -Name 'LaunchProtected' -ErrorAction SilentlyContinue).LaunchProtected
                    if ($null -ne $launch) { $entry.PPL = [int]$launch } else { $entry.PPL = 0 }
                } catch { $entry.PPL = $null }
            }
            $svcTable[$s] = $entry
        }
        $state.Services = $svcTable

        $taskNames = @(
            'Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance',
            'Microsoft\Windows\Windows Defender\Windows Defender Cleanup',
            'Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan',
            'Microsoft\Windows\Windows Defender\Windows Defender Verification',
            'Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh'
        )
        $taskTable = [ordered]@{}
        foreach ($t in $taskNames) {
            try {
                $parts = $t -split '\\'
                $name  = $parts[-1]
                $path  = '\' + ($parts[0..($parts.Count-2)] -join '\') + '\'
                $task  = Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue
                if ($task) { $taskTable[$name] = "$($task.State)" } else { $taskTable[$name] = 'NotFound' }
            } catch { $taskTable[($t -split '\\')[-1]] = 'Error' }
        }
        $state.ScheduledTasks = $taskTable

        $policyKeys = [ordered]@{
            'DisableAntiSpyware'                              = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
            'DisableRealtimeMonitoring'                       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            'DisableBehaviorMonitoring'                       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            'DisableOnAccessProtection'                       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            'DisableScanOnRealtimeEnable'                     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            'DisableIOAVProtection'                           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            'SpynetReporting'                                 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
            'SubmitSamplesConsent'                            = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        }
        $polTable = [ordered]@{}
        foreach ($kv in $policyKeys.GetEnumerator()) {
            try {
                $v = (Get-ItemProperty -LiteralPath $kv.Value -Name $kv.Key -ErrorAction SilentlyContinue).$($kv.Key)
                if ($null -ne $v) { $polTable[$kv.Key] = [int]$v } else { $polTable[$kv.Key] = $null }
            } catch { $polTable[$kv.Key] = $null }
        }
        $state.PolicyKeys = $polTable

        # Third-party AV detection via Security Center (informational only)
        try {
            $av = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'AntivirusProduct' -ErrorAction SilentlyContinue
            if ($av) {
                $state.ThirdPartyAV = @($av | Where-Object { $_.displayName -notmatch 'Windows Defender|Microsoft Defender' } |
                    ForEach-Object { $_.displayName })
            } else {
                $state.ThirdPartyAV = @()
            }
        } catch { $state.ThirdPartyAV = $null }
    }

    return $state
}

function Write-CliLine {
    # Single stream to stdout; avoids Write-Host pollution and keeps -Silent honest.
    param([string]$Text, [switch]$ErrorStream)
    if ($script:Silent -and -not $ErrorStream.IsPresent) { return }
    if ($ErrorStream.IsPresent) { [Console]::Error.WriteLine($Text) }
    else { [Console]::Out.WriteLine($Text) }
}

function Invoke-VerifyMode {
    param(
        [string]$Expect = 'Auto',
        [switch]$Json,
        [switch]$Eicar,
        [switch]$Force
    )

    $state = Get-DefenderState -Extended

    # Auto: infer expectation from current effective state
    $expectResolved = $Expect
    if ($expectResolved -eq 'Auto') {
        $expectResolved = if ($state.DefenderEffectivelyEnabled) { 'Enabled' } else { 'Disabled' }
    }

    $checks = New-Object System.Collections.Generic.List[hashtable]
    function _check([string]$name, $expected, $actual) {
        $result = if ($null -eq $expected -or $expected -eq $actual) { 'PASS' } else { 'FAIL' }
        $checks.Add([ordered]@{
            name     = $name
            expected = $expected
            actual   = $actual
            result   = $result
        }) | Out-Null
    }

    if ($expectResolved -eq 'Enabled') {
        _check 'RealTimeProtectionEnabled' $true  $state.RealTimeProtectionEnabled
        _check 'AntivirusEnabled'          $true  $state.AntivirusEnabled
        _check 'AntispywareEnabled'        $true  $state.AntispywareEnabled
        _check 'WinDefendRunning'          'Running'   $state.WinDefendStatus
        _check 'WinDefendNotDisabled'      $true  ($state.WinDefendStartType -ne 'Disabled')
        _check 'NoGroupPolicyDisable'      $true  ($state.PolicyDisableAntiSpyware -ne 1)
    } else {
        # 'Disabled' expectation — any of these signals successful disable
        $anyDisabled = (
            $state.RealTimeProtectionEnabled -eq $false -or
            $state.AntivirusEnabled -eq $false -or
            $state.WinDefendStatus -eq 'Stopped' -or
            $state.WinDefendStartType -eq 'Disabled' -or
            $state.PolicyDisableAntiSpyware -eq 1
        )
        _check 'DefenderEffectivelyDisabled' $true $anyDisabled
        _check 'WinDefendServiceStatus'      $null $state.WinDefendStatus
        _check 'WinDefendStartType'          $null $state.WinDefendStartType
        _check 'PolicyDisableAntiSpyware'    $null $state.PolicyDisableAntiSpyware
    }

    # Optional: EICAR synthetic detection test
    if ($Eicar.IsPresent) {
        $eicarCheck = [ordered]@{ name = 'EicarSyntheticDetection'; expected = $null; actual = $null; result = 'SKIP' }
        if (-not $Force.IsPresent) {
            $eicarCheck.actual = 'not-run (add -Force to perform test)'
            $eicarCheck.result = 'SKIP'
        } elseif ($expectResolved -ne 'Enabled') {
            $eicarCheck.actual = 'skipped (Defender expected disabled; EICAR test only valid when enabled)'
            $eicarCheck.result = 'SKIP'
        } else {
            # Write EICAR standard test string, wait briefly, check if it got quarantined.
            # This string is split across chars so the script itself doesn't trip AV on disk.
            $eicarStr = 'X5O!P%@AP' + '[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H' + '*'
            $tempDir  = Join-Path $env:TEMP 'DefenderControl-Verify'
            try { if (-not (Test-Path $tempDir)) { New-Item -Path $tempDir -ItemType Directory -Force | Out-Null } } catch {}
            $eicarPath = Join-Path $tempDir ("eicar-" + [guid]::NewGuid().ToString('N') + '.com')
            try {
                [System.IO.File]::WriteAllText($eicarPath, $eicarStr, [System.Text.Encoding]::ASCII)
                Start-Sleep -Milliseconds 2500
                $eicarStillThere = Test-Path -LiteralPath $eicarPath
                if (-not $eicarStillThere) {
                    $eicarCheck.actual = 'quarantined (Defender detected + removed EICAR test file)'
                    $eicarCheck.result = 'PASS'
                } else {
                    $eicarCheck.actual = 'still-present (Defender did NOT detect EICAR within 2.5s)'
                    $eicarCheck.result = 'FAIL'
                    try { Remove-Item -LiteralPath $eicarPath -Force -ErrorAction SilentlyContinue } catch {}
                }
            } catch {
                $eicarCheck.actual = "write-failed: $($_.Exception.Message)"
                $eicarCheck.result = 'SKIP'
            } finally {
                # Best-effort cleanup (if Defender didn't quarantine, or we errored)
                try { if (Test-Path -LiteralPath $eicarPath) { Remove-Item -LiteralPath $eicarPath -Force -ErrorAction SilentlyContinue } } catch {}
                try { if ((Get-ChildItem -Path $tempDir -ErrorAction SilentlyContinue).Count -eq 0) {
                    Remove-Item -Path $tempDir -Force -Recurse -ErrorAction SilentlyContinue
                } } catch {}
            }
        }
        $checks.Add($eicarCheck) | Out-Null
    }

    $failCount  = @($checks | Where-Object { $_.result -eq 'FAIL' }).Count
    $overall    = if ($failCount -eq 0) { 'PASS' } else { 'FAIL' }

    $report = [ordered]@{
        timestamp         = (Get-Date).ToString('o')
        host              = $env:COMPUTERNAME
        expectation       = $expectResolved
        expectationSource = $Expect
        tamperProtected   = $state.IsTamperProtected
        defenderMode      = $state.DefenderMode
        platformVersion   = $state.DefenderPlatformVersion
        managedDevice     = $state.ManagedDevice
        managedDeviceWarning = $state.ManagedDeviceWarning
        state             = $state
        overall           = $overall
        failCount         = $failCount
        checks            = @($checks)
    }

    if ($Json.IsPresent) {
        [Console]::Out.WriteLine(($report | ConvertTo-Json -Depth 6))
    } else {
        Write-CliLine ("Defender Control Verify - expect: {0} (source: {1})" -f $report.expectation, $report.expectationSource)
        Write-CliLine ("Overall: {0}  FailCount: {1}  TamperProtected: {2}" -f $report.overall, $report.failCount, $report.tamperProtected)
        Write-CliLine '---'
        foreach ($c in $checks) {
            $mark = switch ($c.result) { 'PASS' { 'PASS' }; 'FAIL' { 'FAIL' }; 'SKIP' { 'SKIP' } }
            Write-CliLine ("  [{0}] {1,-30} expected={2}  actual={3}" -f $mark, $c.name, $c.expected, $c.actual)
        }
    }

    if ($state.IsTamperProtected -eq $true) { exit $script:EXIT_TAMPER_BLOCKED }
    if ($overall -eq 'PASS') { exit $script:EXIT_OK } else { exit $script:EXIT_VERIFY_FAIL }
}

function Invoke-CliMode {
    param(
        [string]$Mode,
        [string]$Expect = 'Auto',
        [switch]$Json,
        [switch]$Silent,
        [switch]$Eicar,
        [switch]$Force,
        [string]$OutputPath,
        [switch]$MpSupportFiles,
        [switch]$ListManifests,
        [switch]$PruneManifests,
        [switch]$Redact,
        [int]$RetentionDays = 30
    )

    $script:Silent = $Silent.IsPresent

    switch ($Mode) {
        'Verify' {
            Invoke-VerifyMode -Expect $Expect -Json:$Json -Eicar:$Eicar -Force:$Force
            exit $script:EXIT_USAGE # defensive
        }
        { $_ -in 'Status','Health' } {
            $extended = ($_ -eq 'Health')
            $state    = Get-DefenderState -Extended:$extended

            if ($Json.IsPresent) {
                # Depth 6 covers nested services/tasks/policy/firewall tables.
                [Console]::Out.WriteLine(($state | ConvertTo-Json -Depth 6 -Compress:$false))
            } else {
                Write-CliLine ("Defender Control v{0} - {1} snapshot" -f $state.Version, $Mode)
                Write-CliLine ("Host: {0}  OS: {1}" -f $state.Computer, $state.OS)
                Write-CliLine '---'
                Write-CliLine ("Real-Time Protection    : {0}" -f $state.RealTimeProtectionEnabled)
                Write-CliLine ("Antivirus Enabled       : {0}" -f $state.AntivirusEnabled)
                Write-CliLine ("Antispyware Enabled     : {0}" -f $state.AntispywareEnabled)
                Write-CliLine ("Behavior Monitor        : {0}" -f $state.BehaviorMonitorEnabled)
                Write-CliLine ("NIS Enabled             : {0}" -f $state.NISEnabled)
                Write-CliLine ("Tamper Protection       : {0}" -f $state.IsTamperProtected)
                Write-CliLine ("Defender Mode           : {0}" -f $state.DefenderMode)
                Write-CliLine ("Platform Version        : {0}" -f $state.DefenderPlatformVersion)
                Write-CliLine ("MDE Onboarded           : {0}" -f $state.MDEOnboarded)
                Write-CliLine ("Force Passive Policy    : {0}" -f $state.ForceDefenderPassiveMode)
                Write-CliLine ("Managed Device Signals  : {0}" -f $state.ManagedDevice)
                Write-CliLine ("Last Signature Update   : {0}" -f $state.AntivirusSignatureLastUpdated)
                Write-CliLine ("WinDefend Service       : {0} (Start: {1})" -f $state.WinDefendStatus, $state.WinDefendStartType)
                Write-CliLine ("Policy DisableAntiSpy   : {0}" -f $state.PolicyDisableAntiSpyware)
                Write-CliLine ("Effectively Enabled     : {0}" -f $state.DefenderEffectivelyEnabled)
                if ($state.ManagedDeviceWarning) {
                    Write-CliLine ("WARN: {0}" -f $state.ManagedDeviceWarning) -ErrorStream
                }
                if ($state.FirewallProfilesEnabled) {
                    $fwLine = ($state.FirewallProfilesEnabled.GetEnumerator() |
                        ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '
                    Write-CliLine ("Firewall Profiles       : {0}" -f $fwLine)
                }
                if ($extended -and $state.Services) {
                    Write-CliLine ''
                    Write-CliLine 'Services (Status / Start / PPL):'
                    foreach ($s in $state.Services.GetEnumerator()) {
                        Write-CliLine ("  {0,-24} {1,-10} {2,-10} PPL={3}" -f `
                            $s.Key, $s.Value.Status, $s.Value.StartType, $s.Value.PPL)
                    }
                }
                if ($extended -and $state.ScheduledTasks) {
                    Write-CliLine ''
                    Write-CliLine 'Scheduled Tasks:'
                    foreach ($t in $state.ScheduledTasks.GetEnumerator()) {
                        Write-CliLine ("  {0,-50} {1}" -f $t.Key, $t.Value)
                    }
                }
                if ($extended -and $state.PolicyKeys) {
                    Write-CliLine ''
                    Write-CliLine 'Policy Keys (null = not set):'
                    foreach ($p in $state.PolicyKeys.GetEnumerator()) {
                        Write-CliLine ("  {0,-40} {1}" -f $p.Key, $p.Value)
                    }
                }
                if ($extended -and $null -ne $state.ThirdPartyAV) {
                    Write-CliLine ''
                    $avCount = @($state.ThirdPartyAV).Count
                    if ($avCount -eq 0) {
                        Write-CliLine 'Third-party AV          : none detected'
                    } else {
                        Write-CliLine ("Third-party AV          : {0}" -f (($state.ThirdPartyAV) -join ', '))
                    }
                }
                if ($state.MpStatusQueryError) {
                    Write-CliLine ("WARN: Get-MpComputerStatus failed: {0}" -f $state.MpStatusQueryError) -ErrorStream
                }
            }

            if ($state.IsTamperProtected -eq $true) { exit $script:EXIT_TAMPER_BLOCKED }
            exit $script:EXIT_OK
        }

        'Manifest' {
            $manifestActionCount = 0
            if ($ListManifests.IsPresent) { $manifestActionCount++ }
            if ($PruneManifests.IsPresent) { $manifestActionCount++ }
            if ($Redact.IsPresent) { $manifestActionCount++ }
            if ($manifestActionCount -gt 1) {
                Write-CliLine 'DefenderControl: choose only one manifest action.' -ErrorStream
                exit $script:EXIT_USAGE
            }
            if ($RetentionDays -lt 1) {
                Write-CliLine 'DefenderControl: -RetentionDays must be at least 1.' -ErrorStream
                exit $script:EXIT_USAGE
            }

            if ($ListManifests.IsPresent) {
                $summary = Get-DefenderControlManifestSummary
                if ($Json.IsPresent) {
                    [Console]::Out.WriteLine(($summary | ConvertTo-Json -Depth 6))
                } else {
                    Write-CliLine ("Manifest retention: {0} days; keep newest {1} files" -f `
                        $summary.RetentionDays, $summary.MaxCount)
                    Write-CliLine ("Manifest directory: {0}" -f $summary.Directory)
                    Write-CliLine ("Manifests found: {0}" -f $summary.Count)
                    foreach ($item in @($summary.Manifests)) {
                        Write-CliLine ("  {0}  {1} bytes  {2}" -f $item.Name, $item.Length, $item.LastWriteTime)
                    }
                }
                exit $script:EXIT_OK
            }

            if ($PruneManifests.IsPresent) {
                $pruned = Remove-DefenderControlManifests -RetentionDays $RetentionDays
                if ($Json.IsPresent) {
                    [Console]::Out.WriteLine(($pruned | ConvertTo-Json -Depth 6))
                } else {
                    Write-CliLine ("Manifest retention: {0} days; keep newest {1} files" -f `
                        $pruned.RetentionDays, $pruned.MaxCount)
                    Write-CliLine ("Pruned {0} manifest(s); {1} remain." -f $pruned.RemovedCount, $pruned.RemainingCount)
                    foreach ($removed in @($pruned.Removed)) { Write-CliLine ("  Removed: {0}" -f $removed) }
                }
                exit $script:EXIT_OK
            }

            if ($Redact.IsPresent) {
                try {
                    $redacted = Export-DefenderControlRedactedData -OutputPath $OutputPath
                    if ($Json.IsPresent) {
                        [Console]::Out.WriteLine(($redacted | ConvertTo-Json -Depth 6))
                    } else {
                        Write-CliLine ("Redacted export created: {0}" -f $redacted.Path)
                        Write-CliLine ("Manifest included: {0}  Log included: {1}" -f `
                            $redacted.ManifestIncluded, $redacted.LogIncluded)
                        foreach ($warning in @($redacted.Warnings)) { Write-CliLine ("WARN: {0}" -f $warning) -ErrorStream }
                    }
                    exit $script:EXIT_OK
                } catch {
                    Write-CliLine ("DefenderControl: redacted export failed: {0}" -f $_.Exception.Message) -ErrorStream
                    exit $script:EXIT_USAGE
                }
            }

            $dir = Get-DefenderControlManifestDirectory
            $latest = Get-DefenderControlManifestFiles | Select-Object -First 1
            if (-not $latest) {
                Write-CliLine "No manifests found in $dir" -ErrorStream
                exit $script:EXIT_USAGE
            }
            $text = Get-Content -Raw -LiteralPath $latest.FullName
            if ($Json.IsPresent) {
                try {
                    $manifestObject = $text | ConvertFrom-Json
                    $manifestObject | Add-Member -NotePropertyName retentionPolicy -NotePropertyValue ([ordered]@{
                        days = $script:ManifestRetentionDays
                        maxCount = $script:ManifestMaxCount
                        redactionAvailable = $true
                    }) -Force
                    [Console]::Out.WriteLine(($manifestObject | ConvertTo-Json -Depth 12))
                } catch {
                    [Console]::Out.WriteLine($text)
                }
            } else {
                Write-CliLine ("Manifest retention: {0} days; keep newest {1} files" -f `
                    $script:ManifestRetentionDays, $script:ManifestMaxCount)
                Write-CliLine ("Latest manifest: " + $latest.FullName)
                Write-CliLine '---'
                [Console]::Out.WriteLine($text)
            }
            exit $script:EXIT_OK
        }

        'SupportBundle' {
            try {
                Write-DefenderControlEvent -Message "Defender Control: support bundle collection started on $env:COMPUTERNAME" -EventId 3001
                $bundle = New-DefenderControlSupportBundle `
                    -OutputPath $OutputPath `
                    -IncludeMpSupportFiles:$MpSupportFiles `
                    -Version $script:Version `
                    -OSDetail $script:OSDetail `
                    -EventLogSource $script:EventLogSource
                if ($Json.IsPresent) {
                    [Console]::Out.WriteLine(($bundle | ConvertTo-Json -Depth 6))
                } else {
                    Write-CliLine ("Support bundle created: {0}" -f $bundle.Path)
                    Write-CliLine ("Files: {0}  MpSupportFiles.cab: {1}" -f $bundle.FileCount, $bundle.IncludedMpSupportFiles)
                    if ($bundle.Warnings.Count -gt 0) {
                        foreach ($warning in $bundle.Warnings) { Write-CliLine ("WARN: {0}" -f $warning) -ErrorStream }
                    }
                }
                Write-DefenderControlEvent -Message "Defender Control: support bundle created on $env:COMPUTERNAME at $($bundle.Path)" -EventId 3002
                exit $script:EXIT_OK
            } catch {
                Write-DefenderControlEvent -Message "Defender Control: support bundle collection failed on $env:COMPUTERNAME - $($_.Exception.Message)" -EventId 3003 -EntryType ([System.Diagnostics.EventLogEntryType]::Error)
                Write-CliLine ("DefenderControl: support bundle failed: {0}" -f $_.Exception.Message) -ErrorStream
                exit $script:EXIT_USAGE
            }
        }

        'Disable' {
            Write-CliLine "DefenderControl: -Mode Disable is reserved. Use the GUI for mutating operations." -ErrorStream
            exit $script:EXIT_USAGE
        }
        'Enable'  {
            Write-CliLine "DefenderControl: -Mode Enable is reserved. Use the GUI for mutating operations." -ErrorStream
            exit $script:EXIT_USAGE
        }
        default {
            Write-CliLine "DefenderControl: unknown mode '$Mode'" -ErrorStream
            exit $script:EXIT_USAGE
        }
    }
}

function New-DefenderControlSupportBundle {
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        [switch]$IncludeMpSupportFiles,
        $State,
        [object[]]$LogEntries,
        [string]$Version = 'unknown',
        [string]$OSDetail = 'unknown',
        [string]$EventLogSource = 'DefenderControl'
    )

    if ($null -eq $State) { $State = Get-DefenderState -Extended }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $desktop = [Environment]::GetFolderPath('Desktop')
        if ([string]::IsNullOrWhiteSpace($desktop) -or -not (Test-Path -LiteralPath $desktop)) {
            $desktop = $env:TEMP
        }
        $OutputPath = Join-Path $desktop "DefenderControl-Support-$stamp.zip"
    } elseif (Test-Path -LiteralPath $OutputPath -PathType Container) {
        $OutputPath = Join-Path $OutputPath "DefenderControl-Support-$stamp.zip"
    } elseif ([IO.Path]::GetExtension($OutputPath) -ne '.zip') {
        $OutputPath = "$OutputPath.zip"
    }

    $parent = Split-Path -Parent $OutputPath
    if ([string]::IsNullOrWhiteSpace($parent)) { $parent = (Get-Location).ProviderPath }
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    $OutputPath = Join-Path $parent (Split-Path -Leaf $OutputPath)

    $tempRoot = Join-Path $env:TEMP "DefenderControl-Support-$([guid]::NewGuid().ToString('N'))"
    $stage = Join-Path $tempRoot 'bundle'
    $warnings = New-Object System.Collections.Generic.List[string]
    $files = New-Object System.Collections.Generic.List[string]
    $mpCollection = 'not-requested'
    $mpSupportIncluded = $false
    $manifestSource = $null

    try {
        New-Item -Path $stage -ItemType Directory -Force | Out-Null

        $healthPath = Join-Path $stage 'Health.json'
        [IO.File]::WriteAllText(
            $healthPath,
            ($State | ConvertTo-Json -Depth 12),
            [Text.UTF8Encoding]::new($false))
        $files.Add('Health.json') | Out-Null

        $manifestDir = Join-Path $env:ProgramData 'DefenderControl\manifests'
        $latestManifest = $null
        if (Test-Path -LiteralPath $manifestDir) {
            $latestManifest = Get-ChildItem -LiteralPath $manifestDir -Filter '*.json' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
        }
        $manifestStage = Join-Path $stage 'manifest'
        New-Item -Path $manifestStage -ItemType Directory -Force | Out-Null
        if ($latestManifest) {
            Copy-Item -LiteralPath $latestManifest.FullName -Destination (Join-Path $manifestStage 'latest.json') -Force
            $manifestSource = $latestManifest.FullName
            $files.Add('manifest\latest.json') | Out-Null
        } else {
            $manifestNote = Join-Path $manifestStage 'none.txt'
            [IO.File]::WriteAllText($manifestNote, 'No DefenderControl manifest was found on this device.', [Text.UTF8Encoding]::new($false))
            $warnings.Add('No DefenderControl manifest was found.') | Out-Null
            $files.Add('manifest\none.txt') | Out-Null
        }

        $operationLines = New-Object System.Collections.Generic.List[string]
        $operationLines.Add("Defender Control v$Version - Support Bundle")
        $operationLines.Add("Generated: $(Get-Date -Format 'o')")
        $operationLines.Add("System: $env:COMPUTERNAME | $OSDetail")
        $operationLines.Add('')
        if (@($LogEntries).Count -gt 0) {
            $operationLines.Add('GUI operation log:')
            foreach ($entry in @($LogEntries)) {
                $time = if ($entry.Time) { $entry.Time } else { '--:--:--' }
                $message = if ($entry.Message) { $entry.Message } else { "$entry" }
                $operationLines.Add("[$time] $message")
            }
        } else {
            $operationLines.Add('CLI support bundle: no in-memory GUI operation log was available.')
            $operationLines.Add('The Health.json, manifest, event log, and optional Defender CAB contain the collected diagnostics.')
        }
        $logPath = Join-Path $stage 'operation-log.txt'
        [IO.File]::WriteAllLines($logPath, $operationLines.ToArray(), [Text.UTF8Encoding]::new($false))
        $files.Add('operation-log.txt') | Out-Null

        $eventRecords = @()
        try {
            $eventStart = (Get-Date).AddDays(-7)
            $eventRecords = @(Get-WinEvent -FilterHashtable @{
                    LogName = 'Application'
                    ProviderName = $EventLogSource
                    StartTime = $eventStart
                } -MaxEvents 200 -ErrorAction Stop | ForEach-Object {
                    [ordered]@{
                        TimeCreated = $_.TimeCreated.ToString('o')
                        Id = $_.Id
                        Level = $_.LevelDisplayName
                        Provider = $_.ProviderName
                        Message = $_.Message
                    }
                })
        } catch {
            $warnings.Add("Recent DefenderControl event log could not be read: $($_.Exception.Message)") | Out-Null
        }
        $eventsPath = Join-Path $stage 'events.json'
        $eventJson = if (@($eventRecords).Count -gt 0) {
            $eventRecords | ConvertTo-Json -Depth 6
        } else {
            '[]'
        }
        [IO.File]::WriteAllText($eventsPath, $eventJson, [Text.UTF8Encoding]::new($false))
        $files.Add('events.json') | Out-Null

        $logDir = Join-Path $env:ProgramData 'DefenderControl\logs'
        if (Test-Path -LiteralPath $logDir) {
            $recentLogs = @(Get-ChildItem -LiteralPath $logDir -Filter '*.log' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 10)
            if ($recentLogs.Count -gt 0) {
                $logStage = Join-Path $stage 'logs'
                New-Item -Path $logStage -ItemType Directory -Force | Out-Null
                foreach ($recentLog in $recentLogs) {
                    Copy-Item -LiteralPath $recentLog.FullName -Destination (Join-Path $logStage $recentLog.Name) -Force
                    $files.Add("logs\$($recentLog.Name)") | Out-Null
                }
            }
        }

        if ($IncludeMpSupportFiles.IsPresent) {
            $mpCollection = 'requested'
            $mpOutputRoot = Join-Path $tempRoot 'mp-support-output'
            New-Item -Path $mpOutputRoot -ItemType Directory -Force | Out-Null
            $mpCandidates = New-Object System.Collections.Generic.List[string]
            $platformRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
            if (Test-Path -LiteralPath $platformRoot) {
                $platformDirs = @(Get-ChildItem -LiteralPath $platformRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
                foreach ($platformDir in $platformDirs) {
                    $mpCandidates.Add((Join-Path $platformDir.FullName 'MpCmdRun.exe')) | Out-Null
                }
            }
            $mpCandidates.Add((Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe')) | Out-Null
            $mpCmdRun = $mpCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
            $mpOutputPath = Join-Path $stage 'MpCmdRun-output.txt'
            if ($mpCmdRun) {
                $stdoutPath = Join-Path $mpOutputRoot 'stdout.txt'
                $stderrPath = Join-Path $mpOutputRoot 'stderr.txt'
                try {
                    $argumentList = '-GetFiles -SupportLogLocation "' + $mpOutputRoot + '"'
                    $mpProcess = Start-Process -FilePath $mpCmdRun -ArgumentList $argumentList `
                        -WorkingDirectory (Split-Path -Parent $mpCmdRun) -WindowStyle Hidden -Wait -PassThru `
                        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -ErrorAction Stop
                    $mpCollection = "completed (exit $($mpProcess.ExitCode))"
                } catch {
                    $mpCollection = 'failed'
                    $warnings.Add("MpCmdRun.exe -GetFiles failed: $($_.Exception.Message)") | Out-Null
                }
                $mpOutputLines = @(
                    "MpCmdRun.exe: $mpCmdRun"
                    "Collection: $mpCollection"
                    ''
                )
                if (Test-Path -LiteralPath $stdoutPath) { $mpOutputLines += Get-Content -LiteralPath $stdoutPath }
                if (Test-Path -LiteralPath $stderrPath) { $mpOutputLines += Get-Content -LiteralPath $stderrPath }
                [IO.File]::WriteAllLines($mpOutputPath, $mpOutputLines, [Text.UTF8Encoding]::new($false))
                $files.Add('MpCmdRun-output.txt') | Out-Null

                $mpCab = Get-ChildItem -LiteralPath $mpOutputRoot -Recurse -Filter '*.cab' -File -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if (-not $mpCab) {
                    $defaultCab = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Support\MpSupportFiles.cab'
                    if (Test-Path -LiteralPath $defaultCab) { $mpCab = Get-Item -LiteralPath $defaultCab }
                }
                if ($mpCab) {
                    Copy-Item -LiteralPath $mpCab.FullName -Destination (Join-Path $stage 'MpSupportFiles.cab') -Force
                    $mpSupportIncluded = $true
                    $files.Add('MpSupportFiles.cab') | Out-Null
                } else {
                    $warnings.Add('MpCmdRun completed but no MpSupportFiles.cab was found.') | Out-Null
                }
            } else {
                $mpCollection = 'unavailable'
                $warnings.Add('MpCmdRun.exe was not found; Microsoft Defender diagnostic CAB was not collected.') | Out-Null
                [IO.File]::WriteAllText($mpOutputPath, 'MpCmdRun.exe was not found on this device.', [Text.UTF8Encoding]::new($false))
                $files.Add('MpCmdRun-output.txt') | Out-Null
            }
        }

        $metadata = [ordered]@{
            schemaVersion = 1
            generatedAt = (Get-Date).ToString('o')
            version = $Version
            host = $env:COMPUTERNAME
            os = $OSDetail
            healthMode = 'Extended'
            manifestSource = $manifestSource
            eventWindowDays = 7
            eventCount = @($eventRecords).Count
            includeMpSupportFiles = $IncludeMpSupportFiles.IsPresent
            mpSupportCollection = $mpCollection
            includedMpSupportFiles = $mpSupportIncluded
            files = @($files)
            warnings = @($warnings)
        }
        $metadataPath = Join-Path $stage 'bundle-metadata.json'
        [IO.File]::WriteAllText($metadataPath, ($metadata | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        $files.Add('bundle-metadata.json') | Out-Null

        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $OutputPath -Force
        $resolvedOutput = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
        return [pscustomobject]@{
            Path = $resolvedOutput
            FileCount = @($files).Count
            IncludedMpSupportFiles = $mpSupportIncluded
            Warnings = @($warnings)
        }
    } finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-DefenderControlManifestDirectory {
    [CmdletBinding()]
    param([string]$Directory)
    if ([string]::IsNullOrWhiteSpace($Directory)) {
        $Directory = Join-Path $env:ProgramData 'DefenderControl\manifests'
    }
    return $Directory
}

function Get-DefenderControlManifestFiles {
    [CmdletBinding()]
    param([string]$Directory)
    $Directory = Get-DefenderControlManifestDirectory -Directory $Directory
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $Directory -Filter '*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
}

function Get-DefenderControlManifestSummary {
    [CmdletBinding()]
    param([string]$Directory)
    $Directory = Get-DefenderControlManifestDirectory -Directory $Directory
    $files = @(Get-DefenderControlManifestFiles -Directory $Directory)
    return [pscustomobject]@{
        Directory = $Directory
        RetentionDays = $script:ManifestRetentionDays
        MaxCount = $script:ManifestMaxCount
        Count = $files.Count
        Manifests = @($files | ForEach-Object {
            [ordered]@{
                Name = $_.Name
                FullName = $_.FullName
                Length = $_.Length
                LastWriteTime = $_.LastWriteTime.ToString('o')
            }
        })
    }
}

function Remove-DefenderControlManifests {
    [CmdletBinding()]
    param(
        [string]$Directory,
        [ValidateRange(1,3650)][int]$RetentionDays = 30,
        [ValidateRange(1,10000)][int]$MaxCount = 50
    )

    $Directory = Get-DefenderControlManifestDirectory -Directory $Directory
    $files = @(Get-DefenderControlManifestFiles -Directory $Directory)
    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    $candidates = @{}

    foreach ($file in $files) {
        if ($file.LastWriteTime -lt $cutoff) { $candidates[$file.FullName] = $file }
    }
    if ($files.Count -gt $MaxCount) {
        foreach ($file in @($files | Select-Object -Skip $MaxCount)) {
            $candidates[$file.FullName] = $file
        }
    }

    $root = $null
    if (Test-Path -LiteralPath $Directory -PathType Container) {
        $root = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Directory).ProviderPath).TrimEnd('\') + '\'
    }
    $removed = New-Object System.Collections.Generic.List[string]
    foreach ($file in @($candidates.Values | Sort-Object FullName)) {
        $target = [IO.Path]::GetFullPath($file.FullName)
        if ($root -and -not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to prune a manifest outside the manifest directory: $target"
        }
        Remove-Item -LiteralPath $target -Force -ErrorAction Stop
        $removed.Add($file.Name) | Out-Null
    }

    return [pscustomobject]@{
        Directory = $Directory
        RetentionDays = $RetentionDays
        MaxCount = $MaxCount
        Cutoff = $cutoff.ToString('o')
        RemovedCount = $removed.Count
        Removed = @($removed)
        RemainingCount = @((Get-DefenderControlManifestFiles -Directory $Directory)).Count
    }
}

function ConvertTo-RedactedDefenderControlText {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Text,
        [string[]]$KnownHostNames
    )
    if ($null -eq $Text) { return $null }
    $result = [string]$Text
    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
        $result = $result -replace [regex]::Escape($env:COMPUTERNAME), '[REDACTED_HOST]'
    }
    foreach ($knownHost in @($KnownHostNames)) {
        if (-not [string]::IsNullOrWhiteSpace($knownHost)) {
            $result = $result -replace [regex]::Escape($knownHost), '[REDACTED_HOST]'
        }
    }
    $result = $result -replace '(?i)[A-Z]:\\Users\\[^\\\s]+', '[REDACTED_USER_PATH]'
    $result = $result -replace '(?i)(HKLM:|HKCU:|HKCR:|Registry::)[^\s,;]+', '[REDACTED_REGISTRY_PATH]'
    return $result
}

function ConvertTo-RedactedDefenderControlValue {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Value,
        [string]$PropertyName = '',
        [string[]]$KnownHostNames
    )

    if ($null -eq $Value) { return $null }
    $property = [string]$PropertyName
    if ($property -match '(?i)^(host|computer|computername|username|user|domain)$') {
        return '[REDACTED]'
    }
    if ($property -match '(?i)(thirdpartyav|displayname|providername|avprovider)') {
        return '[REDACTED_AV_PROVIDER]'
    }
    if ($property -match '(?i)(registrypath|providerpath|^path$|filepath|sourcepath)') {
        return '[REDACTED_REGISTRY_PATH]'
    }
    if ($property -match '(?i)^(name|valuename|before|after|value|oldvalue|newvalue|defaultvalue)$') {
        return '[REDACTED]'
    }

        if ($Value -is [string]) {
        return ConvertTo-RedactedDefenderControlText -Text $Value -KnownHostNames $KnownHostNames
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($entry in $Value.GetEnumerator()) {
            $result[[string]$entry.Key] = ConvertTo-RedactedDefenderControlValue `
                -Value $entry.Value -PropertyName ([string]$entry.Key) -KnownHostNames $KnownHostNames
        }
        return $result
    }
    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
        return @($Value | ForEach-Object {
            ConvertTo-RedactedDefenderControlValue -Value $_ -PropertyName $PropertyName -KnownHostNames $KnownHostNames
        })
    }
    if ($Value.PSObject -and $Value.PSObject.Properties.Count -gt 0 -and
        -not ($Value -is [ValueType])) {
        $result = [ordered]@{}
        foreach ($propertyValue in $Value.PSObject.Properties) {
            $result[$propertyValue.Name] = ConvertTo-RedactedDefenderControlValue `
                -Value $propertyValue.Value -PropertyName $propertyValue.Name -KnownHostNames $KnownHostNames
        }
        return $result
    }
    return $Value
}

function Export-DefenderControlRedactedData {
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        [string]$Directory,
        [object[]]$LogEntries
    )

    $Directory = Get-DefenderControlManifestDirectory -Directory $Directory
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $desktop = [Environment]::GetFolderPath('Desktop')
        if ([string]::IsNullOrWhiteSpace($desktop) -or -not (Test-Path -LiteralPath $desktop)) { $desktop = $env:TEMP }
        $OutputPath = Join-Path $desktop "DefenderControl-Redacted-$stamp.zip"
    } elseif (Test-Path -LiteralPath $OutputPath -PathType Container) {
        $OutputPath = Join-Path $OutputPath "DefenderControl-Redacted-$stamp.zip"
    } elseif ([IO.Path]::GetExtension($OutputPath) -ne '.zip') {
        $OutputPath = "$OutputPath.zip"
    }
    $parent = Split-Path -Parent $OutputPath
    if ([string]::IsNullOrWhiteSpace($parent)) { $parent = (Get-Location).ProviderPath }
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    $OutputPath = Join-Path $parent (Split-Path -Leaf $OutputPath)

    $tempRoot = Join-Path $env:TEMP "DefenderControl-Redacted-$([guid]::NewGuid().ToString('N'))"
    $stage = Join-Path $tempRoot 'export'
    $warnings = New-Object System.Collections.Generic.List[string]
    $manifestIncluded = $false
    $logIncluded = $false
    try {
        New-Item -Path $stage -ItemType Directory -Force | Out-Null
        $latest = Get-DefenderControlManifestFiles -Directory $Directory | Select-Object -First 1
        if ($latest) {
            try {
                $manifest = Get-Content -Raw -LiteralPath $latest.FullName -ErrorAction Stop | ConvertFrom-Json
                $knownHosts = @()
                if ($manifest.host) { $knownHosts = @([string]$manifest.host) }
                $redactedManifest = ConvertTo-RedactedDefenderControlValue `
                    -Value $manifest -KnownHostNames $knownHosts
                [IO.File]::WriteAllText((Join-Path $stage 'manifest-redacted.json'),
                    ($redactedManifest | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
                $manifestIncluded = $true
            } catch {
                $warnings.Add("Latest manifest could not be redacted: $($_.Exception.Message)") | Out-Null
            }
        } else {
            $warnings.Add('No DefenderControl manifest was found.') | Out-Null
        }

        $redactedLines = New-Object System.Collections.Generic.List[string]
        if ($null -ne $LogEntries) {
            foreach ($entry in @($LogEntries)) {
                $time = if ($entry.Time) { $entry.Time } else { '--:--:--' }
                $message = if ($entry.Message) { $entry.Message } else { "$entry" }
                $redactedLines.Add((ConvertTo-RedactedDefenderControlText -Text "[$time] $message")) | Out-Null
            }
        } else {
            $logDir = Join-Path $env:ProgramData 'DefenderControl\logs'
            $logFiles = @()
            if (Test-Path -LiteralPath $logDir) {
                $logFiles = @(Get-ChildItem -LiteralPath $logDir -Filter '*.log' -File -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 10)
            }
            foreach ($logFile in $logFiles) {
                $redactedLines.Add((ConvertTo-RedactedDefenderControlText -Text "--- $($logFile.Name) ---")) | Out-Null
                foreach ($line in @(Get-Content -LiteralPath $logFile.FullName -ErrorAction SilentlyContinue)) {
                    $redactedLines.Add((ConvertTo-RedactedDefenderControlText -Text $line)) | Out-Null
                }
            }
        }
        if ($redactedLines.Count -eq 0) {
            $redactedLines.Add('No DefenderControl operation log entries were found.') | Out-Null
            $warnings.Add('No DefenderControl operation log entries were found.') | Out-Null
        }
        [IO.File]::WriteAllLines((Join-Path $stage 'operation-log-redacted.txt'),
            $redactedLines.ToArray(), [Text.UTF8Encoding]::new($false))
        $logIncluded = $true

        $metadata = [ordered]@{
            schemaVersion = 1
            generatedAt = (Get-Date).ToString('o')
            redacted = $true
            retentionPolicy = [ordered]@{
                days = $script:ManifestRetentionDays
                maxCount = $script:ManifestMaxCount
            }
            files = @('manifest-redacted.json', 'operation-log-redacted.txt')
            warnings = @($warnings)
        }
        [IO.File]::WriteAllText((Join-Path $stage 'export-metadata.json'),
            ($metadata | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $OutputPath -Force
        return [pscustomobject]@{
            Path = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
            ManifestIncluded = $manifestIncluded
            LogIncluded = $logIncluded
            Warnings = @($warnings)
        }
    } finally {
        if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

if ($script:IsCliMode) {
    Invoke-CliMode -Mode $Mode -Expect $Expect -Json:$Json -Silent:$Silent -Eicar:$Eicar -Force:$Force `
        -OutputPath $OutputPath -MpSupportFiles:$MpSupportFiles `
        -ListManifests:$ListManifests -PruneManifests:$PruneManifests `
        -Redact:$Redact -RetentionDays $RetentionDays
    # Invoke-CliMode always exits; defensive fall-through:
    exit $script:EXIT_USAGE
}

# ==================================================================================
#  COMPILE TOKENPRIV (registry ownership P/Invoke) - once in main scope
# ==================================================================================
$privCode = @"
using System;
using System.Runtime.InteropServices;
public class TokenPriv {
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    struct TOKEN_PRIVILEGES { public int PrivilegeCount; public long Luid; public int Attributes; }
    public static void Enable(string privilege) {
        IntPtr token;
        OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x0028, out token);
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Attributes = 2 };
        LookupPrivilegeValue(null, privilege, out tp.Luid);
        AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
"@
if (-not ([System.Management.Automation.PSTypeName]'TokenPriv').Type) {
    Add-Type -TypeDefinition $privCode -Language CSharp
}

# ==================================================================================
#  CLEANUP ORPHAN SCHEDULED TASKS from previous interrupted runs
# ==================================================================================
try {
    Get-ScheduledTask -TaskName "DefCtrl_RegFix_*" -ErrorAction SilentlyContinue |
        ForEach-Object { Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue }
} catch {}

# ==================================================================================
#  XAML GUI
# ==================================================================================
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Defender Control"
        AutomationProperties.Name="Defender Control"
        Width="880" Height="920"
        WindowStartupLocation="CenterScreen"
        ResizeMode="CanMinimize"
        Background="#1a1a2e">
    <Window.Resources>
        <SolidColorBrush x:Key="AccentRed" Color="#e74c3c"/>
        <SolidColorBrush x:Key="AccentGreen" Color="#2ecc71"/>
        <SolidColorBrush x:Key="AccentBlue" Color="#3498db"/>
        <SolidColorBrush x:Key="AccentOrange" Color="#e67e22"/>
        <SolidColorBrush x:Key="CardBg" Color="#16213e"/>
        <SolidColorBrush x:Key="CardBorder" Color="#2a2a4a"/>
        <SolidColorBrush x:Key="TextPrimary" Color="#ecf0f1"/>
        <SolidColorBrush x:Key="TextSecondary" Color="#95a5a6"/>
        <SolidColorBrush x:Key="TextDim" Color="#7f8c8d"/>

        <Style x:Key="ActionButton" TargetType="Button">
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Height" Value="44"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                CornerRadius="8" Padding="20,0">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Opacity" Value="0.85"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="border" Property="Opacity" Value="0.4"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="SmallButton" TargetType="Button">
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Height" Value="30"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                CornerRadius="6" Padding="14,0">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Opacity" Value="0.85"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="Card" TargetType="Border">
            <Setter Property="Background" Value="{StaticResource CardBg}"/>
            <Setter Property="BorderBrush" Value="{StaticResource CardBorder}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="10"/>
            <Setter Property="Padding" Value="20,14"/>
            <Setter Property="Margin" Value="0,0,0,8"/>
        </Style>

        <Style x:Key="DarkCheck" TargetType="CheckBox">
            <Setter Property="Foreground" Value="#95a5a6"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>

        <!-- Full ComboBox ControlTemplate for dark mode -->
        <ControlTemplate x:Key="DarkComboBoxToggleButton" TargetType="ToggleButton">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition/>
                    <ColumnDefinition Width="20"/>
                </Grid.ColumnDefinitions>
                <Border x:Name="Border" Grid.ColumnSpan="2" CornerRadius="6"
                        Background="#2a2a4a" BorderBrush="#3a3a5a" BorderThickness="1"/>
                <Border Grid.Column="0" CornerRadius="6,0,0,6" Margin="1"
                        Background="Transparent"/>
                <Path x:Name="Arrow" Grid.Column="1" Fill="#95a5a6"
                      HorizontalAlignment="Center" VerticalAlignment="Center"
                      Data="M0,0 L4,4 L8,0 Z"/>
            </Grid>
        </ControlTemplate>

        <ControlTemplate x:Key="DarkComboBoxTextBox" TargetType="TextBox">
            <Border x:Name="PART_ContentHost" Focusable="False"
                    Background="Transparent"/>
        </ControlTemplate>

        <Style x:Key="DarkComboBox" TargetType="ComboBox">
            <Setter Property="Foreground" Value="#ecf0f1"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Height" Value="30"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBox">
                        <Grid>
                            <ToggleButton Name="ToggleButton"
                                          Template="{StaticResource DarkComboBoxToggleButton}"
                                          Grid.Column="2" Focusable="False"
                                          IsChecked="{Binding Path=IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"
                                          ClickMode="Press"/>
                            <ContentPresenter Name="ContentSite" IsHitTestVisible="False"
                                              Content="{TemplateBinding SelectionBoxItem}"
                                              ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                                              ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}"
                                              Margin="8,3,28,3" VerticalAlignment="Center"
                                              HorizontalAlignment="Left"/>
                            <Popup Name="Popup" Placement="Bottom"
                                   IsOpen="{TemplateBinding IsDropDownOpen}"
                                   AllowsTransparency="True" Focusable="False"
                                   PopupAnimation="Slide">
                                <Grid Name="DropDown" SnapsToDevicePixels="True"
                                      MinWidth="{TemplateBinding ActualWidth}"
                                      MaxHeight="{TemplateBinding MaxDropDownHeight}">
                                    <Border x:Name="DropDownBorder"
                                            Background="#1e1e3e" BorderThickness="1"
                                            BorderBrush="#3a3a5a" CornerRadius="6"/>
                                    <ScrollViewer Margin="4,6,4,6" SnapsToDevicePixels="True">
                                        <StackPanel IsItemsHost="True"
                                                    KeyboardNavigation.DirectionalNavigation="Contained"/>
                                    </ScrollViewer>
                                </Grid>
                            </Popup>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Setter Property="ItemContainerStyle">
                <Setter.Value>
                    <Style TargetType="ComboBoxItem">
                        <Setter Property="Foreground" Value="#ecf0f1"/>
                        <Setter Property="Background" Value="Transparent"/>
                        <Setter Property="Padding" Value="8,4"/>
                        <Setter Property="Cursor" Value="Hand"/>
                        <Setter Property="Template">
                            <Setter.Value>
                                <ControlTemplate TargetType="ComboBoxItem">
                                    <Border x:Name="Bd" Background="{TemplateBinding Background}"
                                            Padding="{TemplateBinding Padding}" CornerRadius="4">
                                        <ContentPresenter/>
                                    </Border>
                                    <ControlTemplate.Triggers>
                                        <Trigger Property="IsHighlighted" Value="True">
                                            <Setter TargetName="Bd" Property="Background" Value="#2a2a5a"/>
                                        </Trigger>
                                        <Trigger Property="IsSelected" Value="True">
                                            <Setter TargetName="Bd" Property="Background" Value="#3498db"/>
                                        </Trigger>
                                    </ControlTemplate.Triggers>
                                </ControlTemplate>
                            </Setter.Value>
                        </Setter>
                    </Style>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid Margin="24,14,24,16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Grid Grid.Row="0" Margin="0,0,0,12">
            <StackPanel VerticalAlignment="Center">
                <TextBlock x:Name="txtTitle" Text="DEFENDER CONTROL" FontSize="24" FontWeight="Bold"
                           Foreground="{StaticResource TextPrimary}" Margin="0,0,0,2"/>
                <TextBlock x:Name="txtSubtitle" Text="" FontSize="12" Foreground="{StaticResource TextDim}"/>
            </StackPanel>
            <CheckBox x:Name="chkDryRun" Content=" Dry Run (simulate only)"
                      AutomationProperties.Name="Dry run mode"
                      AutomationProperties.HelpText="Simulate the operation without changing Defender settings"
                      Style="{StaticResource DarkCheck}" HorizontalAlignment="Right"
                      VerticalAlignment="Center"/>
        </Grid>

        <!-- Status Card with Buttons -->
        <Border Grid.Row="1" Style="{StaticResource Card}">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" VerticalAlignment="Center">
                    <TextBlock Text="Defender Status" FontSize="13"
                               Foreground="{StaticResource TextSecondary}" Margin="0,0,0,3"/>
                    <TextBlock x:Name="txtStatus" Text="Checking..."
                               AutomationProperties.Name="Defender status: checking"
                               FontSize="20" FontWeight="Bold"
                               Foreground="{StaticResource AccentOrange}"/>
                    <TextBlock x:Name="txtTamper" Text=""
                               AutomationProperties.Name="Tamper protection status"
                               FontSize="12"
                               Foreground="{StaticResource TextDim}" Margin="0,3,0,0"/>
                </StackPanel>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                    <Button x:Name="btnRefresh" Content="Refresh"
                            AutomationProperties.Name="Refresh Defender status"
                            Background="#2a2a4a"
                            Style="{StaticResource SmallButton}" Margin="0,0,8,0"/>
                    <Button x:Name="btnDisable" Content="  Disable Defender  "
                            AutomationProperties.Name="Disable Defender"
                            Background="{StaticResource AccentRed}"
                            Style="{StaticResource ActionButton}"/>
                    <Button x:Name="btnEnable" Content="  Enable Defender  "
                            AutomationProperties.Name="Enable Defender"
                            Background="{StaticResource AccentGreen}"
                            Style="{StaticResource ActionButton}" Margin="8,0,0,0"/>
                    <Button x:Name="btnReboot" Content="  Reboot Now  "
                            AutomationProperties.Name="Reboot now"
                            Background="#8e44ad"
                            Style="{StaticResource ActionButton}" Margin="8,0,0,0" Visibility="Collapsed"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Live Status Dashboard -->
        <Border Grid.Row="2" Style="{StaticResource Card}">
            <StackPanel>
                <TextBlock Text="Live Status Dashboard" FontSize="13" FontWeight="SemiBold"
                           Foreground="{StaticResource TextSecondary}" Margin="0,0,0,8"/>
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <!-- Row 0 -->
                    <StackPanel Grid.Row="0" Grid.Column="0" Margin="0,0,12,6">
                        <TextBlock Text="Real-Time Protection" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashRTP" Text="--" AutomationProperties.Name="Real-time protection status"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>
                    <StackPanel Grid.Row="0" Grid.Column="1" Margin="0,0,12,6">
                        <TextBlock Text="Tamper Protection" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashTamper" Text="--" AutomationProperties.Name="Tamper protection status"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>
                    <StackPanel Grid.Row="0" Grid.Column="2" Margin="0,0,12,6">
                        <TextBlock Text="Cloud Protection" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashCloud" Text="--" AutomationProperties.Name="Cloud protection status"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>

                    <!-- Row 1 -->
                    <StackPanel Grid.Row="1" Grid.Column="0" Margin="0,0,12,6">
                        <TextBlock Text="Firewall" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashFirewall" Text="--" AutomationProperties.Name="Firewall status"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>
                    <StackPanel Grid.Row="1" Grid.Column="1" Margin="0,0,12,6">
                        <TextBlock Text="Defender Service (WinDefend)" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashService" Text="--" AutomationProperties.Name="Defender service status"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>
                    <StackPanel Grid.Row="1" Grid.Column="2" Margin="0,0,12,6">
                        <TextBlock Text="Anti-Spyware Status" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashAntiSpy" Text="--" AutomationProperties.Name="Anti-spyware status"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>

                    <!-- Row 2: PPL Status -->
                    <StackPanel Grid.Row="2" Grid.Column="0" Margin="0,0,12,6">
                        <TextBlock Text="PPL: MsMpEng" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashPplMsMpEng" Text="--" AutomationProperties.Name="MsMpEng protected process status"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>
                    <StackPanel Grid.Row="2" Grid.Column="1" Margin="0,0,12,6">
                        <TextBlock Text="PPL: WdFilter / WdBoot" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashPplWdFilter" Text="--" AutomationProperties.Name="WdFilter and WdBoot protected process status"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>
                    <StackPanel Grid.Row="2" Grid.Column="2" Margin="0,0,12,6">
                        <TextBlock Text="PPL: WdNisDrv" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashPplWdNisDrv" Text="--" AutomationProperties.Name="WdNisDrv protected process status"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>

                    <!-- Row 3: Defender for Endpoint / passive mode -->
                    <StackPanel Grid.Row="3" Grid.Column="0" Margin="0,0,12,6">
                        <TextBlock Text="Defender Mode" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashMode" Text="--" AutomationProperties.Name="Defender mode"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>
                    <StackPanel Grid.Row="3" Grid.Column="1" Margin="0,0,12,6">
                        <TextBlock Text="Platform Version" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashPlatform" Text="--" AutomationProperties.Name="Defender platform version"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>
                    <StackPanel Grid.Row="3" Grid.Column="2" Margin="0,0,12,6">
                        <TextBlock Text="MDE / Managed Signals" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashMde" Text="--" AutomationProperties.Name="Defender for Endpoint and managed signals"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>

                    <!-- Row 4 -->
                    <StackPanel Grid.Row="4" Grid.Column="0" Grid.ColumnSpan="3" Margin="0,0,12,0">
                        <TextBlock Text="Last Definition Update" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashDefUpdate" Text="--" AutomationProperties.Name="Last Defender definition update"
                                   FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>

                    <!-- Refresh Dashboard button -->
                    <Button x:Name="btnRefreshDash" Content="Refresh Status"
                            AutomationProperties.Name="Refresh live Defender status"
                            Background="#2a2a4a"
                            Style="{StaticResource SmallButton}" Grid.Row="0" Grid.Column="3"
                            VerticalAlignment="Top" Margin="4,0,0,0"/>
                </Grid>
            </StackPanel>
        </Border>

        <!-- Tamper Protection Warning Panel (hidden by default) -->
        <Border x:Name="tamperWarningPanel" Grid.Row="3" Visibility="Collapsed"
                AutomationProperties.Name="Tamper protection warning"
                Background="#2d1a1a" BorderBrush="#e74c3c" BorderThickness="1"
                CornerRadius="10" Padding="16,12" Margin="0,0,0,8">
            <StackPanel>
                <TextBlock Text="!! TAMPER PROTECTION IS ON !!" FontSize="14" FontWeight="Bold"
                           Foreground="#e74c3c" Margin="0,0,0,6"/>
                <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#e8a0a0"
                           Text="Tamper Protection prevents scripts and tools from modifying Defender settings. You must disable it manually before using the Disable button."/>
                <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#ecf0f1" Margin="0,8,0,0"
                           Text="Steps to disable Tamper Protection:"/>
                <TextBlock FontSize="12" Foreground="#b0bec5" Margin="12,4,0,0"
                           Text="1. Open Windows Security (search 'Windows Security' in Start)"/>
                <TextBlock FontSize="12" Foreground="#b0bec5" Margin="12,2,0,0"
                           Text="2. Click 'Virus &amp; threat protection'"/>
                <TextBlock FontSize="12" Foreground="#b0bec5" Margin="12,2,0,0"
                           Text="3. Under 'Virus &amp; threat protection settings', click 'Manage settings'"/>
                <TextBlock FontSize="12" Foreground="#b0bec5" Margin="12,2,0,0"
                           Text="4. Scroll down to 'Tamper Protection' and toggle it OFF"/>
                <TextBlock FontSize="12" Foreground="#b0bec5" Margin="12,2,0,0"
                           Text="5. Click 'Refresh Status' above to update the dashboard"/>
                <Button x:Name="btnOpenWSecurity" Content="Open Windows Security"
                        AutomationProperties.Name="Open Windows Security"
                        Background="#3a2020"
                        Style="{StaticResource SmallButton}" HorizontalAlignment="Left" Margin="0,8,0,0"/>
            </StackPanel>
        </Border>

        <!-- Managed device warning panel (hidden by default) -->
        <Border x:Name="managedWarningPanel" Grid.Row="4" Visibility="Collapsed"
                AutomationProperties.Name="Managed Defender warning"
                Background="#2d2418" BorderBrush="#e67e22" BorderThickness="1"
                CornerRadius="10" Padding="16,12" Margin="0,0,0,8">
            <StackPanel>
                <TextBlock Text="!! MANAGED DEFENDER SIGNALS DETECTED !!" FontSize="14" FontWeight="Bold"
                           Foreground="#e67e22" Margin="0,0,0,6"/>
                <TextBlock x:Name="txtManagedWarning" TextWrapping="Wrap"
                           AutomationProperties.Name="Managed Defender warning details"
                           FontSize="12" Foreground="#f0c58a"/>
                <TextBlock Text="Disable/Enable operations may be overridden by Microsoft Defender for Endpoint, Intune, or other device policy. Contact your security administrator before proceeding."
                           TextWrapping="Wrap" FontSize="12" Foreground="#ecf0f1" Margin="0,8,0,0"/>
            </StackPanel>
        </Border>

        <!-- Scheduled Re-Enable -->
        <Border Grid.Row="5" Style="{StaticResource Card}">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock Grid.Column="0" Text="Schedule Re-Enable:" FontSize="12"
                           Foreground="{StaticResource TextSecondary}" VerticalAlignment="Center"
                           Margin="0,0,8,0"/>
                <ComboBox x:Name="cmbScheduleHours" Grid.Column="1"
                          AutomationProperties.Name="Re-enable schedule duration"
                          Style="{StaticResource DarkComboBox}" Width="80" Margin="0,0,8,0">
                    <ComboBoxItem Content="1 hour" IsSelected="True"/>
                    <ComboBoxItem Content="2 hours"/>
                    <ComboBoxItem Content="4 hours"/>
                    <ComboBoxItem Content="8 hours"/>
                    <ComboBoxItem Content="24 hours"/>
                </ComboBox>
                <Button x:Name="btnSchedule" Content="Schedule"
                        AutomationProperties.Name="Schedule Defender re-enable"
                        Background="#8e44ad"
                        Style="{StaticResource SmallButton}" Grid.Column="2" Margin="0,0,8,0"/>
                <TextBlock x:Name="txtScheduleStatus" Grid.Column="3" Text=""
                           AutomationProperties.Name="Re-enable schedule status"
                           FontSize="11"
                           Foreground="{StaticResource TextDim}" VerticalAlignment="Center"/>
                <Button x:Name="btnCancelSchedule" Content="Cancel"
                        AutomationProperties.Name="Cancel Defender re-enable schedule"
                        Background="#c0392b"
                        Style="{StaticResource SmallButton}" Grid.Column="4" Visibility="Collapsed"/>
            </Grid>
        </Border>

        <!-- Progress Bar -->
        <Border Grid.Row="6" Background="#16213e" CornerRadius="4" Height="6" Margin="0,0,0,8">
            <ProgressBar x:Name="progressBar" Minimum="0" Maximum="100" Value="0"
                         AutomationProperties.Name="Defender operation progress"
                         Height="6" Background="Transparent" Foreground="#3498db"
                         BorderThickness="0"/>
        </Border>

        <!-- Log Header -->
        <Grid Grid.Row="7" Margin="0,0,0,0">
            <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                <TextBlock Text="Operation Log" FontSize="13" FontWeight="SemiBold"
                           Foreground="{StaticResource TextSecondary}" VerticalAlignment="Center"/>
                <TextBlock x:Name="txtRunning" Text=""
                           AutomationProperties.Name="Current Defender operation"
                           FontSize="12"
                           Foreground="{StaticResource AccentOrange}" Margin="12,0,0,0"
                           VerticalAlignment="Center"/>
            </StackPanel>
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
                <CheckBox x:Name="chkVerbose" Content=" Verbose" IsChecked="True"
                          AutomationProperties.Name="Show verbose operation log entries"
                          Style="{StaticResource DarkCheck}" Margin="0,0,12,0"/>
                <Button x:Name="btnExport" Content="Export"
                        AutomationProperties.Name="Export operation log"
                        Background="#2a2a4a"
                        Style="{StaticResource SmallButton}" Margin="0,0,6,0"/>
                <Button x:Name="btnSupportBundle" Content="Support Bundle"
                        AutomationProperties.Name="Create Defender support bundle"
                        Background="#2a2a4a"
                        Style="{StaticResource SmallButton}" Margin="0,0,6,0"/>
                <Button x:Name="btnListManifests" Content="Manifests"
                        AutomationProperties.Name="List audit manifests"
                        Background="#2a2a4a"
                        Style="{StaticResource SmallButton}" Margin="0,0,6,0"/>
                <Button x:Name="btnRedactExport" Content="Redact"
                        AutomationProperties.Name="Export redacted manifests and logs"
                        Background="#2a2a4a"
                        Style="{StaticResource SmallButton}" Margin="0,0,6,0"/>
                <Button x:Name="btnPruneManifests" Content="Prune"
                        AutomationProperties.Name="Prune old audit manifests"
                        Background="#2a2a4a"
                        Style="{StaticResource SmallButton}" Margin="0,0,6,0"/>
                <Button x:Name="btnClearLog" Content="Clear"
                        AutomationProperties.Name="Clear operation log"
                        Background="#2a2a4a"
                        Style="{StaticResource SmallButton}"/>
            </StackPanel>
        </Grid>

        <!-- Log Body -->
        <Border Grid.Row="8" Style="{StaticResource Card}" Margin="0,6,0,0">
            <Border Background="#0f1729" CornerRadius="6" Padding="4">
                <ScrollViewer x:Name="logScroll" AutomationProperties.Name="Operation log scroll area"
                              VerticalScrollBarVisibility="Auto">
                    <RichTextBox x:Name="rtbLog" AutomationProperties.Name="Defender operation log"
                                 Background="Transparent" BorderThickness="0"
                                 IsReadOnly="True" FontFamily="Cascadia Code,Consolas,Courier New"
                                 FontSize="12" Foreground="#b0bec5" VerticalScrollBarVisibility="Disabled"
                                 Padding="10,6">
                        <RichTextBox.Resources>
                            <Style TargetType="Paragraph">
                                <Setter Property="Margin" Value="0,1,0,1"/>
                            </Style>
                        </RichTextBox.Resources>
                        <FlowDocument/>
                    </RichTextBox>
                </ScrollViewer>
            </Border>
        </Border>

        <!-- Footer -->
        <Grid Grid.Row="9" Margin="0,8,0,0">
            <TextBlock Text="Windows Firewall is NOT affected by this tool."
                       FontSize="11" Foreground="{StaticResource TextDim}" VerticalAlignment="Center"/>
            <TextBlock x:Name="txtVersion" Text=""
                       FontSize="11" Foreground="{StaticResource TextDim}"
                       HorizontalAlignment="Right" VerticalAlignment="Center"/>
        </Grid>
    </Grid>
</Window>
"@

# ==================================================================================
#  LOAD WINDOW & CONTROLS
# ==================================================================================
$reader  = [System.Xml.XmlNodeReader]::new($xaml)
$window  = [Windows.Markup.XamlReader]::Load($reader)

$txtTitle    = $window.FindName("txtTitle")
$txtSubtitle = $window.FindName("txtSubtitle")
$txtStatus   = $window.FindName("txtStatus")
$txtTamper   = $window.FindName("txtTamper")
$txtRunning  = $window.FindName("txtRunning")
$txtVersion  = $window.FindName("txtVersion")
$rtbLog      = $window.FindName("rtbLog")
$logScroll   = $window.FindName("logScroll")
$btnDisable  = $window.FindName("btnDisable")
$btnEnable   = $window.FindName("btnEnable")
$btnRefresh  = $window.FindName("btnRefresh")
$btnReboot   = $window.FindName("btnReboot")
$btnExport   = $window.FindName("btnExport")
$btnSupportBundle = $window.FindName("btnSupportBundle")
$btnListManifests = $window.FindName("btnListManifests")
$btnRedactExport = $window.FindName("btnRedactExport")
$btnPruneManifests = $window.FindName("btnPruneManifests")
$btnClearLog = $window.FindName("btnClearLog")
$chkDryRun   = $window.FindName("chkDryRun")
$chkVerbose  = $window.FindName("chkVerbose")
$progressBar = $window.FindName("progressBar")

# Dashboard controls
$dashRTP       = $window.FindName("dashRTP")
$dashTamper    = $window.FindName("dashTamper")
$dashCloud     = $window.FindName("dashCloud")
$dashFirewall  = $window.FindName("dashFirewall")
$dashService   = $window.FindName("dashService")
$dashAntiSpy   = $window.FindName("dashAntiSpy")
$dashDefUpdate  = $window.FindName("dashDefUpdate")
$dashMode       = $window.FindName("dashMode")
$dashPlatform   = $window.FindName("dashPlatform")
$dashMde        = $window.FindName("dashMde")
$dashPplMsMpEng = $window.FindName("dashPplMsMpEng")
$dashPplWdFilter = $window.FindName("dashPplWdFilter")
$dashPplWdNisDrv = $window.FindName("dashPplWdNisDrv")
$btnRefreshDash = $window.FindName("btnRefreshDash")

# Tamper Protection warning panel
$tamperWarningPanel = $window.FindName("tamperWarningPanel")
$btnOpenWSecurity   = $window.FindName("btnOpenWSecurity")
$managedWarningPanel = $window.FindName("managedWarningPanel")
$txtManagedWarning  = $window.FindName("txtManagedWarning")

# Scheduled re-enable controls
$cmbScheduleHours  = $window.FindName("cmbScheduleHours")
$btnSchedule       = $window.FindName("btnSchedule")
$txtScheduleStatus = $window.FindName("txtScheduleStatus")
$btnCancelSchedule = $window.FindName("btnCancelSchedule")

# Set dynamic text
$txtSubtitle.Text = "Comprehensive Microsoft Defender Management  |  $script:OSDetail"
$txtVersion.Text  = "v$script:Version  |  Running as Administrator"

function Set-AutomationStateName {
    param(
        [Parameter(Mandatory)][object]$Element,
        [Parameter(Mandatory)][string]$Label,
        [AllowNull()][object]$Value
    )
    $display = [string]$Value
    if ([string]::IsNullOrWhiteSpace($display)) { $display = 'unknown' }
    [System.Windows.Automation.AutomationProperties]::SetName(
        $Element, ("{0}: {1}" -f $Label, $display))
}

Set-AutomationStateName $txtStatus 'Defender status' $txtStatus.Text
Set-AutomationStateName $txtTamper 'Tamper protection' $txtTamper.Text
Set-AutomationStateName $txtRunning 'Current Defender operation' $txtRunning.Text
Set-AutomationStateName $txtScheduleStatus 'Re-enable schedule' $txtScheduleStatus.Text

# ==================================================================================
#  THREAD-SAFE QUEUES & LOG STORAGE
# ==================================================================================
$script:LogQueue    = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
$script:StatusQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
$script:DashQueue   = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
$script:IsRunning   = $false
$script:AllLogEntries = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())

function Queue-Log {
    param([string]$Message, [string]$Color = "#b0bec5", [string]$Level = "info")
    $script:LogQueue.Enqueue(@{ Message = $Message; Color = $Color; Time = (Get-Date -Format "HH:mm:ss"); Level = $Level })
}
function Queue-Success { param([string]$Msg) Queue-Log $Msg "#2ecc71" "success" }
function Queue-Warn    { param([string]$Msg) Queue-Log $Msg "#e67e22" "warn" }
function Queue-Err     { param([string]$Msg) Queue-Log $Msg "#e74c3c" "error" }
function Queue-Info    { param([string]$Msg) Queue-Log $Msg "#3498db" "info" }
function Queue-Verbose { param([string]$Msg) Queue-Log $Msg "#7f8c8d" "verbose" }
function Queue-Phase   { param([string]$Msg) Queue-Log $Msg "#bb86fc" "phase" }
function Queue-Status {
    param([string]$StatusText, [string]$StatusColor, [string]$TamperText, [string]$TamperColor,
          [bool]$DisableBtn, [bool]$EnableBtn, [int]$Progress = -1, [string]$RunningText = "",
          [string]$ShowReboot = "")
    $script:StatusQueue.Enqueue(@{
        StatusText = $StatusText; StatusColor = $StatusColor
        TamperText = $TamperText; TamperColor = $TamperColor
        DisableBtn = $DisableBtn; EnableBtn   = $EnableBtn
        Progress   = $Progress;   RunningText = $RunningText
        ShowReboot = $ShowReboot
    })
}
function Queue-Dashboard {
    param([string]$RTP, [string]$RTPColor,
          [string]$Tamper, [string]$TamperColor,
          [string]$Cloud, [string]$CloudColor,
          [string]$Firewall, [string]$FirewallColor,
          [string]$Service, [string]$ServiceColor,
          [string]$AntiSpy, [string]$AntiSpyColor,
          [string]$DefUpdate, [string]$DefUpdateColor,
          [string]$PplMsMpEng = "--", [string]$PplMsMpEngColor = "#7f8c8d",
          [string]$PplWdFilter = "--", [string]$PplWdFilterColor = "#7f8c8d",
          [string]$PplWdNisDrv = "--", [string]$PplWdNisDrvColor = "#7f8c8d",
          [string]$DefenderMode = "--", [string]$DefenderModeColor = "#7f8c8d",
          [string]$PlatformVersion = "--", [string]$PlatformVersionColor = "#7f8c8d",
          [string]$MdeStatus = "--", [string]$MdeStatusColor = "#7f8c8d",
          [string]$ManagedWarning = "",
          [bool]$ShowTamperWarning = $false)
    $script:DashQueue.Enqueue(@{
        RTP = $RTP; RTPColor = $RTPColor
        Tamper = $Tamper; TamperColor = $TamperColor
        Cloud = $Cloud; CloudColor = $CloudColor
        Firewall = $Firewall; FirewallColor = $FirewallColor
        Service = $Service; ServiceColor = $ServiceColor
        AntiSpy = $AntiSpy; AntiSpyColor = $AntiSpyColor
        DefUpdate = $DefUpdate; DefUpdateColor = $DefUpdateColor
        PplMsMpEng = $PplMsMpEng; PplMsMpEngColor = $PplMsMpEngColor
        PplWdFilter = $PplWdFilter; PplWdFilterColor = $PplWdFilterColor
        PplWdNisDrv = $PplWdNisDrv; PplWdNisDrvColor = $PplWdNisDrvColor
        DefenderMode = $DefenderMode; DefenderModeColor = $DefenderModeColor
        PlatformVersion = $PlatformVersion; PlatformVersionColor = $PlatformVersionColor
        MdeStatus = $MdeStatus; MdeStatusColor = $MdeStatusColor
        ManagedWarning = $ManagedWarning
        ShowTamperWarning = $ShowTamperWarning
    })
}

# -- Helper: render one log entry as a RichTextBox paragraph -------------------------
function Add-LogParagraph {
    param([hashtable]$Entry)
    $para = [System.Windows.Documents.Paragraph]::new()
    $para.Margin = [System.Windows.Thickness]::new(0,1,0,1)
    $timeRun = [System.Windows.Documents.Run]::new("[$($Entry.Time)] ")
    $timeRun.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#546e7a")
    $para.Inlines.Add($timeRun)
    $msgRun = [System.Windows.Documents.Run]::new($Entry.Message)
    $msgRun.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($Entry.Color)
    $para.Inlines.Add($msgRun)
    $rtbLog.Document.Blocks.Add($para)
}

# -- Helper: rebuild log from stored entries (used by verbose toggle) ----------------
function Rebuild-Log {
    $rtbLog.Document.Blocks.Clear()
    foreach ($entry in $script:AllLogEntries) {
        if ($entry.Level -eq "verbose" -and -not $script:ShowVerbose) { continue }
        Add-LogParagraph $entry
    }
    $rtbLog.ScrollToEnd()
    $logScroll.ScrollToEnd()
}

# ==================================================================================
#  UI TIMER (drains queues on UI thread every 50ms)
# ==================================================================================
$script:uiTimer = [System.Windows.Threading.DispatcherTimer]::new()
$script:uiTimer.Interval = [TimeSpan]::FromMilliseconds(50)
$script:uiTimer.Add_Tick({
    $entry = $null
    $count = 0
    while ($script:LogQueue.TryDequeue([ref]$entry) -and $count -lt 40) {
        $count++
        $script:AllLogEntries.Add($entry) | Out-Null
        if ($entry.Level -eq "verbose" -and -not $script:ShowVerbose) { continue }
        Add-LogParagraph $entry
    }
    if ($count -gt 0) { $rtbLog.ScrollToEnd(); $logScroll.ScrollToEnd() }

    $st = $null
    while ($script:StatusQueue.TryDequeue([ref]$st)) {
        if ($st.StatusText) {
            $txtStatus.Text = $st.StatusText
            $txtStatus.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($st.StatusColor)
            Set-AutomationStateName $txtStatus 'Defender status' $st.StatusText
        }
        if ($null -ne $st.TamperText -and $st.TamperText -ne "") {
            $txtTamper.Text = $st.TamperText
            $txtTamper.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($st.TamperColor)
            Set-AutomationStateName $txtTamper 'Tamper protection' $st.TamperText
        } else {
            Set-AutomationStateName $txtTamper 'Tamper protection' 'not reported'
        }
        $btnDisable.IsEnabled = $st.DisableBtn
        $btnEnable.IsEnabled  = $st.EnableBtn
        $btnRefresh.IsEnabled = (-not $script:IsRunning)
        if ($st.Progress -ge 0) { $progressBar.Value = $st.Progress }
        $txtRunning.Text = $st.RunningText
        Set-AutomationStateName $txtRunning 'Current Defender operation' $st.RunningText
        if ($st.ShowReboot -eq "show")    { $btnReboot.Visibility = "Visible" }
        if ($st.ShowReboot -eq "hide")    { $btnReboot.Visibility = "Collapsed" }
    }

    # Drain dashboard queue
    $dsh = $null
    while ($script:DashQueue.TryDequeue([ref]$dsh)) {
        $bc = [System.Windows.Media.BrushConverter]::new()
        $dashRTP.Text = $dsh.RTP
        $dashRTP.Foreground = $bc.ConvertFromString($dsh.RTPColor)
        Set-AutomationStateName $dashRTP 'Real-time protection' $dsh.RTP
        $dashTamper.Text = $dsh.Tamper
        $dashTamper.Foreground = $bc.ConvertFromString($dsh.TamperColor)
        Set-AutomationStateName $dashTamper 'Tamper protection' $dsh.Tamper
        $dashCloud.Text = $dsh.Cloud
        $dashCloud.Foreground = $bc.ConvertFromString($dsh.CloudColor)
        Set-AutomationStateName $dashCloud 'Cloud protection' $dsh.Cloud
        $dashFirewall.Text = $dsh.Firewall
        $dashFirewall.Foreground = $bc.ConvertFromString($dsh.FirewallColor)
        Set-AutomationStateName $dashFirewall 'Firewall' $dsh.Firewall
        $dashService.Text = $dsh.Service
        $dashService.Foreground = $bc.ConvertFromString($dsh.ServiceColor)
        Set-AutomationStateName $dashService 'Defender service' $dsh.Service
        $dashAntiSpy.Text = $dsh.AntiSpy
        $dashAntiSpy.Foreground = $bc.ConvertFromString($dsh.AntiSpyColor)
        Set-AutomationStateName $dashAntiSpy 'Anti-spyware' $dsh.AntiSpy
        $dashDefUpdate.Text = $dsh.DefUpdate
        $dashDefUpdate.Foreground = $bc.ConvertFromString($dsh.DefUpdateColor)
        Set-AutomationStateName $dashDefUpdate 'Last Defender definition update' $dsh.DefUpdate
        if ($dsh.PplMsMpEng) {
            $dashPplMsMpEng.Text = $dsh.PplMsMpEng
            $dashPplMsMpEng.Foreground = $bc.ConvertFromString($dsh.PplMsMpEngColor)
            Set-AutomationStateName $dashPplMsMpEng 'MsMpEng protected process' $dsh.PplMsMpEng
        }
        if ($dsh.PplWdFilter) {
            $dashPplWdFilter.Text = $dsh.PplWdFilter
            $dashPplWdFilter.Foreground = $bc.ConvertFromString($dsh.PplWdFilterColor)
            Set-AutomationStateName $dashPplWdFilter 'WdFilter and WdBoot protected process' $dsh.PplWdFilter
        }
        if ($dsh.PplWdNisDrv) {
            $dashPplWdNisDrv.Text = $dsh.PplWdNisDrv
            $dashPplWdNisDrv.Foreground = $bc.ConvertFromString($dsh.PplWdNisDrvColor)
            Set-AutomationStateName $dashPplWdNisDrv 'WdNisDrv protected process' $dsh.PplWdNisDrv
        }
        if ($dsh.DefenderMode) {
            $dashMode.Text = $dsh.DefenderMode
            $dashMode.Foreground = $bc.ConvertFromString($dsh.DefenderModeColor)
            Set-AutomationStateName $dashMode 'Defender mode' $dsh.DefenderMode
        }
        if ($dsh.PlatformVersion) {
            $dashPlatform.Text = $dsh.PlatformVersion
            $dashPlatform.Foreground = $bc.ConvertFromString($dsh.PlatformVersionColor)
            Set-AutomationStateName $dashPlatform 'Defender platform version' $dsh.PlatformVersion
        }
        if ($dsh.MdeStatus) {
            $dashMde.Text = $dsh.MdeStatus
            $dashMde.Foreground = $bc.ConvertFromString($dsh.MdeStatusColor)
            Set-AutomationStateName $dashMde 'Defender for Endpoint and managed signals' $dsh.MdeStatus
        }
        if ($dsh.ShowTamperWarning) {
            $tamperWarningPanel.Visibility = "Visible"
            $btnDisable.ToolTip = "Tamper Protection must be disabled first. See the warning panel below for instructions."
        } else {
            $tamperWarningPanel.Visibility = "Collapsed"
            $btnDisable.ToolTip = $null
        }
        if ($dsh.ManagedWarning) {
            $txtManagedWarning.Text = $dsh.ManagedWarning
            $managedWarningPanel.Visibility = "Visible"
            Set-AutomationStateName $txtManagedWarning 'Managed Defender warning' $dsh.ManagedWarning
        } else {
            $txtManagedWarning.Text = ""
            $managedWarningPanel.Visibility = "Collapsed"
            Set-AutomationStateName $txtManagedWarning 'Managed Defender warning' 'none'
        }
    }
})
$script:uiTimer.Start()

# ==================================================================================
#  SHARED FUNCTIONS (injected into runspaces via double-quoted here-string)
# ==================================================================================
$script:SharedFunctions = @"
function Queue-Log {
    param([string]`$Message, [string]`$Color = "#b0bec5", [string]`$Level = "info")
    `$LogQueue.Enqueue(@{ Message = `$Message; Color = `$Color; Time = (Get-Date -Format "HH:mm:ss"); Level = `$Level })
}
function Queue-Success { param([string]`$Msg) Queue-Log `$Msg "#2ecc71" "success" }
function Queue-Warn    { param([string]`$Msg) Queue-Log `$Msg "#e67e22" "warn" }
function Queue-Err     { param([string]`$Msg) Queue-Log `$Msg "#e74c3c" "error" }
function Queue-Info    { param([string]`$Msg) Queue-Log `$Msg "#3498db" "info" }
function Queue-Verbose { param([string]`$Msg) Queue-Log `$Msg "#7f8c8d" "verbose" }
function Queue-Phase   { param([string]`$Msg) Queue-Log `$Msg "#bb86fc" "phase" }
function Queue-Status {
    param([string]`$StatusText, [string]`$StatusColor, [string]`$TamperText, [string]`$TamperColor,
          [bool]`$DisableBtn, [bool]`$EnableBtn, [int]`$Progress = -1, [string]`$RunningText = "",
          [string]`$ShowReboot = "")
    `$StatusQueue.Enqueue(@{
        StatusText = `$StatusText; StatusColor = `$StatusColor
        TamperText = `$TamperText; TamperColor = `$TamperColor
        DisableBtn = `$DisableBtn; EnableBtn   = `$EnableBtn
        Progress   = `$Progress;   RunningText = `$RunningText
        ShowReboot = `$ShowReboot
    })
}
function Queue-Dashboard {
    param([string]`$RTP, [string]`$RTPColor,
          [string]`$Tamper, [string]`$TamperColor,
          [string]`$Cloud, [string]`$CloudColor,
          [string]`$Firewall, [string]`$FirewallColor,
          [string]`$Service, [string]`$ServiceColor,
          [string]`$AntiSpy, [string]`$AntiSpyColor,
          [string]`$DefUpdate, [string]`$DefUpdateColor,
          [string]`$PplMsMpEng = "--", [string]`$PplMsMpEngColor = "#7f8c8d",
          [string]`$PplWdFilter = "--", [string]`$PplWdFilterColor = "#7f8c8d",
          [string]`$PplWdNisDrv = "--", [string]`$PplWdNisDrvColor = "#7f8c8d",
          [string]`$DefenderMode = "--", [string]`$DefenderModeColor = "#7f8c8d",
          [string]`$PlatformVersion = "--", [string]`$PlatformVersionColor = "#7f8c8d",
          [string]`$MdeStatus = "--", [string]`$MdeStatusColor = "#7f8c8d",
          [string]`$ManagedWarning = "",
          [bool]`$ShowTamperWarning = `$false)
    `$DashQueue.Enqueue(@{
        RTP = `$RTP; RTPColor = `$RTPColor
        Tamper = `$Tamper; TamperColor = `$TamperColor
        Cloud = `$Cloud; CloudColor = `$CloudColor
        Firewall = `$Firewall; FirewallColor = `$FirewallColor
        Service = `$Service; ServiceColor = `$ServiceColor
        AntiSpy = `$AntiSpy; AntiSpyColor = `$AntiSpyColor
        DefUpdate = `$DefUpdate; DefUpdateColor = `$DefUpdateColor
        PplMsMpEng = `$PplMsMpEng; PplMsMpEngColor = `$PplMsMpEngColor
        PplWdFilter = `$PplWdFilter; PplWdFilterColor = `$PplWdFilterColor
        PplWdNisDrv = `$PplWdNisDrv; PplWdNisDrvColor = `$PplWdNisDrvColor
        DefenderMode = `$DefenderMode; DefenderModeColor = `$DefenderModeColor
        PlatformVersion = `$PlatformVersion; PlatformVersionColor = `$PlatformVersionColor
        MdeStatus = `$MdeStatus; MdeStatusColor = `$MdeStatusColor
        ManagedWarning = `$ManagedWarning
        ShowTamperWarning = `$ShowTamperWarning
    })
}
function Get-DefenderEndpointState {
    param(`$MpStatus = `$null)
    `$state = [ordered]@{
        AMRunningMode               = `$null
        DefenderMode                = 'Unknown'
        AMProductVersion            = `$null
        DefenderPlatformVersion     = `$null
        AMEngineVersion             = `$null
        AMServiceVersion            = `$null
        IsTamperProtected           = `$null
        ForceDefenderPassiveMode    = `$null
        MDEStatusKeyPresent         = `$false
        MDEOnboardingState          = `$null
        MDESenseIsRunning           = `$null
        MDEOrgIdPresent             = `$false
        MDEOnboarded                = `$false
        ManagedDefenderProductType  = `$null
        TPExclusions                = `$null
        ManagedTamperProtection     = `$false
        ManagedDevice               = `$false
        ManagedDeviceWarning        = `$null
    }

    if (`$null -eq `$MpStatus) {
        try { `$MpStatus = Get-MpComputerStatus -ErrorAction Stop } catch {}
    }
    if (`$MpStatus) {
        `$runningMode = `$MpStatus.PSObject.Properties['AMRunningMode']
        if (`$runningMode) { `$state.AMRunningMode = "`$(`$runningMode.Value)" }
        `$productVersion = `$MpStatus.PSObject.Properties['AMProductVersion']
        if (`$productVersion) {
            `$state.AMProductVersion = "`$(`$productVersion.Value)"
            `$state.DefenderPlatformVersion = `$state.AMProductVersion
        }
        `$engineVersion = `$MpStatus.PSObject.Properties['AMEngineVersion']
        if (`$engineVersion) { `$state.AMEngineVersion = "`$(`$engineVersion.Value)" }
        `$serviceVersion = `$MpStatus.PSObject.Properties['AMServiceVersion']
        if (`$serviceVersion) { `$state.AMServiceVersion = "`$(`$serviceVersion.Value)" }
        `$tamper = `$MpStatus.PSObject.Properties['IsTamperProtected']
        if (`$tamper) { `$state.IsTamperProtected = [bool]`$tamper.Value }
    }

    `$passivePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
    `$mdeStatusPath     = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
    `$managedPath       = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
    `$featuresPath      = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
    try {
        `$passiveReg = Get-ItemProperty -LiteralPath `$passivePolicyPath -Name 'ForceDefenderPassiveMode' -ErrorAction SilentlyContinue
        if (`$null -ne `$passiveReg) { `$state.ForceDefenderPassiveMode = [int]`$passiveReg.ForceDefenderPassiveMode }
    } catch {}
    try {
        if (Test-Path -LiteralPath `$mdeStatusPath) {
            `$state.MDEStatusKeyPresent = `$true
            `$mdeStatus = Get-ItemProperty -LiteralPath `$mdeStatusPath -ErrorAction SilentlyContinue
            if (`$mdeStatus) {
                `$onboarding = `$mdeStatus.PSObject.Properties['OnboardingState']
                if (`$onboarding) { `$state.MDEOnboardingState = [int]`$onboarding.Value }
                `$senseRunning = `$mdeStatus.PSObject.Properties['SenseIsRunning']
                if (`$senseRunning) { `$state.MDESenseIsRunning = [int]`$senseRunning.Value }
                `$orgId = `$mdeStatus.PSObject.Properties['OrgId']
                `$orgText = if (`$orgId) { [string]`$orgId.Value } else { '' }
                if (-not [string]::IsNullOrWhiteSpace(`$orgText)) { `$state.MDEOrgIdPresent = `$true }
            }
        }
    } catch {}
    try {
        `$managedReg = Get-ItemProperty -LiteralPath `$managedPath -Name 'ManagedDefenderProductType' -ErrorAction SilentlyContinue
        if (`$null -ne `$managedReg) { `$state.ManagedDefenderProductType = [int]`$managedReg.ManagedDefenderProductType }
    } catch {}
    try {
        `$tpReg = Get-ItemProperty -LiteralPath `$featuresPath -Name 'TPExclusions' -ErrorAction SilentlyContinue
        if (`$null -ne `$tpReg) { `$state.TPExclusions = [int]`$tpReg.TPExclusions }
    } catch {}

    if (`$state.AMRunningMode -match 'EDR\s*Block') {
        `$state.DefenderMode = 'EDR Block Mode'
    } elseif (`$state.AMRunningMode -match 'Passive') {
        `$state.DefenderMode = 'Passive'
    } elseif (`$state.AMRunningMode -match '^Normal$') {
        `$state.DefenderMode = 'Normal'
    } elseif (`$state.AMRunningMode -match 'Disabled') {
        `$state.DefenderMode = 'Disabled'
    }
    if (`$state.DefenderMode -eq 'Unknown' -and `$MpStatus) {
        if (`$MpStatus.AMServiceEnabled -eq `$false -or `$MpStatus.AntivirusEnabled -eq `$false) {
            `$state.DefenderMode = 'Disabled'
        }
    }
    if (`$state.DefenderMode -eq 'Unknown') {
        try {
            `$winDefend = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
            if (`$winDefend -and `$winDefend.Status -eq 'Stopped') { `$state.DefenderMode = 'Disabled' }
        } catch {}
    }

    `$state.MDEOnboarded = (`$state.MDEOnboardingState -eq 1 -or `$state.MDEOrgIdPresent -eq `$true)
    `$managedProduct = `$state.ManagedDefenderProductType -in @(6, 7)
    `$state.ManagedTamperProtection = (`$managedProduct -or `$state.TPExclusions -eq 1)
    `$state.ManagedDevice = (
        `$state.MDEOnboarded -or
        `$state.ForceDefenderPassiveMode -eq 1 -or
        `$managedProduct -or
        `$state.TPExclusions -eq 1
    )
    if (`$state.ManagedDevice) {
        `$signals = New-Object System.Collections.Generic.List[string]
        if (`$state.MDEOnboarded) { `$signals.Add('MDE onboarding') | Out-Null }
        if (`$state.ForceDefenderPassiveMode -eq 1) { `$signals.Add('passive-mode policy') | Out-Null }
        if (`$managedProduct) { `$signals.Add("ManagedDefenderProductType=`$(`$state.ManagedDefenderProductType)") | Out-Null }
        if (`$state.TPExclusions -eq 1) { `$signals.Add('tamper-protected exclusions') | Out-Null }
        `$state.ManagedDeviceWarning = "Managed Defender or device-management signals detected (`$(`$signals -join ', ')). Local changes may be ignored or reverted; consult your security administrator before disabling Defender."
    }
    return `$state
}
function Get-TxField {
    param(`$Entry, [string]`$Name, `$Default = `$null)
    if (`$Entry -is [System.Collections.IDictionary]) {
        if (`$Entry.Contains(`$Name)) { return `$Entry[`$Name] }
    }
    `$prop = `$Entry.PSObject.Properties[`$Name]
    if (`$prop) { return `$prop.Value }
    return `$Default
}
function Get-RegValueSnapshot {
    param([string]`$Path, [string]`$Name)
    `$snapshot = [ordered]@{ PathExists = `$false; Exists = `$false; Value = `$null; Type = `$null }
    try {
        if (Test-Path -LiteralPath `$Path) {
            `$snapshot.PathExists = `$true
            `$key = Get-Item -LiteralPath `$Path -ErrorAction Stop
            if (@(`$key.GetValueNames()) -contains `$Name) {
                `$snapshot.Exists = `$true
                `$snapshot.Value = `$key.GetValue(`$Name, `$null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                `$snapshot.Type = "`$(`$key.GetValueKind(`$Name))"
            }
        }
    } catch {}
    return `$snapshot
}
function Convert-ProviderPathToLocalMachineKey {
    param([string]`$Path)
    if (`$Path -like 'HKLM:\*') { return `$Path.Substring(6) }
    return `$null
}
function Restore-RegValueForReplay {
    param(`$Entry, [bool]`$BeforeExists, `$BeforeValue, [string]`$BeforeType)
    `$path = Get-TxField `$Entry 'Path'
    `$name = Get-TxField `$Entry 'Name'
    `$op = Get-TxField `$Entry 'Op'
    if (-not `$path -or -not `$name) { return 'Skipped' }

    if (`$BeforeExists) {
        `$regType = if (`$BeforeType) { `$BeforeType } elseif (Get-TxField `$Entry 'Type') { Get-TxField `$Entry 'Type' } else { 'DWord' }
        if (`$DryRun) {
            Queue-Info "  [DRY RUN] Would restore `$path\`$name = `$BeforeValue (`$regType)"
            return 'Restored'
        }
        try {
            if (-not (Test-Path -LiteralPath `$path)) { New-Item -Path `$path -Force | Out-Null }
            Set-ItemProperty -LiteralPath `$path -Name `$name -Value `$BeforeValue -Type `$regType -Force -ErrorAction Stop
            return 'Restored'
        } catch {
            if (`$op -eq 'SetProtected' -and `$regType -eq 'DWord') {
                `$keyPath = Convert-ProviderPathToLocalMachineKey -Path `$path
                if (`$keyPath -and (Set-ProtectedRegValue -KeyPath `$keyPath -ValueName `$name -Value ([int]`$BeforeValue))) {
                    return 'Restored'
                }
            }
            Queue-Verbose "  Replay restore failed: `$path\`$name - `$(`$_.Exception.Message)"
            return 'Failed'
        }
    }

    if (`$DryRun) {
        Queue-Info "  [DRY RUN] Would remove `$path\`$name to restore prior absence"
        return 'Removed'
    }
    try {
        `$current = Get-RegValueSnapshot -Path `$path -Name `$name
        if (`$current.Exists) {
            Remove-ItemProperty -LiteralPath `$path -Name `$name -Force -ErrorAction Stop
        }
        return 'Removed'
    } catch {
        Queue-Verbose "  Replay remove failed: `$path\`$name - `$(`$_.Exception.Message)"
        return 'Failed'
    }
}
function Invoke-UndoTransactionReplay {
    param(`$TransactionLog)
    `$summary = [ordered]@{ restored = 0; removed = 0; skipped = 0; failed = 0 }
    `$entries = @(`$TransactionLog)
    for (`$i = `$entries.Count - 1; `$i -ge 0; `$i--) {
        `$entry = `$entries[`$i]
        if ((Get-TxField `$entry 'Success' `$true) -eq `$false) { `$summary.skipped++; continue }
        `$hasBeforeExists = `$false
        if (`$entry -is [System.Collections.IDictionary]) {
            `$hasBeforeExists = `$entry.Contains('BeforeExists')
        } else {
            `$hasBeforeExists = [bool]`$entry.PSObject.Properties['BeforeExists']
        }
        `$beforeValue = Get-TxField `$entry 'Before'
        `$beforeExists = if (`$hasBeforeExists) { [bool](Get-TxField `$entry 'BeforeExists' `$false) } else { `$null -ne `$beforeValue }
        `$beforeType = Get-TxField `$entry 'BeforeType' (Get-TxField `$entry 'Type' 'DWord')
        `$action = Restore-RegValueForReplay -Entry `$entry -BeforeExists `$beforeExists -BeforeValue `$beforeValue -BeforeType `$beforeType
        switch (`$action) {
            'Restored' { `$summary.restored++ }
            'Removed'  { `$summary.removed++ }
            'Failed'   { `$summary.failed++ }
            default    { `$summary.skipped++ }
        }
    }
    return `$summary
}
function Set-RegValue {
    param([string]`$Path, [string]`$Name, `$Value, [string]`$Type = "DWord")
    if (`$DryRun) { Queue-Info "  [DRY RUN] Would set `$Path\`$Name = `$Value"; return `$true }
    `$before = Get-RegValueSnapshot -Path `$Path -Name `$Name
    try {
        if (-not (Test-Path -LiteralPath `$Path)) { New-Item -Path `$Path -Force | Out-Null; Queue-Verbose "  Created key: `$Path" }
        Set-ItemProperty -LiteralPath `$Path -Name `$Name -Value `$Value -Type `$Type -Force -ErrorAction Stop
        `$TxLog.Enqueue(@{ Time=(Get-Date).ToString('o'); Op='Set'; Path=`$Path; Name=`$Name; BeforeExists=`$before.Exists; Before=`$before.Value; BeforeType=`$before.Type; AfterExists=`$true; After=`$Value; AfterType=`$Type; Type=`$Type; Method='SetItemProperty'; Success=`$true })
        return `$true
    } catch {
        `$TxLog.Enqueue(@{ Time=(Get-Date).ToString('o'); Op='Set'; Path=`$Path; Name=`$Name; BeforeExists=`$before.Exists; Before=`$before.Value; BeforeType=`$before.Type; AfterExists=`$true; After=`$Value; AfterType=`$Type; Type=`$Type; Method='SetItemProperty'; Success=`$false; Error="`$_" })
        Queue-Err "  REG ERROR: `$Path\`$Name - `$_"; return `$false
    }
}
function Remove-RegValue {
    param([string]`$Path, [string]`$Name)
    if (`$DryRun) { Queue-Info "  [DRY RUN] Would remove `$Path\`$Name"; return `$true }
    `$before = Get-RegValueSnapshot -Path `$Path -Name `$Name
    try {
        if (Test-Path -LiteralPath `$Path) {
            if (`$before.Exists) { Remove-ItemProperty -LiteralPath `$Path -Name `$Name -Force -ErrorAction Stop }
        }
        `$TxLog.Enqueue(@{ Time=(Get-Date).ToString('o'); Op='Remove'; Path=`$Path; Name=`$Name; BeforeExists=`$before.Exists; Before=`$before.Value; BeforeType=`$before.Type; AfterExists=`$false; After=`$null; AfterType=`$null; Method='RemoveItemProperty'; Success=`$true })
        return `$true
    } catch {
        `$TxLog.Enqueue(@{ Time=(Get-Date).ToString('o'); Op='Remove'; Path=`$Path; Name=`$Name; BeforeExists=`$before.Exists; Before=`$before.Value; BeforeType=`$before.Type; AfterExists=`$false; After=`$null; AfterType=`$null; Method='RemoveItemProperty'; Success=`$false; Error="`$_" })
        Queue-Err "  REG REMOVE ERROR: `$Path\`$Name - `$_"; return `$false
    }
}
function Set-ProtectedRegValue {
    param([string]`$KeyPath, [string]`$ValueName, [int]`$Value)
    if (`$DryRun) { Queue-Info "  [DRY RUN] Would set `$KeyPath\`$ValueName = `$Value (protected)"; return `$true }
    `$fullPath = "HKLM:\`$KeyPath"
    `$before = Get-RegValueSnapshot -Path `$fullPath -Name `$ValueName
    # Attempt 1: Direct write
    try {
        Set-ItemProperty -LiteralPath `$fullPath -Name `$ValueName -Value `$Value -Type DWord -Force -ErrorAction Stop
        `$TxLog.Enqueue(@{ Time=(Get-Date).ToString('o'); Op='SetProtected'; Path=`$fullPath; Name=`$ValueName; BeforeExists=`$before.Exists; Before=`$before.Value; BeforeType=`$before.Type; AfterExists=`$true; After=`$Value; AfterType='DWord'; Type='DWord'; Method='Direct'; Success=`$true })
        return `$true
    } catch { Queue-Verbose "    Direct write failed for `$KeyPath\`$ValueName" }
    # Attempt 2: Take ownership + write via .NET handle
    try {
        [TokenPriv]::Enable("SeTakeOwnershipPrivilege")
        [TokenPriv]::Enable("SeRestorePrivilege")
        `$adminSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
        `$regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(`$KeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            ([System.Security.AccessControl.RegistryRights]::TakeOwnership -bor [System.Security.AccessControl.RegistryRights]::ChangePermissions))
        if (`$regKey) {
            `$acl = `$regKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
            `$acl.SetOwner(`$adminSid)
            `$regKey.SetAccessControl(`$acl)
            `$acl = `$regKey.GetAccessControl()
            `$rule = [System.Security.AccessControl.RegistryAccessRule]::new(
                `$adminSid,
                [System.Security.AccessControl.RegistryRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow)
            `$acl.AddAccessRule(`$rule)
            `$regKey.SetAccessControl(`$acl)
            `$regKey.Close()
            Queue-Verbose "    Ownership acquired for `$KeyPath"
            `$regKey2 = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(`$KeyPath, `$true)
            if (`$regKey2) {
                `$regKey2.SetValue(`$ValueName, `$Value, [Microsoft.Win32.RegistryValueKind]::DWord)
                `$regKey2.Close()
                Queue-Verbose "    Wrote via .NET handle: `$ValueName = `$Value"
                `$TxLog.Enqueue(@{ Time=(Get-Date).ToString('o'); Op='SetProtected'; Path=`$fullPath; Name=`$ValueName; BeforeExists=`$before.Exists; Before=`$before.Value; BeforeType=`$before.Type; AfterExists=`$true; After=`$Value; AfterType='DWord'; Type='DWord'; Method='NETHandle'; Success=`$true })
                return `$true
            }
        }
    } catch { Queue-Verbose "    .NET handle approach failed: `$(`$_.Exception.Message)" }
    # Attempt 3: reg.exe
    try {
        `$regExePath = "HKLM\`$KeyPath"
        `$result = & reg.exe add `$regExePath /v `$ValueName /t REG_DWORD /d `$Value /f 2>&1
        if (`$LASTEXITCODE -eq 0) {
            Queue-Verbose "    Wrote via reg.exe: `$ValueName = `$Value"
            `$TxLog.Enqueue(@{ Time=(Get-Date).ToString('o'); Op='SetProtected'; Path=`$fullPath; Name=`$ValueName; BeforeExists=`$before.Exists; Before=`$before.Value; BeforeType=`$before.Type; AfterExists=`$true; After=`$Value; AfterType='DWord'; Type='DWord'; Method='RegExe'; Success=`$true })
            return `$true
        } else { Queue-Verbose "    reg.exe failed: `$result" }
    } catch { Queue-Verbose "    reg.exe exception: `$(`$_.Exception.Message)" }
    # Attempt 4: SYSTEM scheduled task
    try {
        `$taskAction = New-ScheduledTaskAction -Execute "reg.exe" -Argument "add `"HKLM\`$KeyPath`" /v `$ValueName /t REG_DWORD /d `$Value /f"
        `$taskName = "DefCtrl_RegFix_`$(Get-Random)"
        Register-ScheduledTask -TaskName `$taskName -Action `$taskAction -User "SYSTEM" -RunLevel Highest -Force -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName `$taskName -ErrorAction Stop
        Start-Sleep -Milliseconds 500
        Unregister-ScheduledTask -TaskName `$taskName -Confirm:`$false -ErrorAction SilentlyContinue
        `$check = (Get-ItemProperty -Path `$fullPath -Name `$ValueName -ErrorAction SilentlyContinue).`$ValueName
        if (`$check -eq `$Value) {
            Queue-Verbose "    Wrote via SYSTEM task: `$ValueName = `$Value"
            `$TxLog.Enqueue(@{ Time=(Get-Date).ToString('o'); Op='SetProtected'; Path=`$fullPath; Name=`$ValueName; BeforeExists=`$before.Exists; Before=`$before.Value; BeforeType=`$before.Type; AfterExists=`$true; After=`$Value; AfterType='DWord'; Type='DWord'; Method='SystemTask'; Success=`$true })
            return `$true
        }
    } catch { Queue-Verbose "    SYSTEM task failed: `$(`$_.Exception.Message)" }
    `$TxLog.Enqueue(@{ Time=(Get-Date).ToString('o'); Op='SetProtected'; Path=`$fullPath; Name=`$ValueName; BeforeExists=`$before.Exists; Before=`$before.Value; BeforeType=`$before.Type; AfterExists=`$true; After=`$Value; AfterType='DWord'; Type='DWord'; Method='AllFailed'; Success=`$false })
    Queue-Warn "    All methods failed for `$KeyPath\`$ValueName"
    return `$false
}
function Set-ServiceStart {
    param([string]`$ServiceName, [int]`$StartValue)
    `$keyPath = "SYSTEM\CurrentControlSet\Services\`$ServiceName"
    `$fullPath = "HKLM:\`$keyPath"
    if (-not (Test-Path `$fullPath)) { Queue-Verbose "  Service key missing: `$ServiceName"; return `$false }
    `$cur = (Get-ItemProperty -Path `$fullPath -Name "Start" -ErrorAction SilentlyContinue).Start
    Queue-Verbose "  `$ServiceName current Start = `$cur"
    `$result = Set-ProtectedRegValue -KeyPath `$keyPath -ValueName "Start" -Value `$StartValue
    if (`$result) { Queue-Success "  `$ServiceName : `$cur -> `$StartValue" }
    else { Queue-Err "  `$ServiceName : Failed to set Start = `$StartValue" }
    return `$result
}
function Set-ServicePPL {
    param([string]`$ServiceName, [int]`$PPLValue)
    `$keyPath = "SYSTEM\CurrentControlSet\Services\`$ServiceName"
    `$fullPath = "HKLM:\`$keyPath"
    if (-not (Test-Path `$fullPath)) { return `$false }
    `$cur = (Get-ItemProperty -Path `$fullPath -Name "LaunchProtected" -ErrorAction SilentlyContinue).LaunchProtected
    if (`$null -eq `$cur) { Queue-Verbose "  `$ServiceName : LaunchProtected not present"; return `$true }
    if (`$cur -eq `$PPLValue) { Queue-Verbose "  `$ServiceName : LaunchProtected already `$PPLValue"; return `$true }
    Queue-Verbose "  `$ServiceName LaunchProtected = `$cur, setting to `$PPLValue"
    `$result = Set-ProtectedRegValue -KeyPath `$keyPath -ValueName "LaunchProtected" -Value `$PPLValue
    if (`$result) { Queue-Success "  `$ServiceName : LaunchProtected `$cur -> `$PPLValue" }
    else { Queue-Warn "  `$ServiceName : Could not change LaunchProtected (may need Safe Mode)" }
    return `$result
}
function Get-FirewallSnapshot {
    # Returns a plain hashtable of firewall profile state + protected service state.
    # Used as before/after pair to prove this tool did not touch the firewall.
    `$snap = [ordered]@{}
    try {
        Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
            `$snap["Profile_`$(`$_.Name)_Enabled"] = [bool]`$_.Enabled
        }
    } catch {
        Queue-Verbose "  Firewall snapshot: Get-NetFirewallProfile failed (`$(`$_.Exception.Message))"
    }
    foreach (`$svc in @('mpssvc','BFE')) {
        `$o = Get-Service -Name `$svc -ErrorAction SilentlyContinue
        if (`$o) {
            `$snap["Service_`${svc}_Status"]    = "`$(`$o.Status)"
            `$snap["Service_`${svc}_StartType"] = "`$(`$o.StartType)"
        } else {
            `$snap["Service_`${svc}_Status"]    = 'NotFound'
            `$snap["Service_`${svc}_StartType"] = 'NotFound'
        }
    }
    return `$snap
}
function Test-FirewallIntact {
    # Before/After are ordered-dict-or-hashtable. Use .Contains for cross-compat.
    param(`$Before, `$After)
    `$diffs = @()
    if (`$null -eq `$Before -or `$null -eq `$After) { return ,`$diffs }
    foreach (`$k in @(`$Before.Keys)) {
        if (`$After.Contains(`$k) -and `$After[`$k] -ne `$Before[`$k]) {
            `$diffs += "`${k}: `$(`$Before[`$k]) -> `$(`$After[`$k])"
        }
    }
    return ,`$diffs  # force array return
}
function Get-ThirdPartyAVList {
    # Query Security Center for registered AV products; exclude Microsoft Defender.
    try {
        `$products = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'AntivirusProduct' -ErrorAction Stop
        if (-not `$products) { return @() }
        return @(`$products |
            Where-Object { `$_.displayName -notmatch 'Windows Defender|Microsoft Defender' } |
            ForEach-Object { `$_.displayName })
    } catch {
        Queue-Verbose "  Third-party AV detection failed: `$(`$_.Exception.Message)"
        return `$null
    }
}
function New-DefenderControlManifest {
    param([string]`$Operation, [bool]`$DryRunFlag)
    `$dir = Join-Path `$env:ProgramData 'DefenderControl\manifests'
    if (-not (Test-Path `$dir)) {
        try { New-Item -Path `$dir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch {
            Queue-Verbose "  Manifest dir create failed: `$(`$_.Exception.Message)"
            return `$null
        }
    }
    `$ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
    `$file = Join-Path `$dir ("`$Operation-`$ts.json")
    return [ordered]@{
        schemaVersion   = 1
        operation       = `$Operation
        dryRun          = `$DryRunFlag
        startedAt       = (Get-Date).ToString('o')
        host            = `$env:COMPUTERNAME
        osBuild         = `$OSBuild
        firewallBefore  = `$null
        firewallAfter   = `$null
        firewallIntact  = `$null
        firewallDiffs   = @()
        thirdPartyAV    = @()
        defenderStateBefore = `$null
        defenderStateAfter  = `$null
        phasesCompleted = @()
        transactionLog  = @()
        finishedAt      = `$null
        retentionPolicy = [ordered]@{
            days = 30
            maxCount = 50
            redactionAvailable = `$true
        }
        path            = `$file
    }
}
function Save-DefenderControlManifest {
    param(`$Manifest)
    if (`$null -eq `$Manifest) { return `$null }
    `$Manifest.finishedAt = (Get-Date).ToString('o')
    # Drain transaction log into manifest
    `$txEntries = [System.Collections.ArrayList]::new()
    `$txEntry = `$null
    while (`$TxLog.TryDequeue([ref]`$txEntry)) { `$txEntries.Add(`$txEntry) | Out-Null }
    `$Manifest.transactionLog = @(`$txEntries)
    try {
        `$json = (`$Manifest | ConvertTo-Json -Depth 8)
        [System.IO.File]::WriteAllText(`$Manifest.path, `$json, [System.Text.Encoding]::UTF8)
        Queue-Info "  Undo manifest saved: `$(`$Manifest.path)"
        Queue-Info "  Transaction log: `$(`$txEntries.Count) registry operations recorded"
        return `$Manifest.path
    } catch {
        Queue-Warn "  Manifest save failed: `$(`$_.Exception.Message)"
        return `$null
    }
}
function Write-DefenderControlEvent {
    param(
        [string]`$Message,
        [int]`$EventId = 1000,
        [System.Diagnostics.EventLogEntryType]`$EntryType = [System.Diagnostics.EventLogEntryType]::Information
    )
    if (-not `$EventLogReady) { return }
    try {
        [System.Diagnostics.EventLog]::WriteEntry(`$EventLogSource, `$Message, `$EntryType, `$EventId)
    } catch {}
}
"@

# Keep the support bundle writer available to GUI runspaces without maintaining
# a second copy of its implementation inside the injected function block.
$script:SharedFunctions += "`nfunction New-DefenderControlSupportBundle {`n" +
    ${function:New-DefenderControlSupportBundle}.ToString() + "`n}`n"

# ==================================================================================
#  BACKGROUND RUNSPACE RUNNER
# ==================================================================================
function Start-BackgroundWork {
    param([ScriptBlock]$Work, [switch]$AutoRefresh, [hashtable]$Context)

    $script:IsRunning = $true
    $script:DryRun = $chkDryRun.IsChecked
    $window.Dispatcher.Invoke([Action]{
        $btnDisable.IsEnabled = $false
        $btnEnable.IsEnabled  = $false
        $btnRefresh.IsEnabled = $false
        $btnSupportBundle.IsEnabled = $false
        $chkDryRun.IsEnabled  = $false
    })

    $runspace = [RunspaceFactory]::CreateRunspace()
    $runspace.ApartmentState = "STA"
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable("LogQueue",    $script:LogQueue)
    $runspace.SessionStateProxy.SetVariable("StatusQueue", $script:StatusQueue)
    $runspace.SessionStateProxy.SetVariable("DashQueue",   $script:DashQueue)
    $runspace.SessionStateProxy.SetVariable("DryRun",      $script:DryRun)
    $runspace.SessionStateProxy.SetVariable("OSBuild",     $script:OSBuild)
    $runspace.SessionStateProxy.SetVariable("EventLogReady",  $script:EventLogReady)
    $runspace.SessionStateProxy.SetVariable("EventLogSource", $script:EventLogSource)
    if ($Context) {
        foreach ($contextEntry in $Context.GetEnumerator()) {
            $runspace.SessionStateProxy.SetVariable($contextEntry.Key, $contextEntry.Value)
        }
    }
    $txLog = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
    $runspace.SessionStateProxy.SetVariable("TxLog", $txLog)
    $runspace.SessionStateProxy.SetVariable("TxLogRef", $txLog)

    $ps = [PowerShell]::Create()
    $ps.Runspace = $runspace
    $ps.AddScript($script:SharedFunctions).Invoke() | Out-Null
    $ps.Commands.Clear()

    $ps.AddScript($Work) | Out-Null
    $handle = $ps.BeginInvoke()

    $doAutoRefresh = $AutoRefresh.IsPresent
    $completionTimer = [System.Windows.Threading.DispatcherTimer]::new()
    $completionTimer.Interval = [TimeSpan]::FromMilliseconds(200)
    $completionTimer.Tag = @{ PS = $ps; Handle = $handle; Runspace = $runspace; AutoRefresh = $doAutoRefresh }
    $completionTimer.Add_Tick({
        $timer = $this
        $data  = $timer.Tag
        if ($data.Handle.IsCompleted) {
            $timer.Stop()
            $workerError = $null
            try {
                $data.PS.EndInvoke($data.Handle)
            } catch {
                $workerError = $_.Exception
            }
            if ($workerError) {
                $crashPath = Write-DefenderControlCrashLog -Exception $workerError -PowerShell $data.PS
                $message = $workerError.Message
                if ([string]::IsNullOrWhiteSpace($message)) { $message = $workerError.GetType().FullName }
                Queue-Err "Background operation failed: $message"
                if ($crashPath) {
                    Queue-Err "Crash log saved: $crashPath"
                } else {
                    Queue-Warn "Crash log could not be written to ProgramData"
                }
                Queue-Status -StatusText "ERROR" -StatusColor "#e74c3c" -TamperText "Operation failed - see log" -TamperColor "#e74c3c" -DisableBtn $true -EnableBtn $true -Progress 100 -RunningText "Background worker failed"
                Write-DefenderControlEvent -Message "Defender Control: background operation failed on $env:COMPUTERNAME - $message" -EventId 9001 -EntryType ([System.Diagnostics.EventLogEntryType]::Error)
            }
            $data.PS.Dispose()
            $data.Runspace.Dispose()
            $script:IsRunning = $false
            $btnRefresh.IsEnabled = $true
            $btnSupportBundle.IsEnabled = $true
            $chkDryRun.IsEnabled  = $true
            if ($data.AutoRefresh -and -not $workerError) {
                # Delayed auto-refresh after operation completes
                $refreshTimer = [System.Windows.Threading.DispatcherTimer]::new()
                $refreshTimer.Interval = [TimeSpan]::FromSeconds(2)
                $refreshTimer.Add_Tick({
                    $this.Stop()
                    if (-not $script:IsRunning) { Update-StatusAsync }
                })
                $refreshTimer.Start()
            }
        }
    })
    $completionTimer.Start()
}

# ==================================================================================
#  STATUS REFRESH (async) - with full dashboard population
# ==================================================================================
function Update-StatusAsync {
    Start-BackgroundWork -Work {
        Queue-Info "Querying current Defender status..."
        $enabled  = $true
        $tamperOn = $false
        $mpStatus = $null

        # Dashboard defaults
        $rtpText = "OFF"; $rtpColor = "#e74c3c"
        $tamperText = "OFF"; $tamperColor = "#7f8c8d"
        $cloudText = "OFF"; $cloudColor = "#e74c3c"
        $fwText = "OFF"; $fwColor = "#e74c3c"
        $svcText = "Unknown"; $svcColor = "#7f8c8d"
        $antiSpyText = "Unknown"; $antiSpyColor = "#7f8c8d"
        $defUpdateText = "Unknown"; $defUpdateColor = "#7f8c8d"
        $modeText = "Unknown"; $modeColor = "#7f8c8d"
        $platformText = "Unknown"; $platformColor = "#7f8c8d"
        $mdeText = "Not detected"; $mdeColor = "#7f8c8d"
        $managedWarning = ""

        try {
            Queue-Verbose "  Calling Get-MpComputerStatus..."
            $mpStatus = Get-MpComputerStatus -ErrorAction Stop

            # Real-Time Protection
            if ($mpStatus.RealTimeProtectionEnabled) {
                $rtpText = "ON"; $rtpColor = "#2ecc71"
            } else { $enabled = $false }
            Queue-Verbose "  RealTimeProtectionEnabled : $($mpStatus.RealTimeProtectionEnabled)"

            # Tamper Protection
            if ($mpStatus.IsTamperProtected) {
                $tamperOn = $true
                $tamperText = "ON"; $tamperColor = "#2ecc71"
            } else {
                $tamperText = "OFF"; $tamperColor = "#7f8c8d"
            }
            Queue-Verbose "  IsTamperProtected         : $($mpStatus.IsTamperProtected)"

            # Cloud Protection (OnAccessProtection as proxy, or check AntivirusSignatureLastUpdated)
            if ($mpStatus.AntivirusEnabled) {
                $cloudText = "ON"; $cloudColor = "#2ecc71"
            } else {
                $cloudText = "OFF"; $cloudColor = "#e74c3c"
                $enabled = $false
            }
            Queue-Verbose "  AntivirusEnabled          : $($mpStatus.AntivirusEnabled)"

            # Anti-Spyware
            if ($mpStatus.AntispywareEnabled) {
                $antiSpyText = "Enabled"; $antiSpyColor = "#2ecc71"
            } else {
                $antiSpyText = "Disabled"; $antiSpyColor = "#e74c3c"
            }
            Queue-Verbose "  AntispywareEnabled        : $($mpStatus.AntispywareEnabled)"

            # Last Definition Update
            if ($mpStatus.AntivirusSignatureLastUpdated) {
                $defUpdateText = $mpStatus.AntivirusSignatureLastUpdated.ToString("yyyy-MM-dd HH:mm")
                $daysSince = ((Get-Date) - $mpStatus.AntivirusSignatureLastUpdated).TotalDays
                if ($daysSince -gt 7) { $defUpdateColor = "#e74c3c" }
                elseif ($daysSince -gt 3) { $defUpdateColor = "#e67e22" }
                else { $defUpdateColor = "#2ecc71" }
            }

            Queue-Verbose "  AMServiceEnabled          : $($mpStatus.AMServiceEnabled)"
            Queue-Verbose "  BehaviorMonitorEnabled    : $($mpStatus.BehaviorMonitorEnabled)"
            Queue-Verbose "  IoavProtectionEnabled     : $($mpStatus.IoavProtectionEnabled)"
            Queue-Verbose "  NISEnabled                : $($mpStatus.NISEnabled)"
            Queue-Verbose "  OnAccessProtectionEnabled : $($mpStatus.OnAccessProtectionEnabled)"

            if (-not $mpStatus.RealTimeProtectionEnabled) { $enabled = $false }
            if (-not $mpStatus.AntivirusEnabled)          { $enabled = $false }
        } catch {
            $enabled = $false
            Queue-Warn "  Could not query Defender: $($_.Exception.Message)"
        }

        $endpointState = Get-DefenderEndpointState -MpStatus $mpStatus
        $modeText = $endpointState.DefenderMode
        switch ($modeText) {
            'Normal'        { $modeColor = "#2ecc71" }
            'Passive'       { $modeColor = "#3498db" }
            'EDR Block Mode' { $modeColor = "#9b59b6" }
            'Disabled'      { $modeColor = "#e74c3c" }
        }
        if ($endpointState.DefenderPlatformVersion) { $platformText = $endpointState.DefenderPlatformVersion; $platformColor = "#3498db" }
        if ($endpointState.MDEOnboarded) {
            $mdeText = "Onboarded"
            $mdeColor = "#e67e22"
        } elseif ($endpointState.ForceDefenderPassiveMode -eq 1) {
            $mdeText = "Passive policy"
            $mdeColor = "#e67e22"
        } elseif ($endpointState.MDEStatusKeyPresent) {
            $mdeText = "Status key present"
            $mdeColor = "#e67e22"
        }
        if ($endpointState.ManagedDevice) { $managedWarning = $endpointState.ManagedDeviceWarning }

        # Check DisableAntiSpyware registry
        try {
            $asReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
            Queue-Verbose "  Policy DisableAntiSpyware : $($asReg.DisableAntiSpyware)"
            if ($asReg.DisableAntiSpyware -eq 1) {
                $enabled = $false
                $antiSpyText = "Disabled (GP)"; $antiSpyColor = "#e74c3c"
            }
        } catch {}

        # WinDefend service
        $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        if ($svc) {
            Queue-Verbose "  WinDefend service: Status=$($svc.Status) StartType=$($svc.StartType)"
            if ($svc.Status -eq 'Running') {
                $svcText = "Running"; $svcColor = "#2ecc71"
            } elseif ($svc.Status -eq 'Stopped') {
                $svcText = "Stopped"; $svcColor = "#e74c3c"
                $enabled = $false
            } else {
                $svcText = "$($svc.Status)"; $svcColor = "#e67e22"
            }
            $svcStart = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name "Start" -ErrorAction SilentlyContinue).Start
            if ($svcStart -eq 4) {
                $svcText = "Disabled"; $svcColor = "#e74c3c"
                $enabled = $false
            }
        } else {
            Queue-Verbose "  WinDefend service not found"
            $svcText = "Not Found"; $svcColor = "#e74c3c"
            $enabled = $false
        }
        if ($endpointState.DefenderMode -eq 'Unknown' -and -not $enabled) {
            $modeText = "Disabled"
            $modeColor = "#e74c3c"
        }

        # Firewall status
        try {
            $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
            $allOn = $true
            foreach ($p in $fwProfiles) {
                if (-not $p.Enabled) { $allOn = $false; break }
            }
            if ($allOn) { $fwText = "ON"; $fwColor = "#2ecc71" }
            else { $fwText = "Partial"; $fwColor = "#e67e22" }
        } catch {
            $fwText = "Unknown"; $fwColor = "#7f8c8d"
        }

        # PPL status per service
        $pplMap = @{ 0 = 'None'; 1 = 'AuthenticodeLight'; 2 = 'WindowsLight'; 3 = 'Windows'; 4 = 'AntimalwareLight' }
        $pplMsMpEngText = "--"; $pplMsMpEngColor = "#7f8c8d"
        $pplWdFilterText = "--"; $pplWdFilterColor = "#7f8c8d"
        $pplWdNisDrvText = "--"; $pplWdNisDrvColor = "#7f8c8d"

        # MsMpEng (WinDefend service)
        try {
            $lp = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name "LaunchProtected" -ErrorAction SilentlyContinue).LaunchProtected
            if ($null -ne $lp) {
                $label = if ($pplMap.ContainsKey([int]$lp)) { $pplMap[[int]$lp] } else { "Unknown($lp)" }
                if ([int]$lp -gt 0) { $pplMsMpEngText = "Protected ($label)"; $pplMsMpEngColor = "#2ecc71" }
                else { $pplMsMpEngText = "Stripped"; $pplMsMpEngColor = "#e74c3c" }
            } else { $pplMsMpEngText = "Not Set"; $pplMsMpEngColor = "#7f8c8d" }
        } catch {}
        Queue-Verbose "  PPL WinDefend (MsMpEng): $pplMsMpEngText"

        # WdFilter + WdBoot (combined tile)
        try {
            $lpFilter = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\WdFilter" -Name "LaunchProtected" -ErrorAction SilentlyContinue).LaunchProtected
            $lpBoot   = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot" -Name "LaunchProtected" -ErrorAction SilentlyContinue).LaunchProtected
            $fVal = if ($null -ne $lpFilter) { [int]$lpFilter } else { -1 }
            $bVal = if ($null -ne $lpBoot)   { [int]$lpBoot }   else { -1 }
            if ($fVal -gt 0 -and $bVal -gt 0) { $pplWdFilterText = "Protected"; $pplWdFilterColor = "#2ecc71" }
            elseif ($fVal -le 0 -and $bVal -le 0) { $pplWdFilterText = "Stripped"; $pplWdFilterColor = "#e74c3c" }
            elseif ($fVal -eq -1 -and $bVal -eq -1) { $pplWdFilterText = "Not Set"; $pplWdFilterColor = "#7f8c8d" }
            else { $pplWdFilterText = "Partial"; $pplWdFilterColor = "#e67e22" }
        } catch {}
        Queue-Verbose "  PPL WdFilter/WdBoot: $pplWdFilterText"

        # WdNisDrv
        try {
            $lpNis = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisDrv" -Name "LaunchProtected" -ErrorAction SilentlyContinue).LaunchProtected
            if ($null -ne $lpNis) {
                if ([int]$lpNis -gt 0) { $pplWdNisDrvText = "Protected"; $pplWdNisDrvColor = "#2ecc71" }
                else { $pplWdNisDrvText = "Stripped"; $pplWdNisDrvColor = "#e74c3c" }
            } else { $pplWdNisDrvText = "Not Set"; $pplWdNisDrvColor = "#7f8c8d" }
        } catch {}
        Queue-Verbose "  PPL WdNisDrv: $pplWdNisDrvText"

        # Push dashboard update
        Queue-Dashboard -RTP $rtpText -RTPColor $rtpColor `
            -Tamper $tamperText -TamperColor $tamperColor `
            -Cloud $cloudText -CloudColor $cloudColor `
            -Firewall $fwText -FirewallColor $fwColor `
            -Service $svcText -ServiceColor $svcColor `
            -AntiSpy $antiSpyText -AntiSpyColor $antiSpyColor `
            -DefUpdate $defUpdateText -DefUpdateColor $defUpdateColor `
            -PplMsMpEng $pplMsMpEngText -PplMsMpEngColor $pplMsMpEngColor `
            -PplWdFilter $pplWdFilterText -PplWdFilterColor $pplWdFilterColor `
            -PplWdNisDrv $pplWdNisDrvText -PplWdNisDrvColor $pplWdNisDrvColor `
            -DefenderMode $modeText -DefenderModeColor $modeColor `
            -PlatformVersion $platformText -PlatformVersionColor $platformColor `
            -MdeStatus $mdeText -MdeStatusColor $mdeColor `
            -ManagedWarning $managedWarning `
            -ShowTamperWarning $tamperOn

        # Push main status
        $tamperStatusText  = if ($tamperOn) { "Tamper Protection: ON" } else { "Tamper Protection: OFF" }
        $tamperStatusColor = if ($tamperOn) { "#2ecc71" } else { "#7f8c8d" }
        if ($enabled) {
            Queue-Status -StatusText "ENABLED (Active)" -StatusColor "#2ecc71" -TamperText $tamperStatusText -TamperColor $tamperStatusColor -DisableBtn $true -EnableBtn $false -Progress 0 -RunningText "" -ShowReboot "hide"
            Queue-Success "Defender is ACTIVE and running"
        } else {
            $tText  = if ($tamperOn) { "Warning: Tamper Protection still ON - disable it in Windows Security first" } else { "Tamper Protection: OFF" }
            $tColor = if ($tamperOn) { "#e67e22" } else { "#7f8c8d" }
            Queue-Status -StatusText "DISABLED" -StatusColor "#e74c3c" -TamperText $tText -TamperColor $tColor -DisableBtn $false -EnableBtn $true -Progress 0 -RunningText "" -ShowReboot "hide"
            Queue-Success "Defender appears DISABLED"
        }
    }
}

# ==================================================================================
#  DISABLE DEFENDER (async)
# ==================================================================================
function Invoke-DisableDefender {
    Start-BackgroundWork -AutoRefresh -Work {
        $defPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        $rtpPolicyPath = "$defPolicyPath\Real-Time Protection"
        $spynetPath    = "$defPolicyPath\Spynet"
        $reportingPath = "$defPolicyPath\Reporting"
        $mpEnginePath  = "$defPolicyPath\MpEngine"
        $notifPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications"
        $systrayPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray"
        $runPath       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $explorerPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
        $totalPhases = 11
        $phase = 0
        $manifest = New-DefenderControlManifest -Operation 'Disable' -DryRunFlag $DryRun

        if ($DryRun) {
            Queue-Warn "========== DRY RUN MODE - No changes will be made =========="
        }
        Queue-Info "============================================"
        Queue-Info "  DISABLING MICROSOFT DEFENDER"
        Queue-Info "============================================"
        Write-DefenderControlEvent -Message "Defender Control: Disable operation started on $env:COMPUTERNAME (DryRun=$DryRun)" -EventId 1001
        Start-Sleep -Milliseconds 100

        # -- Phase 0: Safety pre-flight (firewall snapshot + third-party AV) ----------
        Queue-Phase "--- Phase 0 : Safety Pre-Flight ---"
        $fwBefore = Get-FirewallSnapshot
        if ($manifest) { $manifest.firewallBefore = $fwBefore }
        Queue-Verbose "  Firewall snapshot captured ($($fwBefore.Count) fields)"

        $endpointBefore = Get-DefenderEndpointState
        if ($manifest) { $manifest.defenderStateBefore = $endpointBefore }
        Queue-Info "  Defender mode: $($endpointBefore.DefenderMode) | Platform: $($endpointBefore.DefenderPlatformVersion)"
        if ($endpointBefore.ManagedDevice) {
            Queue-Warn "  ** MANAGED DEVICE / MDE SIGNAL DETECTED **"
            Queue-Warn "  $($endpointBefore.ManagedDeviceWarning)"
            Queue-Warn "  Review this with your security administrator before changing Defender services or policies."
        } else {
            Queue-Verbose "  No MDE or managed-device signals detected"
        }

        $tpAv = Get-ThirdPartyAVList
        if ($manifest) {
            if ($null -eq $tpAv) { $manifest.thirdPartyAV = @() }
            else { $manifest.thirdPartyAV = @($tpAv) }
        }
        if ($null -eq $tpAv) {
            Queue-Warn "  Could not query Security Center for third-party AV"
        } elseif ((@($tpAv)).Count -eq 0) {
            Queue-Warn "  No third-party antivirus detected. After disabling Defender, this system will have"
            Queue-Warn "  NO real-time malware protection. Consider installing one (e.g. ESET, Bitdefender,"
            Queue-Warn "  Malwarebytes) before rebooting, unless this is an air-gapped / sandbox system."
        } else {
            Queue-Success "  Third-party AV detected: $((@($tpAv)) -join ', ')"
        }
        Start-Sleep -Milliseconds 60

        # -- Phase 1: System Restore Point -----------------------------------------------
        $phase++
        Queue-Status -StatusText "DISABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - System Restore Point"
        Queue-Phase "--- Phase $phase/$totalPhases : Creating System Restore Point ---"
        if ($DryRun) {
            Queue-Info "  [DRY RUN] Would create System Restore Point"
        } else {
            try {
                # Enable System Restore on C: if not already
                Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
                Checkpoint-Computer -Description "Defender Control - Pre-Disable" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
                Queue-Success "  Restore point created successfully"
            } catch {
                $msg = $_.Exception.Message
                if ($msg -match "frequency") {
                    Queue-Warn "  Restore point skipped (one was created recently)"
                } else {
                    Queue-Warn "  Restore point failed: $msg"
                    Queue-Warn "  Continuing without restore point..."
                }
            }
        }
        Start-Sleep -Milliseconds 80

        # -- Phase 2: Tamper Protection Check -------------------------------------------
        $phase++
        Queue-Status -StatusText "DISABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Tamper Protection check"
        Queue-Phase "--- Phase $phase/$totalPhases : Checking Tamper Protection ---"
        try {
            $mpStatus = Get-MpComputerStatus -ErrorAction Stop
            Queue-Verbose "  RealTimeProtectionEnabled: $($mpStatus.RealTimeProtectionEnabled)"
            Queue-Verbose "  IsTamperProtected: $($mpStatus.IsTamperProtected)"
            if ($mpStatus.IsTamperProtected) {
                Queue-Warn "  ** TAMPER PROTECTION IS ON **"
                Queue-Warn "  Registry-level changes will be BLOCKED by Windows."
                Queue-Warn "  For full disable: Windows Security > Virus & Threat Protection > Manage Settings > Tamper Protection = OFF"
            } else {
                Queue-Success "  Tamper Protection is OFF - all changes should persist"
            }
        } catch {
            Queue-Warn "  Could not query status: $($_.Exception.Message)"
        }
        Start-Sleep -Milliseconds 60

        # -- Phase 3: MpPreference Settings ---------------------------------------------
        $phase++
        Queue-Status -StatusText "DISABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Defender preferences"
        Queue-Phase "--- Phase $phase/$totalPhases : Disabling via Set-MpPreference ---"

        $prefSettings = [ordered]@{
            DisableRealtimeMonitoring                     = $true
            DisableBehaviorMonitoring                     = $true
            DisableBlockAtFirstSeen                       = $true
            DisableIOAVProtection                         = $true
            DisablePrivacyMode                            = $true
            DisableIntrusionPreventionSystem              = $true
            DisableScriptScanning                         = $true
            DisableArchiveScanning                        = $true
            DisableEmailScanning                          = $true
            DisableRemovableDriveScanning                 = $true
            DisableScanningMappedNetworkDrivesForFullScan = $true
            DisableScanningNetworkFiles                   = $true
            LowThreatDefaultAction                        = 6
            ModerateThreatDefaultAction                   = 6
            HighThreatDefaultAction                       = 6
            SevereThreatDefaultAction                     = 6
            MAPSReporting                                 = 0
            SubmitSamplesConsent                           = 2
            SignatureDisableUpdateOnStartupWithoutEngine   = $true
            PUAProtection                                 = 0
            EnableControlledFolderAccess                   = 0
            EnableNetworkProtection                        = 0
            CloudBlockLevel                                = 0
            CloudExtendedTimeout                           = 0
            ScanScheduleQuickScanTime                      = 0
        }
        $i = 0
        $total = $prefSettings.Count
        foreach ($s in $prefSettings.GetEnumerator()) {
            $i++
            if ($DryRun) {
                Queue-Info "  [DRY RUN] [$i/$total] Would set $($s.Key) = $($s.Value)"
            } else {
                try {
                    $p = @{ $s.Key = $s.Value }
                    Set-MpPreference @p -ErrorAction Stop
                    Queue-Success "  [$i/$total] $($s.Key) = $($s.Value)"
                } catch {
                    Queue-Warn "  [$i/$total] BLOCKED $($s.Key): $($_.Exception.Message)"
                }
            }
        }

        Queue-Verbose "  Adding wildcard exclusions to suppress scanning..."
        if ($DryRun) {
            Queue-Info "  [DRY RUN] Would add drive/extension/process exclusions"
        } else {
            try {
                $drives = (Get-PSDrive -PSProvider FileSystem).Root
                Set-MpPreference -ExclusionPath $drives -ErrorAction Stop
                $driveList = $drives -join ", "
                Queue-Success "  Drive exclusions added: $driveList"
            } catch { Queue-Warn "  Drive exclusions blocked: $($_.Exception.Message)" }
            try {
                Set-MpPreference -ExclusionExtension @('*') -ErrorAction Stop
                Queue-Success "  Wildcard extension exclusion (*) added"
            } catch { Queue-Warn "  Extension exclusion blocked: $($_.Exception.Message)" }
            try {
                Set-MpPreference -ExclusionProcess @('*') -ErrorAction Stop
                Queue-Success "  Wildcard process exclusion (*) added"
            } catch { Queue-Warn "  Process exclusion blocked: $($_.Exception.Message)" }
        }

        # -- Phase 4: Group Policy Registry Keys ----------------------------------------
        $phase++
        Queue-Status -StatusText "DISABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Group Policy registry"
        Queue-Phase "--- Phase $phase/$totalPhases : Setting Group Policy Registry Keys ---"

        # Note: DisableAntiSpyware is ignored on Win11 22H2+ but still set for Win10 compat
        if ($OSBuild -ge 22621) {
            Queue-Verbose "  Note: DisableAntiSpyware GP is deprecated on this Win11 build - setting anyway for defense in depth"
        }

        $gpEntries = @(
            @{ Path = $defPolicyPath;  Name = "DisableAntiSpyware";                  Value = 1 }
            @{ Path = $defPolicyPath;  Name = "DisableAntiVirus";                    Value = 1 }
            @{ Path = $defPolicyPath;  Name = "ServiceKeepAlive";                    Value = 0 }
            @{ Path = $defPolicyPath;  Name = "AllowFastServiceStartup";             Value = 0 }
            @{ Path = $defPolicyPath;  Name = "DisableRoutinelyTakingAction";        Value = 1 }
            @{ Path = $defPolicyPath;  Name = "DisableLocalAdminMerge";              Value = 1 }
            @{ Path = $rtpPolicyPath;  Name = "DisableRealtimeMonitoring";           Value = 1 }
            @{ Path = $rtpPolicyPath;  Name = "DisableBehaviorMonitoring";           Value = 1 }
            @{ Path = $rtpPolicyPath;  Name = "DisableOnAccessProtection";           Value = 1 }
            @{ Path = $rtpPolicyPath;  Name = "DisableScanOnRealtimeEnable";         Value = 1 }
            @{ Path = $rtpPolicyPath;  Name = "DisableIOAVProtection";               Value = 1 }
            @{ Path = $rtpPolicyPath;  Name = "DisableRawWriteNotification";         Value = 1 }
            @{ Path = $rtpPolicyPath;  Name = "DisableInformationProtectionControl"; Value = 1 }
            @{ Path = $spynetPath;     Name = "SpynetReporting";                     Value = 0 }
            @{ Path = $spynetPath;     Name = "SubmitSamplesConsent";                Value = 2 }
            @{ Path = $spynetPath;     Name = "DisableBlockAtFirstSeen";             Value = 1 }
            @{ Path = $reportingPath;  Name = "DisableGenericRePorts";               Value = 1 }
            @{ Path = $mpEnginePath;   Name = "MpEnablePus";                         Value = 0 }
            @{ Path = $mpEnginePath;   Name = "MpCloudBlockLevel";                   Value = 0 }
        )
        $i = 0
        $total = $gpEntries.Count
        foreach ($e in $gpEntries) {
            $i++
            $r = Set-RegValue $e.Path $e.Name $e.Value
            if ($r) { Queue-Success "  [$i/$total] $($e.Name) = $($e.Value)" }
        }

        # -- Phase 5: Notifications & Systray -------------------------------------------
        $phase++
        Queue-Status -StatusText "DISABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Notifications & systray"
        Queue-Phase "--- Phase $phase/$totalPhases : Disabling Notifications & System Tray ---"

        Set-RegValue $notifPath "DisableNotifications" 1
        Queue-Success "  Policy DisableNotifications = 1"
        Set-RegValue $notifPath "DisableEnhancedNotifications" 1
        Queue-Success "  Policy DisableEnhancedNotifications = 1"
        Set-RegValue $systrayPath "HideSystray" 1
        Queue-Success "  Policy HideSystray = 1"
        Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" "DisableNotifications" 1
        Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" "DisableEnhancedNotifications" 1
        Queue-Success "  Security Center notification suppression applied"

        if (-not $DryRun) {
            try {
                Set-RegValue $runPath "SecurityHealth" "" "String"
                Queue-Success "  SecurityHealth autostart value cleared"
                if (Test-Path $explorerPath) {
                    $bytes = [byte[]]@(0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                    Set-ItemProperty -Path $explorerPath -Name "SecurityHealth" -Value $bytes -Type Binary -Force -ErrorAction SilentlyContinue
                    Queue-Success "  StartupApproved: SecurityHealth marked disabled"
                }
            } catch { Queue-Warn "  SecurityHealth startup: $($_.Exception.Message)" }
        }

        # -- Phase 6: Scheduled Tasks ---------------------------------------------------
        $phase++
        Queue-Status -StatusText "DISABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Scheduled tasks"
        Queue-Phase "--- Phase $phase/$totalPhases : Disabling Scheduled Tasks ---"

        $tasks = @(
            "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
            "Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
            "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
            "Microsoft\Windows\Windows Defender\Windows Defender Verification",
            "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh"
        )
        foreach ($task in $tasks) {
            $lastSlash = $task.LastIndexOf('\')
            $taskName  = $task.Substring($lastSlash + 1)
            $taskPath  = "\" + $task.Substring(0, $lastSlash + 1)
            if ($DryRun) {
                Queue-Info "  [DRY RUN] Would disable: $taskName"
            } else {
                try {
                    $taskObj = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
                    if ($taskObj) {
                        if ($taskObj.State -eq 'Disabled') { Queue-Verbose "  Already disabled: $taskName" }
                        else { Disable-ScheduledTask -InputObject $taskObj -ErrorAction Stop | Out-Null; Queue-Success "  Disabled: $taskName" }
                    } else { Queue-Verbose "  Not found: $taskName" }
                } catch { Queue-Warn "  $taskName : $($_.Exception.Message)" }
            }
        }

        # -- Phase 7: Services ----------------------------------------------------------
        $phase++
        Queue-Status -StatusText "DISABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Disabling services"
        Queue-Phase "--- Phase $phase/$totalPhases : Disabling Defender Services (Start=4) ---"

        $services = @("WinDefend","WdNisSvc","WdNisDrv","WdFilter","WdBoot","SecurityHealthService","wscsvc","Sense")
        foreach ($svc in $services) {
            Set-ServiceStart -ServiceName $svc -StartValue 4
        }

        Queue-Info "  Stripping PPL (Protected Process Light) flags..."
        $pplServices = @("WinDefend","WdNisSvc","WdNisDrv","WdFilter")
        foreach ($svc in $pplServices) {
            Set-ServicePPL -ServiceName $svc -PPLValue 0
        }

        # -- Phase 8: Context Menus -----------------------------------------------------
        $phase++
        Queue-Status -StatusText "DISABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Context menus"
        Queue-Phase "--- Phase $phase/$totalPhases : Removing Context Menu Integration ---"

        $ctxPaths = @(
            "HKLM:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP",
            "HKLM:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP",
            "HKLM:\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP"
        )
        foreach ($cp in $ctxPaths) {
            $label = $cp -replace [regex]::Escape("HKLM:\SOFTWARE\Classes\"), ""
            if (Test-Path -LiteralPath $cp) {
                if ($DryRun) {
                    Queue-Info "  [DRY RUN] Would blank context menu: $label"
                } else {
                    try {
                        $dv = (Get-ItemProperty -LiteralPath $cp -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
                        Queue-Verbose "  $label current = $dv"
                        if ($dv -and $dv -ne "") {
                            Set-ItemProperty -LiteralPath $cp -Name "BackupDefault" -Value $dv -Type String -Force
                            Set-ItemProperty -LiteralPath $cp -Name "(Default)" -Value "" -Force
                            Queue-Success "  Blanked: $label"
                        } else { Queue-Verbose "  Already blank: $label" }
                    } catch { Queue-Warn "  $label : $($_.Exception.Message)" }
                }
            } else { Queue-Verbose "  Path missing: $label" }
        }

        # -- Phase 9: Additional Hardening -----------------------------------------------
        $phase++
        Queue-Status -StatusText "DISABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Additional settings"
        Queue-Phase "--- Phase $phase/$totalPhases : Additional Settings ---"

        Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" "ConfigureAppInstallControlEnabled" 0
        Queue-Success "  SmartScreen policy disabled"
        Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "Off" "String"
        Queue-Success "  Explorer SmartScreen = Off"
        Set-RegValue "$defPolicyPath\Signature Updates" "ForceUpdateFromMU" 0
        Queue-Success "  ForceUpdateFromMU = 0"
        Set-RegValue "$defPolicyPath\Signature Updates" "UpdateOnStartUp" 0
        Queue-Success "  UpdateOnStartUp = 0"

        # -- Phase 10: Stop Processes ----------------------------------------------------
        $phase++
        Queue-Status -StatusText "DISABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Stopping processes"
        Queue-Phase "--- Phase $phase/$totalPhases : Stopping Defender Processes ---"

        if ($DryRun) {
            Queue-Info "  [DRY RUN] Would stop: SecurityHealthSystray, SecurityHealthService, SecurityHealthHost, NisSrv"
            Queue-Info "  [DRY RUN] MsMpEng is PPL-protected (cannot be killed, won't restart after reboot)"
        } else {
            $killableProcs = @("SecurityHealthSystray","SecurityHealthService","SecurityHealthHost","NisSrv")
            foreach ($proc in $killableProcs) {
                try {
                    $running = Get-Process -Name $proc -ErrorAction SilentlyContinue
                    if ($running) {
                        $pidList = ($running | ForEach-Object { $_.Id }) -join ", "
                        Queue-Verbose "  Found $proc (PID $pidList)"
                        Stop-Process -Name $proc -Force -ErrorAction Stop
                        Queue-Success "  Killed: $proc"
                    } else { Queue-Verbose "  Not running: $proc" }
                } catch { Queue-Warn "  $proc : $($_.Exception.Message)" }
            }

            $pplProcs = @("MsMpEng")
            foreach ($proc in $pplProcs) {
                $running = Get-Process -Name $proc -ErrorAction SilentlyContinue
                if ($running) {
                    $pidList = ($running | ForEach-Object { $_.Id }) -join ", "
                    Queue-Verbose "  $proc (PID $pidList) is running as Protected Process Light (PPL)"
                    Queue-Info "  $proc cannot be killed in current session (PPL-protected by Windows kernel)"
                    Queue-Info "  Service is set to Disabled + PPL flag stripped - will not start after reboot"
                } else { Queue-Verbose "  Not running: $proc" }
            }

            try {
                $svcObj = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                if ($svcObj -and $svcObj.Status -eq 'Running') {
                    Queue-Verbose "  Attempting WinDefend service stop..."
                    Stop-Service -Name WinDefend -Force -ErrorAction Stop
                    Queue-Success "  WinDefend service stopped"
                } elseif ($svcObj) { Queue-Verbose "  WinDefend already $($svcObj.Status)" }
            } catch { Queue-Info "  WinDefend service stop blocked (PPL) - will not restart after reboot" }
        }

        # -- Phase 11: Firewall Integrity Verification ----------------------------------
        $phase++
        Queue-Status -StatusText "DISABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Firewall integrity check"
        Queue-Phase "--- Phase $phase/$totalPhases : Firewall Integrity Verification ---"
        $fwAfter = Get-FirewallSnapshot
        $fwDiffs = Test-FirewallIntact -Before $fwBefore -After $fwAfter
        if ($manifest) {
            $manifest.firewallAfter  = $fwAfter
            $manifest.firewallDiffs  = @($fwDiffs)
            $manifest.firewallIntact = ((@($fwDiffs)).Count -eq 0)
            $manifest.phasesCompleted = @('Pre-flight','RestorePoint','TamperCheck','Preferences','GroupPolicy','Notifications','ScheduledTasks','Services','ContextMenus','Additional','Processes','FirewallVerify')
        }
        if ((@($fwDiffs)).Count -eq 0) {
            Queue-Success "  Firewall state unchanged - tool honored the firewall-untouched guarantee"
        } else {
            Queue-Err   "  Firewall state diverged from pre-flight snapshot!"
            foreach ($d in @($fwDiffs)) { Queue-Err "    $d" }
            Queue-Warn  "  This should never happen. Please file an issue with the operation log."
        }
        Start-Sleep -Milliseconds 60

        # -- Manifest: persist undo/audit manifest --------------------------------------
        $endpointAfter = Get-DefenderEndpointState
        if ($manifest) { $manifest.defenderStateAfter = $endpointAfter }
        $null = Save-DefenderControlManifest -Manifest $manifest

        # -- Final Status ----------------------------------------------------------------
        Queue-Info "============================================"
        if ($DryRun) {
            Queue-Info "  DRY RUN COMPLETE - No changes were made"
            Write-DefenderControlEvent -Message "Defender Control: Disable dry-run completed on $env:COMPUTERNAME" -EventId 1002
        } else {
            Queue-Info "  DISABLE OPERATION COMPLETE"
            Write-DefenderControlEvent -Message "Defender Control: Disable operation completed on $env:COMPUTERNAME" -EventId 1003
        }
        Queue-Info "============================================"

        if ($DryRun) {
            Queue-Status -StatusText "DRY RUN DONE" -StatusColor "#3498db" -TamperText "No changes were applied" -TamperColor "#7f8c8d" -DisableBtn $true -EnableBtn $false -Progress 100 -RunningText "" -ShowReboot "hide"
        } else {
            Queue-Warn "Restart recommended for full effect."
            Start-Sleep -Milliseconds 300
            $stillOn = $true
            try {
                $st = Get-MpComputerStatus -ErrorAction Stop
                if (-not $st.RealTimeProtectionEnabled -or -not $st.AntivirusEnabled) { $stillOn = $false }
            } catch { $stillOn = $false }
            $asReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
            if ($asReg.DisableAntiSpyware -eq 1) { $stillOn = $false }

            if ($stillOn) {
                Queue-Status -StatusText "PARTIALLY DISABLED" -StatusColor "#e67e22" -TamperText "Some components active - reboot or disable Tamper Protection" -TamperColor "#e67e22" -DisableBtn $true -EnableBtn $true -Progress 100 -RunningText "" -ShowReboot "show"
                Write-DefenderControlEvent -Message "Defender Control: Disable partially successful on $env:COMPUTERNAME - some components still active" -EventId 1004 -EntryType ([System.Diagnostics.EventLogEntryType]::Warning)
            } else {
                Queue-Status -StatusText "DISABLED" -StatusColor "#e74c3c" -TamperText "Reboot recommended" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $true -Progress 100 -RunningText "" -ShowReboot "show"
            }
        }
        Queue-Success "Done."
    }
}

# ==================================================================================
#  ENABLE DEFENDER (async)
# ==================================================================================
function Invoke-EnableDefender {
    Start-BackgroundWork -AutoRefresh -Work {
        $runPath      = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $explorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
        $totalPhases  = 8
        $phase        = 0
        $manifest = New-DefenderControlManifest -Operation 'Enable' -DryRunFlag $DryRun

        if ($DryRun) {
            Queue-Warn "========== DRY RUN MODE - No changes will be made =========="
        }
        Queue-Info "============================================"
        Queue-Info "  RE-ENABLING MICROSOFT DEFENDER"
        Queue-Info "============================================"
        Write-DefenderControlEvent -Message "Defender Control: Enable operation started on $env:COMPUTERNAME (DryRun=$DryRun)" -EventId 2001
        Start-Sleep -Milliseconds 100

        # -- Phase 0: Firewall snapshot + undo manifest lookup --------------------------
        $fwBefore = Get-FirewallSnapshot
        if ($manifest) { $manifest.firewallBefore = $fwBefore }
        Queue-Verbose "Firewall snapshot captured ($($fwBefore.Count) fields)"

        $endpointBefore = Get-DefenderEndpointState
        if ($manifest) { $manifest.defenderStateBefore = $endpointBefore }
        Queue-Info "  Defender mode: $($endpointBefore.DefenderMode) | Platform: $($endpointBefore.DefenderPlatformVersion)"
        if ($endpointBefore.ManagedDevice) {
            Queue-Warn "  ** MANAGED DEVICE / MDE SIGNAL DETECTED **"
            Queue-Warn "  $($endpointBefore.ManagedDeviceWarning)"
        }

        # Look for the latest Disable manifest to replay its transaction log
        $undoManifest = $null
        $undoTxLog = @()
        $manifestDir = Join-Path $env:ProgramData 'DefenderControl\manifests'
        if (Test-Path $manifestDir) {
            $latestDisable = Get-ChildItem -Path $manifestDir -Filter 'Disable-*.json' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latestDisable) {
                try {
                    $undoManifest = Get-Content -Raw -Path $latestDisable.FullName -ErrorAction Stop | ConvertFrom-Json
                    if ($undoManifest.transactionLog -and $undoManifest.transactionLog.Count -gt 0) {
                        $undoTxLog = @($undoManifest.transactionLog)
                        Queue-Info "  Undo manifest found: $($latestDisable.Name) ($($undoTxLog.Count) registry operations)"
                    } else {
                        Queue-Verbose "  Undo manifest found but has no transaction log"
                    }
                } catch {
                    Queue-Verbose "  Could not parse undo manifest: $($_.Exception.Message)"
                }
            } else {
                Queue-Verbose "  No prior Disable manifest found"
            }
        }

        # Replay in reverse order so each registry value returns to its exact prior state.
        if ($undoTxLog.Count -gt 0) {
            Queue-Phase "--- Undo Manifest Replay ---"
            $replaySummary = Invoke-UndoTransactionReplay -TransactionLog $undoTxLog
            Queue-Info "  Undo replay: $($replaySummary.restored) values restored, $($replaySummary.removed) values removed, $($replaySummary.skipped) skipped, $($replaySummary.failed) failed"
            if ($manifest) {
                $manifest['undoReplay'] = @{
                    source = $latestDisable.Name
                    restored = $replaySummary.restored
                    removed = $replaySummary.removed
                    skipped = $replaySummary.skipped
                    failed = $replaySummary.failed
                }
            }
        }
        Start-Sleep -Milliseconds 60

        # -- Phase 1: Remove Policy Overrides -------------------------------------------
        $phase++
        Queue-Status -StatusText "ENABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Removing policies"
        Queue-Phase "--- Phase $phase/$totalPhases : Removing Group Policy Overrides ---"

        $policiesToRemove = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center"
        )
        foreach ($pol in $policiesToRemove) {
            if (Test-Path $pol) {
                if ($DryRun) {
                    $subs = @(Get-ChildItem -Path $pol -Recurse -ErrorAction SilentlyContinue).Count
                    Queue-Info "  [DRY RUN] Would remove: $pol (+ $subs subkeys)"
                } else {
                    $subs = @(Get-ChildItem -Path $pol -Recurse -ErrorAction SilentlyContinue).Count
                    Queue-Verbose "  $pol has $subs subkeys"
                    try {
                        Remove-Item -Path $pol -Recurse -Force -ErrorAction Stop
                        Queue-Success "  Removed: $pol (+ $subs subkeys)"
                    } catch {
                        Queue-Warn "  Partial removal of $pol : $($_.Exception.Message)"
                        Get-ChildItem -Path $pol -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                            try { Remove-Item $_.PSPath -Recurse -Force -ErrorAction Stop } catch {}
                        }
                    }
                }
            } else { Queue-Verbose "  Already clean: $pol" }
        }

        # -- Phase 2: Restore Preferences -----------------------------------------------
        $phase++
        Queue-Status -StatusText "ENABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Restoring preferences"
        Queue-Phase "--- Phase $phase/$totalPhases : Restoring Defender Preferences ---"

        $restorePrefs = [ordered]@{
            DisableRealtimeMonitoring                     = $false
            DisableBehaviorMonitoring                     = $false
            DisableBlockAtFirstSeen                       = $false
            DisableIOAVProtection                         = $false
            DisablePrivacyMode                            = $false
            DisableIntrusionPreventionSystem              = $false
            DisableScriptScanning                         = $false
            DisableArchiveScanning                        = $false
            DisableEmailScanning                          = $false
            DisableRemovableDriveScanning                 = $false
            DisableScanningMappedNetworkDrivesForFullScan = $false
            DisableScanningNetworkFiles                   = $false
            MAPSReporting                                 = 2
            SubmitSamplesConsent                           = 1
            SignatureDisableUpdateOnStartupWithoutEngine   = $false
            PUAProtection                                 = 1
            EnableControlledFolderAccess                   = 0
            EnableNetworkProtection                        = 1
            CloudBlockLevel                                = 2
            CloudExtendedTimeout                           = 10
            LowThreatDefaultAction                        = 0
            ModerateThreatDefaultAction                   = 0
            HighThreatDefaultAction                       = 0
            SevereThreatDefaultAction                     = 0
        }
        $i = 0
        $total = $restorePrefs.Count
        foreach ($s in $restorePrefs.GetEnumerator()) {
            $i++
            if ($DryRun) {
                Queue-Info "  [DRY RUN] [$i/$total] Would set $($s.Key) = $($s.Value)"
            } else {
                try {
                    $p = @{ $s.Key = $s.Value }
                    Set-MpPreference @p -ErrorAction Stop
                    Queue-Success "  [$i/$total] $($s.Key) = $($s.Value)"
                } catch { Queue-Warn "  [$i/$total] $($s.Key): $($_.Exception.Message)" }
            }
        }

        Queue-Info "  Clearing wildcard exclusions..."
        if (-not $DryRun) {
            try {
                $pref = Get-MpPreference -ErrorAction Stop
                if ($pref.ExclusionPath) {
                    $pathList = $pref.ExclusionPath -join ", "
                    Set-MpPreference -ExclusionPath $pref.ExclusionPath -Remove -ErrorAction Stop
                    Queue-Success "  Cleared path exclusions: $pathList"
                }
            } catch { Queue-Warn "  Path exclusion clear: $($_.Exception.Message)" }
            try {
                $pref = Get-MpPreference -ErrorAction Stop
                if ($pref.ExclusionExtension) {
                    Set-MpPreference -ExclusionExtension $pref.ExclusionExtension -Remove -ErrorAction Stop
                    Queue-Success "  Cleared extension exclusions"
                }
            } catch { Queue-Warn "  Extension exclusion clear: $($_.Exception.Message)" }
            try {
                $pref = Get-MpPreference -ErrorAction Stop
                if ($pref.ExclusionProcess) {
                    Set-MpPreference -ExclusionProcess $pref.ExclusionProcess -Remove -ErrorAction Stop
                    Queue-Success "  Cleared process exclusions"
                }
            } catch { Queue-Warn "  Process exclusion clear: $($_.Exception.Message)" }
        } else {
            Queue-Info "  [DRY RUN] Would clear all wildcard exclusions"
        }

        # -- Phase 3: Restore Services ---------------------------------------------------
        $phase++
        Queue-Status -StatusText "ENABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Restoring services"
        Queue-Phase "--- Phase $phase/$totalPhases : Restoring Defender Services ---"

        $svcDefaults = @(
            @{ Name = "WdBoot";                Start = 0 }
            @{ Name = "WdFilter";              Start = 0 }
            @{ Name = "WinDefend";             Start = 2 }
            @{ Name = "WdNisSvc";              Start = 3 }
            @{ Name = "WdNisDrv";              Start = 3 }
            @{ Name = "SecurityHealthService"; Start = 3 }
            @{ Name = "wscsvc";                Start = 2 }
            @{ Name = "Sense";                 Start = 3 }
        )
        foreach ($sv in $svcDefaults) {
            Set-ServiceStart -ServiceName $sv.Name -StartValue $sv.Start
        }

        Queue-Info "  Restoring PPL (Protected Process Light) flags..."
        $pplRestore = @("WinDefend","WdNisSvc","WdNisDrv","WdFilter")
        foreach ($svc in $pplRestore) {
            Set-ServicePPL -ServiceName $svc -PPLValue 2
        }

        if (-not $DryRun) {
            Queue-Info "  Starting services..."
            $startList = @("WinDefend","WdNisSvc","SecurityHealthService","wscsvc")
            foreach ($svcName in $startList) {
                try {
                    $svcObj = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                    if ($svcObj -and $svcObj.Status -ne 'Running') {
                        Start-Service -Name $svcName -ErrorAction Stop
                        Queue-Success "  Started: $svcName"
                    } elseif ($svcObj) { Queue-Verbose "  Already running: $svcName" }
                } catch { Queue-Warn "  $svcName (reboot needed): $($_.Exception.Message)" }
            }
        }

        # -- Phase 4: Scheduled Tasks ---------------------------------------------------
        $phase++
        Queue-Status -StatusText "ENABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Scheduled tasks"
        Queue-Phase "--- Phase $phase/$totalPhases : Re-enabling Scheduled Tasks ---"

        $tasks = @(
            "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
            "Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
            "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
            "Microsoft\Windows\Windows Defender\Windows Defender Verification",
            "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh"
        )
        foreach ($task in $tasks) {
            $lastSlash = $task.LastIndexOf('\')
            $taskName  = $task.Substring($lastSlash + 1)
            $taskPath  = "\" + $task.Substring(0, $lastSlash + 1)
            if ($DryRun) {
                Queue-Info "  [DRY RUN] Would enable: $taskName"
            } else {
                try {
                    $taskObj = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
                    if ($taskObj -and $taskObj.State -eq 'Disabled') {
                        Enable-ScheduledTask -InputObject $taskObj -ErrorAction Stop | Out-Null
                        Queue-Success "  Enabled: $taskName"
                    } elseif ($taskObj) { Queue-Verbose "  Already enabled: $taskName ($($taskObj.State))" }
                    else { Queue-Verbose "  Not found: $taskName" }
                } catch { Queue-Warn "  $taskName : $($_.Exception.Message)" }
            }
        }

        # -- Phase 5: Context Menus & Systray -------------------------------------------
        $phase++
        Queue-Status -StatusText "ENABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Context menus & systray"
        Queue-Phase "--- Phase $phase/$totalPhases : Restoring Context Menu & System Tray ---"

        $eppGuid  = "{09A47860-11B0-4DA5-AFA5-26D86198A780}"
        $ctxPaths = @(
            "HKLM:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP",
            "HKLM:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP",
            "HKLM:\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP"
        )
        foreach ($cp in $ctxPaths) {
            $label = $cp -replace [regex]::Escape("HKLM:\SOFTWARE\Classes\"), ""
            if (Test-Path -LiteralPath $cp) {
                if ($DryRun) {
                    Queue-Info "  [DRY RUN] Would restore context menu: $label"
                } else {
                    try {
                        Set-ItemProperty -LiteralPath $cp -Name "(Default)" -Value $eppGuid -Force
                        Remove-ItemProperty -LiteralPath $cp -Name "BackupDefault" -Force -ErrorAction SilentlyContinue
                        Queue-Success "  Restored: $label"
                    } catch { Queue-Warn "  $label : $($_.Exception.Message)" }
                }
            }
        }

        if (-not $DryRun) {
            # Restore SecurityHealth autostart
            $resolved = $null
            $candidates = @(
                "$env:ProgramFiles\Windows Defender\MSASCuiL.exe",
                "$env:windir\System32\SecurityHealthSystray.exe"
            )
            foreach ($c in $candidates) {
                if (Test-Path $c) {
                    $resolved = "`"$c`""
                    Queue-Verbose "  Found: $c"
                    break
                }
            }
            if ($resolved) {
                try {
                    Set-ItemProperty -Path $runPath -Name "SecurityHealth" -Value $resolved -Type String -Force
                    Queue-Success "  SecurityHealth autostart restored"
                } catch { Queue-Warn "  $($_.Exception.Message)" }
            } else { Queue-Warn "  SecurityHealth exe not found on disk" }

            if (Test-Path $explorerPath) {
                try {
                    $bytes = [byte[]]@(0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                    Set-ItemProperty -Path $explorerPath -Name "SecurityHealth" -Value $bytes -Type Binary -Force
                    Queue-Success "  StartupApproved: SecurityHealth enabled"
                } catch { Queue-Warn "  StartupApproved: $($_.Exception.Message)" }
            }

            Remove-RegValue "HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" "DisableNotifications"
            Remove-RegValue "HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" "DisableEnhancedNotifications"
            Queue-Success "  Notification suppression removed"

            Set-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "Prompt" "String"
            Queue-Success "  SmartScreen restored"
        }

        # -- Phase 6: Signature Update --------------------------------------------------
        $phase++
        Queue-Status -StatusText "ENABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Signature update"
        Queue-Phase "--- Phase $phase/$totalPhases : Triggering Signature Update ---"

        if ($DryRun) {
            Queue-Info "  [DRY RUN] Would trigger Update-MpSignature"
        } else {
            try {
                Update-MpSignature -ErrorAction Stop
                Queue-Success "  Signatures updated"
            } catch { Queue-Warn "  Update may need reboot: $($_.Exception.Message)" }
        }

        # -- Phase 7: Verify ------------------------------------------------------------
        $phase++
        Queue-Status -StatusText "ENABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Verifying"
        Queue-Phase "--- Phase $phase/$totalPhases : Verifying Defender Status ---"

        Start-Sleep -Milliseconds 500
        $ok = $false
        try {
            $st = Get-MpComputerStatus -ErrorAction Stop
            Queue-Verbose "  RealTimeProtectionEnabled: $($st.RealTimeProtectionEnabled)"
            Queue-Verbose "  AntivirusEnabled: $($st.AntivirusEnabled)"
            Queue-Verbose "  AMServiceEnabled: $($st.AMServiceEnabled)"
            if ($st.RealTimeProtectionEnabled -and $st.AntivirusEnabled) { $ok = $true }
        } catch { Queue-Warn "  Verify failed (reboot needed): $($_.Exception.Message)" }

        # -- Phase 8: Firewall Integrity Verification -----------------------------------
        $phase++
        Queue-Status -StatusText "ENABLING..." -StatusColor "#e67e22" -TamperText "" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $false -Progress ([int]($phase / $totalPhases * 100)) -RunningText "Phase $phase/$totalPhases - Firewall integrity check"
        Queue-Phase "--- Phase $phase/$totalPhases : Firewall Integrity Verification ---"
        $fwAfter = Get-FirewallSnapshot
        $fwDiffs = Test-FirewallIntact -Before $fwBefore -After $fwAfter
        if ($manifest) {
            $manifest.firewallAfter   = $fwAfter
            $manifest.firewallDiffs   = @($fwDiffs)
            $manifest.firewallIntact  = ((@($fwDiffs)).Count -eq 0)
            $manifest.phasesCompleted = @('FirewallSnapshot','RemovePolicies','RestorePreferences','RestoreServices','ScheduledTasks','ContextMenusSystray','SignatureUpdate','Verify','FirewallVerify')
        }
        if ((@($fwDiffs)).Count -eq 0) {
            Queue-Success "  Firewall state unchanged - tool honored the firewall-untouched guarantee"
        } else {
            Queue-Err "  Firewall state diverged from pre-enable snapshot!"
            foreach ($d in @($fwDiffs)) { Queue-Err "    $d" }
        }

        # -- Manifest: persist undo/audit manifest --------------------------------------
        $endpointAfter = Get-DefenderEndpointState
        if ($manifest) { $manifest.defenderStateAfter = $endpointAfter }
        $null = Save-DefenderControlManifest -Manifest $manifest

        Queue-Info "============================================"
        if ($DryRun) {
            Queue-Info "  DRY RUN COMPLETE - No changes were made"
            Write-DefenderControlEvent -Message "Defender Control: Enable dry-run completed on $env:COMPUTERNAME" -EventId 2002
        } else {
            Queue-Info "  ENABLE OPERATION COMPLETE"
            Write-DefenderControlEvent -Message "Defender Control: Enable operation completed on $env:COMPUTERNAME" -EventId 2003
        }
        Queue-Info "============================================"

        if ($DryRun) {
            Queue-Status -StatusText "DRY RUN DONE" -StatusColor "#3498db" -TamperText "No changes were applied" -TamperColor "#7f8c8d" -DisableBtn $false -EnableBtn $true -Progress 100 -RunningText "" -ShowReboot "hide"
        } elseif ($ok) {
            Queue-Success "Defender is ACTIVE and protecting."
            Queue-Status -StatusText "ENABLED (Active)" -StatusColor "#2ecc71" -TamperText "Fully restored" -TamperColor "#7f8c8d" -DisableBtn $true -EnableBtn $false -Progress 100 -RunningText "" -ShowReboot "hide"
        } else {
            Queue-Warn "Reboot STRONGLY recommended to complete restoration."
            Queue-Status -StatusText "PENDING REBOOT" -StatusColor "#e67e22" -TamperText "Restart to complete" -TamperColor "#e67e22" -DisableBtn $true -EnableBtn $true -Progress 100 -RunningText "" -ShowReboot "show"
            Write-DefenderControlEvent -Message "Defender Control: Enable completed on $env:COMPUTERNAME but reboot required" -EventId 2004 -EntryType ([System.Diagnostics.EventLogEntryType]::Warning)
        }
        Queue-Success "Done."
    }
}

# ==================================================================================
#  SCHEDULED RE-ENABLE
# ==================================================================================
$script:ScheduleTaskName = "DefenderControl_ScheduledReEnable"

function Get-ScheduleHours {
    $selected = $cmbScheduleHours.SelectedItem
    if ($null -eq $selected) { return 1 }
    $text = $selected.Content.ToString()
    switch ($text) {
        "1 hour"   { return 1 }
        "2 hours"  { return 2 }
        "4 hours"  { return 4 }
        "8 hours"  { return 8 }
        "24 hours" { return 24 }
        default    { return 1 }
    }
}

function Update-ScheduleStatus {
    try {
        $task = Get-ScheduledTask -TaskName $script:ScheduleTaskName -ErrorAction SilentlyContinue
        if ($task) {
            $trigger = $task.Triggers | Select-Object -First 1
            if ($trigger.StartBoundary) {
                $triggerTime = [datetime]::Parse($trigger.StartBoundary)
                $txtScheduleStatus.Text = "Scheduled re-enable at $($triggerTime.ToString('yyyy-MM-dd HH:mm'))"
            } else {
                $txtScheduleStatus.Text = "Re-enable task is scheduled"
            }
            Set-AutomationStateName $txtScheduleStatus 'Re-enable schedule' $txtScheduleStatus.Text
            $btnCancelSchedule.Visibility = "Visible"
        } else {
            $txtScheduleStatus.Text = ""
            Set-AutomationStateName $txtScheduleStatus 'Re-enable schedule' 'not scheduled'
            $btnCancelSchedule.Visibility = "Collapsed"
        }
    } catch {
        $txtScheduleStatus.Text = ""
        Set-AutomationStateName $txtScheduleStatus 'Re-enable schedule' 'unavailable'
        $btnCancelSchedule.Visibility = "Collapsed"
    }
}

# ==================================================================================
#  EVENT HANDLERS
# ==================================================================================
$btnDisable.Add_Click({
    if ($script:IsRunning) { return }
    $r = [System.Windows.MessageBox]::Show(
        "This will comprehensively disable Microsoft Defender.`n`nA System Restore Point will be created first.`n`nTamper Protection should be OFF first:`nWindows Security > Virus & Threat Protection > Manage Settings`n`nA restart is needed for full effect.`n`nContinue?",
        "Confirm Disable", "YesNo", "Warning")
    if ($r -eq "Yes") { Invoke-DisableDefender }
})

$btnEnable.Add_Click({
    if ($script:IsRunning) { return }
    $r = [System.Windows.MessageBox]::Show(
        "This will restore Microsoft Defender to default state.`n`nA restart is needed for full restoration.`n`nContinue?",
        "Confirm Enable", "YesNo", "Question")
    if ($r -eq "Yes") { Invoke-EnableDefender }
})

$btnRefresh.Add_Click({ if (-not $script:IsRunning) { Update-StatusAsync } })
$btnRefreshDash.Add_Click({ if (-not $script:IsRunning) { Update-StatusAsync } })

$btnReboot.Add_Click({
    $r = [System.Windows.MessageBox]::Show(
        "This will restart your computer immediately.`n`nSave all work before proceeding.`n`nRestart now?",
        "Confirm Reboot", "YesNo", "Warning")
    if ($r -eq "Yes") {
        Restart-Computer -Force
    }
})

$btnClearLog.Add_Click({
    $rtbLog.Document.Blocks.Clear()
    $script:AllLogEntries.Clear()
})

$btnExport.Add_Click({
    $dlg = [System.Windows.Forms.SaveFileDialog]::new()
    $dlg.Title = "Export Operation Log"
    $dlg.Filter = "Text Files (*.txt)|*.txt|Log Files (*.log)|*.log|All Files (*.*)|*.*"
    $dlg.FileName = "DefenderControl_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    $dlg.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $lines = $script:AllLogEntries | ForEach-Object {
                "[$($_.Time)] $($_.Message)"
            }
            $header = @(
                "Defender Control v$script:Version - Operation Log",
                "Exported: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
                "System: $env:COMPUTERNAME | $script:OSDetail",
                "=" * 60
            )
            ($header + $lines) | Out-File -FilePath $dlg.FileName -Encoding UTF8 -Force
            Queue-Success "Log exported to: $($dlg.FileName)"
        } catch {
            Queue-Err "Export failed: $($_.Exception.Message)"
        }
    }
})

$btnListManifests.Add_Click({
    try {
        $summary = Get-DefenderControlManifestSummary
        Queue-Info ("Manifest retention: {0} days; keep newest {1} files; found {2}" -f `
            $summary.RetentionDays, $summary.MaxCount, $summary.Count)
        if ($summary.Count -eq 0) {
            Queue-Info "  No audit manifests found. A Disable or Enable operation will create one."
        } else {
            foreach ($item in @($summary.Manifests)) {
                Queue-Info ("  {0} ({1} bytes, {2})" -f $item.Name, $item.Length, $item.LastWriteTime)
            }
        }
    } catch {
        Queue-Err "Manifest listing failed: $($_.Exception.Message)"
    }
})

$btnRedactExport.Add_Click({
    if ($script:IsRunning) { return }
    $dlg = [System.Windows.Forms.SaveFileDialog]::new()
    $dlg.Title = "Export Redacted Defender Control Data"
    $dlg.Filter = "ZIP Archives (*.zip)|*.zip|All Files (*.*)|*.*"
    $dlg.FileName = "DefenderControl-Redacted-$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
    $dlg.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $redacted = Export-DefenderControlRedactedData `
                -OutputPath $dlg.FileName -LogEntries @($script:AllLogEntries)
            Queue-Success "Redacted export created: $($redacted.Path)"
            foreach ($warning in @($redacted.Warnings)) { Queue-Warn "Redacted export: $warning" }
        } catch {
            Queue-Err "Redacted export failed: $($_.Exception.Message)"
        }
    }
})

$btnPruneManifests.Add_Click({
    if ($script:IsRunning) { return }
    $message = "Remove audit manifests older than $($script:ManifestRetentionDays) days and keep the newest $($script:ManifestMaxCount) files?`n`nThis only removes JSON files inside the DefenderControl manifest directory."
    $choice = [System.Windows.MessageBox]::Show($message, "Prune Audit Manifests", "YesNo", "Warning")
    if ($choice -ne "Yes") { return }
    try {
        $pruned = Remove-DefenderControlManifests `
            -RetentionDays $script:ManifestRetentionDays -MaxCount $script:ManifestMaxCount
        Queue-Success ("Pruned {0} manifest(s); {1} remain." -f $pruned.RemovedCount, $pruned.RemainingCount)
        foreach ($removed in @($pruned.Removed)) { Queue-Verbose "  Removed: $removed" }
    } catch {
        Queue-Err "Manifest pruning failed: $($_.Exception.Message)"
    }
})

$btnSupportBundle.Add_Click({
    if ($script:IsRunning) { return }
    $dlg = [System.Windows.Forms.SaveFileDialog]::new()
    $dlg.Title = "Create Defender Control Support Bundle"
    $dlg.Filter = "ZIP Archives (*.zip)|*.zip|All Files (*.*)|*.*"
    $dlg.FileName = "DefenderControl-Support-$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
    $dlg.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $collectMpSupport = ([System.Windows.MessageBox]::Show(
            "Collect the optional Microsoft Defender diagnostic CAB with MpCmdRun.exe?`n`nThis can take several minutes and may include detailed Defender telemetry.",
            "Include Microsoft Defender Diagnostics", "YesNo", "Question") -eq "Yes")
        try {
            $supportState = Get-DefenderState -Extended
            $supportLogs = @($script:AllLogEntries)
            Write-DefenderControlEvent -Message "Defender Control: support bundle collection started on $env:COMPUTERNAME" -EventId 3001
            Start-BackgroundWork -Context @{
                SupportOutputPath = $dlg.FileName
                SupportIncludeMpSupportFiles = $collectMpSupport
                SupportState = $supportState
                SupportLogEntries = $supportLogs
                SupportVersion = $script:Version
                SupportOSDetail = $script:OSDetail
            } -Work {
                try {
                    $bundle = New-DefenderControlSupportBundle `
                        -OutputPath $SupportOutputPath `
                        -IncludeMpSupportFiles:$SupportIncludeMpSupportFiles `
                        -State $SupportState `
                        -LogEntries $SupportLogEntries `
                        -Version $SupportVersion `
                        -OSDetail $SupportOSDetail `
                        -EventLogSource 'DefenderControl'
                    foreach ($warning in @($bundle.Warnings)) { Queue-Warn "Support bundle: $warning" }
                    Queue-Success "Support bundle created: $($bundle.Path)"
                    Write-DefenderControlEvent -Message "Defender Control: support bundle created on $env:COMPUTERNAME at $($bundle.Path)" -EventId 3002
                } catch {
                    Queue-Err "Support bundle failed: $($_.Exception.Message)"
                    Write-DefenderControlEvent -Message "Defender Control: support bundle collection failed on $env:COMPUTERNAME - $($_.Exception.Message)" -EventId 3003 -EntryType ([System.Diagnostics.EventLogEntryType]::Error)
                }
            }
        } catch {
            Queue-Err "Support bundle failed to start: $($_.Exception.Message)"
        }
    }
})

$chkVerbose.Add_Checked({
    $script:ShowVerbose = $true
    Rebuild-Log
})
$chkVerbose.Add_Unchecked({
    $script:ShowVerbose = $false
    Rebuild-Log
})

$chkDryRun.Add_Checked({  $script:DryRun = $true })
$chkDryRun.Add_Unchecked({ $script:DryRun = $false })

$btnOpenWSecurity.Add_Click({
    try { Start-Process "windowsdefender://threatsettings" } catch {
        try { Start-Process "ms-settings:windowsdefender" } catch {}
    }
})

$btnSchedule.Add_Click({
    if ($script:IsRunning) { return }
    $hours = Get-ScheduleHours
    try {
        # Remove existing task if any
        Unregister-ScheduledTask -TaskName $script:ScheduleTaskName -Confirm:$false -ErrorAction SilentlyContinue

        $triggerTime = (Get-Date).AddHours($hours)

        # Build the enable script inline - runs the enable logic via PowerShell
        $enableScript = @"
# Defender Control - Scheduled Re-Enable
`$ErrorActionPreference = 'SilentlyContinue'
# Remove GP overrides
Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center' -Recurse -Force -ErrorAction SilentlyContinue
# Restore preferences
try {
    Set-MpPreference -DisableRealtimeMonitoring `$false -ErrorAction Stop
    Set-MpPreference -DisableBehaviorMonitoring `$false -ErrorAction Stop
    Set-MpPreference -DisableBlockAtFirstSeen `$false -ErrorAction Stop
    Set-MpPreference -DisableIOAVProtection `$false -ErrorAction Stop
    Set-MpPreference -MAPSReporting 2 -ErrorAction Stop
    Set-MpPreference -SubmitSamplesConsent 1 -ErrorAction Stop
} catch {}
# Restore service start types
`$svcDefaults = @{WdBoot=0;WdFilter=0;WinDefend=2;WdNisSvc=3;WdNisDrv=3;SecurityHealthService=3;wscsvc=2}
foreach (`$kv in `$svcDefaults.GetEnumerator()) {
    `$p = "HKLM:\SYSTEM\CurrentControlSet\Services\`$(`$kv.Key)"
    if (Test-Path `$p) { Set-ItemProperty -Path `$p -Name 'Start' -Value `$kv.Value -Type DWord -Force -ErrorAction SilentlyContinue }
}
# Start services
@('WinDefend','WdNisSvc','SecurityHealthService','wscsvc') | ForEach-Object {
    Start-Service -Name `$_ -ErrorAction SilentlyContinue
}
# Update signatures
Update-MpSignature -ErrorAction SilentlyContinue
# Self-cleanup
Unregister-ScheduledTask -TaskName 'DefenderControl_ScheduledReEnable' -Confirm:`$false -ErrorAction SilentlyContinue
"@

        $encodedCmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($enableScript))
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCmd"
        $trigger = New-ScheduledTaskTrigger -Once -At $triggerTime
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        Register-ScheduledTask -TaskName $script:ScheduleTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

        Queue-Success "Scheduled Defender re-enable in $hours hour(s) at $($triggerTime.ToString('yyyy-MM-dd HH:mm'))"
        Update-ScheduleStatus
    } catch {
        Queue-Err "Failed to create scheduled task: $($_.Exception.Message)"
    }
})

$btnCancelSchedule.Add_Click({
    try {
        Unregister-ScheduledTask -TaskName $script:ScheduleTaskName -Confirm:$false -ErrorAction Stop
        Queue-Success "Scheduled re-enable cancelled"
        Update-ScheduleStatus
    } catch {
        Queue-Err "Failed to cancel schedule: $($_.Exception.Message)"
    }
})

# ==================================================================================
#  INITIALIZE
# ==================================================================================
$window.Add_Loaded({
    Queue-Info "Defender Control v$script:Version initialized"
    Queue-Verbose "Administrator: True"
    Queue-Verbose "OS: $script:OSDetail"
    Queue-Verbose "PowerShell: $($PSVersionTable.PSVersion)"
    Queue-Verbose "Host: $env:COMPUTERNAME"
    Queue-Info "Manifest retention: $($script:ManifestRetentionDays) days; keep newest $($script:ManifestMaxCount) files. Redacted export is available from the log controls."
    if ($script:OSBuild -ge 22621) {
        Queue-Verbose "Note: Win11 22H2+ detected - some GP keys are deprecated but still applied"
    }
    Queue-Info "---"
    Update-StatusAsync
    Update-ScheduleStatus
})

$window.Add_Closed({ $script:uiTimer.Stop() })

$window.ShowDialog() | Out-Null
