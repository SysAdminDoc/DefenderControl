<#
.SYNOPSIS
    Defender Control v3.2.0 - Comprehensive Microsoft Defender Disable/Enable Utility

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
      - CLI: read-only Status / Health modes with JSON output for automation

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
      Verify  - same as Health plus a post-disable sanity check (alias for now)
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

.LINK
    https://github.com/SysAdminDoc/DefenderControl
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Disable','Enable','Status','Health','Verify')]
    [string]$Mode,

    [switch]$DryRun,
    [switch]$Silent,
    [switch]$Json,
    [switch]$Help,
    [switch]$NoRestorePoint,
    [switch]$NoReboot
)

# ==================================================================================
#  CLI EXIT CODES (shared by GUI + CLI)
# ==================================================================================
$script:EXIT_OK             = 0
$script:EXIT_PARTIAL        = 1
$script:EXIT_TAMPER_BLOCKED = 2
$script:EXIT_SAFEMODE       = 3
$script:EXIT_USAGE          = 4

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
    DefenderControl.ps1 -Help                    Show this usage

Flags:
    -Silent         Suppress non-essential CLI output
    -DryRun         Simulate without applying (GUI + CLI)
    -NoRestorePoint Skip restore-point creation (CLI-only)
    -NoReboot       Suppress reboot prompt (CLI-only)

Exit codes:
    0 success   1 partial   2 tamper-blocked   3 safe-mode-needed   4 usage-error

Note: -Mode Disable|Enable are reserved; use the GUI for mutating operations.
'@
    [Console]::Out.WriteLine($usage)
    exit $script:EXIT_OK
}

# ==================================================================================
#  SELF-ELEVATION (forwards original args so CLI mode survives UAC re-launch)
# ==================================================================================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {

    # Rebuild the original argument list from $PSBoundParameters so
    # switches/values survive the UAC re-launch.
    $forwardedArgs = New-Object System.Collections.Generic.List[string]
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        $name = $kv.Key
        $val  = $kv.Value
        if ($val -is [System.Management.Automation.SwitchParameter]) {
            if ($val.IsPresent) { $forwardedArgs.Add("-$name") | Out-Null }
        } else {
            $forwardedArgs.Add("-$name") | Out-Null
            $forwardedArgs.Add('"' + ($val -replace '"','\"') + '"') | Out-Null
        }
    }
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($forwardedArgs.Count -gt 0) { $argList += " " + ($forwardedArgs -join ' ') }

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

$script:Version    = "3.2.0"
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

# Check PowerShell edition
if ($PSVersionTable.PSEdition -eq 'Core') {
    if ($script:IsCliMode) {
        [Console]::Error.WriteLine("DefenderControl: requires Windows PowerShell 5.1 (not PowerShell 7+). Run with powershell.exe, not pwsh.")
        exit $script:EXIT_USAGE
    }
    [System.Windows.MessageBox]::Show(
        "This tool requires Windows PowerShell 5.1 (not PowerShell 7+).`n`nPlease run with: powershell.exe -File `"$PSCommandPath`"",
        "Wrong PowerShell Edition", "OK", "Error") | Out-Null
    exit
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
        AntivirusSignatureLastUpdated = $null
        DefenderEffectivelyEnabled = $false
        PolicyDisableAntiSpyware   = $null
        WinDefendStatus            = $null
        WinDefendStartType         = $null
        FirewallProfilesEnabled    = $null
        MpStatusQueryError         = $null
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

function Invoke-CliMode {
    param(
        [string]$Mode,
        [switch]$Json,
        [switch]$Silent
    )

    $script:Silent = $Silent.IsPresent

    switch ($Mode) {
        { $_ -in 'Status','Health','Verify' } {
            $extended = ($_ -in 'Health','Verify')
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
                Write-CliLine ("Last Signature Update   : {0}" -f $state.AntivirusSignatureLastUpdated)
                Write-CliLine ("WinDefend Service       : {0} (Start: {1})" -f $state.WinDefendStatus, $state.WinDefendStartType)
                Write-CliLine ("Policy DisableAntiSpy   : {0}" -f $state.PolicyDisableAntiSpyware)
                Write-CliLine ("Effectively Enabled     : {0}" -f $state.DefenderEffectivelyEnabled)
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

if ($script:IsCliMode) {
    Invoke-CliMode -Mode $Mode -Json:$Json -Silent:$Silent
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
                    <TextBlock x:Name="txtStatus" Text="Checking..." FontSize="20" FontWeight="Bold"
                               Foreground="{StaticResource AccentOrange}"/>
                    <TextBlock x:Name="txtTamper" Text="" FontSize="12"
                               Foreground="{StaticResource TextDim}" Margin="0,3,0,0"/>
                </StackPanel>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                    <Button x:Name="btnRefresh" Content="Refresh" Background="#2a2a4a"
                            Style="{StaticResource SmallButton}" Margin="0,0,8,0"/>
                    <Button x:Name="btnDisable" Content="  Disable Defender  " Background="{StaticResource AccentRed}"
                            Style="{StaticResource ActionButton}"/>
                    <Button x:Name="btnEnable" Content="  Enable Defender  " Background="{StaticResource AccentGreen}"
                            Style="{StaticResource ActionButton}" Margin="8,0,0,0"/>
                    <Button x:Name="btnReboot" Content="  Reboot Now  " Background="#8e44ad"
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
                    </Grid.RowDefinitions>

                    <!-- Row 0 -->
                    <StackPanel Grid.Row="0" Grid.Column="0" Margin="0,0,12,6">
                        <TextBlock Text="Real-Time Protection" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashRTP" Text="--" FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>
                    <StackPanel Grid.Row="0" Grid.Column="1" Margin="0,0,12,6">
                        <TextBlock Text="Tamper Protection" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashTamper" Text="--" FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>
                    <StackPanel Grid.Row="0" Grid.Column="2" Margin="0,0,12,6">
                        <TextBlock Text="Cloud Protection" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashCloud" Text="--" FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>

                    <!-- Row 1 -->
                    <StackPanel Grid.Row="1" Grid.Column="0" Margin="0,0,12,6">
                        <TextBlock Text="Firewall" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashFirewall" Text="--" FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>
                    <StackPanel Grid.Row="1" Grid.Column="1" Margin="0,0,12,6">
                        <TextBlock Text="Defender Service (WinDefend)" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashService" Text="--" FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>
                    <StackPanel Grid.Row="1" Grid.Column="2" Margin="0,0,12,6">
                        <TextBlock Text="Anti-Spyware Status" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashAntiSpy" Text="--" FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>

                    <!-- Row 2 -->
                    <StackPanel Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="3" Margin="0,0,12,0">
                        <TextBlock Text="Last Definition Update" FontSize="11" Foreground="{StaticResource TextDim}"/>
                        <TextBlock x:Name="dashDefUpdate" Text="--" FontSize="13" FontWeight="SemiBold" Foreground="#7f8c8d"/>
                    </StackPanel>

                    <!-- Refresh Dashboard button -->
                    <Button x:Name="btnRefreshDash" Content="Refresh Status" Background="#2a2a4a"
                            Style="{StaticResource SmallButton}" Grid.Row="0" Grid.Column="3"
                            VerticalAlignment="Top" Margin="4,0,0,0"/>
                </Grid>
            </StackPanel>
        </Border>

        <!-- Tamper Protection Warning Panel (hidden by default) -->
        <Border x:Name="tamperWarningPanel" Grid.Row="3" Visibility="Collapsed"
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
                <Button x:Name="btnOpenWSecurity" Content="Open Windows Security" Background="#3a2020"
                        Style="{StaticResource SmallButton}" HorizontalAlignment="Left" Margin="0,8,0,0"/>
            </StackPanel>
        </Border>

        <!-- Scheduled Re-Enable -->
        <Border Grid.Row="4" Style="{StaticResource Card}">
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
                          Style="{StaticResource DarkComboBox}" Width="80" Margin="0,0,8,0">
                    <ComboBoxItem Content="1 hour" IsSelected="True"/>
                    <ComboBoxItem Content="2 hours"/>
                    <ComboBoxItem Content="4 hours"/>
                    <ComboBoxItem Content="8 hours"/>
                    <ComboBoxItem Content="24 hours"/>
                </ComboBox>
                <Button x:Name="btnSchedule" Content="Schedule" Background="#8e44ad"
                        Style="{StaticResource SmallButton}" Grid.Column="2" Margin="0,0,8,0"/>
                <TextBlock x:Name="txtScheduleStatus" Grid.Column="3" Text="" FontSize="11"
                           Foreground="{StaticResource TextDim}" VerticalAlignment="Center"/>
                <Button x:Name="btnCancelSchedule" Content="Cancel" Background="#c0392b"
                        Style="{StaticResource SmallButton}" Grid.Column="4" Visibility="Collapsed"/>
            </Grid>
        </Border>

        <!-- Progress Bar -->
        <Border Grid.Row="5" Background="#16213e" CornerRadius="4" Height="6" Margin="0,0,0,8">
            <ProgressBar x:Name="progressBar" Minimum="0" Maximum="100" Value="0"
                         Height="6" Background="Transparent" Foreground="#3498db"
                         BorderThickness="0"/>
        </Border>

        <!-- Log Header -->
        <Grid Grid.Row="6" Margin="0,0,0,0">
            <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                <TextBlock Text="Operation Log" FontSize="13" FontWeight="SemiBold"
                           Foreground="{StaticResource TextSecondary}" VerticalAlignment="Center"/>
                <TextBlock x:Name="txtRunning" Text="" FontSize="12"
                           Foreground="{StaticResource AccentOrange}" Margin="12,0,0,0"
                           VerticalAlignment="Center"/>
            </StackPanel>
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
                <CheckBox x:Name="chkVerbose" Content=" Verbose" IsChecked="True"
                          Style="{StaticResource DarkCheck}" Margin="0,0,12,0"/>
                <Button x:Name="btnExport" Content="Export" Background="#2a2a4a"
                        Style="{StaticResource SmallButton}" Margin="0,0,6,0"/>
                <Button x:Name="btnClearLog" Content="Clear" Background="#2a2a4a"
                        Style="{StaticResource SmallButton}"/>
            </StackPanel>
        </Grid>

        <!-- Log Body -->
        <Border Grid.Row="7" Style="{StaticResource Card}" Margin="0,6,0,0">
            <Border Background="#0f1729" CornerRadius="6" Padding="4">
                <ScrollViewer x:Name="logScroll" VerticalScrollBarVisibility="Auto">
                    <RichTextBox x:Name="rtbLog" Background="Transparent" BorderThickness="0"
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
        <Grid Grid.Row="8" Margin="0,8,0,0">
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
$dashDefUpdate = $window.FindName("dashDefUpdate")
$btnRefreshDash = $window.FindName("btnRefreshDash")

# Tamper Protection warning panel
$tamperWarningPanel = $window.FindName("tamperWarningPanel")
$btnOpenWSecurity   = $window.FindName("btnOpenWSecurity")

# Scheduled re-enable controls
$cmbScheduleHours  = $window.FindName("cmbScheduleHours")
$btnSchedule       = $window.FindName("btnSchedule")
$txtScheduleStatus = $window.FindName("txtScheduleStatus")
$btnCancelSchedule = $window.FindName("btnCancelSchedule")

# Set dynamic text
$txtSubtitle.Text = "Comprehensive Microsoft Defender Management  |  $script:OSDetail"
$txtVersion.Text  = "v$script:Version  |  Running as Administrator"

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
          [bool]$ShowTamperWarning = $false)
    $script:DashQueue.Enqueue(@{
        RTP = $RTP; RTPColor = $RTPColor
        Tamper = $Tamper; TamperColor = $TamperColor
        Cloud = $Cloud; CloudColor = $CloudColor
        Firewall = $Firewall; FirewallColor = $FirewallColor
        Service = $Service; ServiceColor = $ServiceColor
        AntiSpy = $AntiSpy; AntiSpyColor = $AntiSpyColor
        DefUpdate = $DefUpdate; DefUpdateColor = $DefUpdateColor
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
        }
        if ($null -ne $st.TamperText -and $st.TamperText -ne "") {
            $txtTamper.Text = $st.TamperText
            $txtTamper.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($st.TamperColor)
        }
        $btnDisable.IsEnabled = $st.DisableBtn
        $btnEnable.IsEnabled  = $st.EnableBtn
        $btnRefresh.IsEnabled = (-not $script:IsRunning)
        if ($st.Progress -ge 0) { $progressBar.Value = $st.Progress }
        $txtRunning.Text = $st.RunningText
        if ($st.ShowReboot -eq "show")    { $btnReboot.Visibility = "Visible" }
        if ($st.ShowReboot -eq "hide")    { $btnReboot.Visibility = "Collapsed" }
    }

    # Drain dashboard queue
    $dsh = $null
    while ($script:DashQueue.TryDequeue([ref]$dsh)) {
        $bc = [System.Windows.Media.BrushConverter]::new()
        $dashRTP.Text = $dsh.RTP
        $dashRTP.Foreground = $bc.ConvertFromString($dsh.RTPColor)
        $dashTamper.Text = $dsh.Tamper
        $dashTamper.Foreground = $bc.ConvertFromString($dsh.TamperColor)
        $dashCloud.Text = $dsh.Cloud
        $dashCloud.Foreground = $bc.ConvertFromString($dsh.CloudColor)
        $dashFirewall.Text = $dsh.Firewall
        $dashFirewall.Foreground = $bc.ConvertFromString($dsh.FirewallColor)
        $dashService.Text = $dsh.Service
        $dashService.Foreground = $bc.ConvertFromString($dsh.ServiceColor)
        $dashAntiSpy.Text = $dsh.AntiSpy
        $dashAntiSpy.Foreground = $bc.ConvertFromString($dsh.AntiSpyColor)
        $dashDefUpdate.Text = $dsh.DefUpdate
        $dashDefUpdate.Foreground = $bc.ConvertFromString($dsh.DefUpdateColor)
        if ($dsh.ShowTamperWarning) {
            $tamperWarningPanel.Visibility = "Visible"
            $btnDisable.ToolTip = "Tamper Protection must be disabled first. See the warning panel below for instructions."
        } else {
            $tamperWarningPanel.Visibility = "Collapsed"
            $btnDisable.ToolTip = $null
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
          [bool]`$ShowTamperWarning = `$false)
    `$DashQueue.Enqueue(@{
        RTP = `$RTP; RTPColor = `$RTPColor
        Tamper = `$Tamper; TamperColor = `$TamperColor
        Cloud = `$Cloud; CloudColor = `$CloudColor
        Firewall = `$Firewall; FirewallColor = `$FirewallColor
        Service = `$Service; ServiceColor = `$ServiceColor
        AntiSpy = `$AntiSpy; AntiSpyColor = `$AntiSpyColor
        DefUpdate = `$DefUpdate; DefUpdateColor = `$DefUpdateColor
        ShowTamperWarning = `$ShowTamperWarning
    })
}
function Set-RegValue {
    param([string]`$Path, [string]`$Name, `$Value, [string]`$Type = "DWord")
    if (`$DryRun) { Queue-Info "  [DRY RUN] Would set `$Path\`$Name = `$Value"; return `$true }
    try {
        if (-not (Test-Path `$Path)) { New-Item -Path `$Path -Force | Out-Null; Queue-Verbose "  Created key: `$Path" }
        Set-ItemProperty -Path `$Path -Name `$Name -Value `$Value -Type `$Type -Force -ErrorAction Stop
        return `$true
    } catch { Queue-Err "  REG ERROR: `$Path\`$Name - `$_"; return `$false }
}
function Remove-RegValue {
    param([string]`$Path, [string]`$Name)
    if (`$DryRun) { Queue-Info "  [DRY RUN] Would remove `$Path\`$Name"; return `$true }
    try {
        if (Test-Path `$Path) {
            `$val = Get-ItemProperty -Path `$Path -Name `$Name -ErrorAction SilentlyContinue
            if (`$null -ne `$val.`$Name) { Remove-ItemProperty -Path `$Path -Name `$Name -Force -ErrorAction Stop }
        }
        return `$true
    } catch { Queue-Err "  REG REMOVE ERROR: `$Path\`$Name - `$_"; return `$false }
}
function Set-ProtectedRegValue {
    param([string]`$KeyPath, [string]`$ValueName, [int]`$Value)
    if (`$DryRun) { Queue-Info "  [DRY RUN] Would set `$KeyPath\`$ValueName = `$Value (protected)"; return `$true }
    `$fullPath = "HKLM:\`$KeyPath"
    # Attempt 1: Direct write
    try {
        Set-ItemProperty -Path `$fullPath -Name `$ValueName -Value `$Value -Type DWord -Force -ErrorAction Stop
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
            return `$true
        }
    } catch { Queue-Verbose "    SYSTEM task failed: `$(`$_.Exception.Message)" }
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
"@

# ==================================================================================
#  BACKGROUND RUNSPACE RUNNER
# ==================================================================================
function Start-BackgroundWork {
    param([ScriptBlock]$Work, [switch]$AutoRefresh)

    $script:IsRunning = $true
    $script:DryRun = $chkDryRun.IsChecked
    $window.Dispatcher.Invoke([Action]{
        $btnDisable.IsEnabled = $false
        $btnEnable.IsEnabled  = $false
        $btnRefresh.IsEnabled = $false
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
            try { $data.PS.EndInvoke($data.Handle) } catch {}
            $data.PS.Dispose()
            $data.Runspace.Dispose()
            $script:IsRunning = $false
            $btnRefresh.IsEnabled = $true
            $chkDryRun.IsEnabled  = $true
            if ($data.AutoRefresh) {
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

        # Dashboard defaults
        $rtpText = "OFF"; $rtpColor = "#e74c3c"
        $tamperText = "OFF"; $tamperColor = "#7f8c8d"
        $cloudText = "OFF"; $cloudColor = "#e74c3c"
        $fwText = "OFF"; $fwColor = "#e74c3c"
        $svcText = "Unknown"; $svcColor = "#7f8c8d"
        $antiSpyText = "Unknown"; $antiSpyColor = "#7f8c8d"
        $defUpdateText = "Unknown"; $defUpdateColor = "#7f8c8d"

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

        # Push dashboard update
        Queue-Dashboard -RTP $rtpText -RTPColor $rtpColor `
            -Tamper $tamperText -TamperColor $tamperColor `
            -Cloud $cloudText -CloudColor $cloudColor `
            -Firewall $fwText -FirewallColor $fwColor `
            -Service $svcText -ServiceColor $svcColor `
            -AntiSpy $antiSpyText -AntiSpyColor $antiSpyColor `
            -DefUpdate $defUpdateText -DefUpdateColor $defUpdateColor `
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
        $totalPhases = 10
        $phase = 0

        if ($DryRun) {
            Queue-Warn "========== DRY RUN MODE - No changes will be made =========="
        }
        Queue-Info "============================================"
        Queue-Info "  DISABLING MICROSOFT DEFENDER"
        Queue-Info "============================================"
        Start-Sleep -Milliseconds 100

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

        # -- Final Status ----------------------------------------------------------------
        Queue-Info "============================================"
        if ($DryRun) {
            Queue-Info "  DRY RUN COMPLETE - No changes were made"
        } else {
            Queue-Info "  DISABLE OPERATION COMPLETE"
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
        $totalPhases  = 7
        $phase        = 0

        if ($DryRun) {
            Queue-Warn "========== DRY RUN MODE - No changes will be made =========="
        }
        Queue-Info "============================================"
        Queue-Info "  RE-ENABLING MICROSOFT DEFENDER"
        Queue-Info "============================================"
        Start-Sleep -Milliseconds 100

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

        Queue-Info "============================================"
        if ($DryRun) {
            Queue-Info "  DRY RUN COMPLETE - No changes were made"
        } else {
            Queue-Info "  ENABLE OPERATION COMPLETE"
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
            $btnCancelSchedule.Visibility = "Visible"
        } else {
            $txtScheduleStatus.Text = ""
            $btnCancelSchedule.Visibility = "Collapsed"
        }
    } catch {
        $txtScheduleStatus.Text = ""
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
    if ($script:OSBuild -ge 22621) {
        Queue-Verbose "Note: Win11 22H2+ detected - some GP keys are deprecated but still applied"
    }
    Queue-Info "---"
    Update-StatusAsync
    Update-ScheduleStatus
})

$window.Add_Closed({ $script:uiTimer.Stop() })

$window.ShowDialog() | Out-Null
