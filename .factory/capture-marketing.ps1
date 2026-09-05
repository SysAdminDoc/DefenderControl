<#
.SYNOPSIS
    Renders a marketing screenshot directly from the production WPF XAML.

.DESCRIPTION
    The window is measured and drawn offscreen. No Defender setting is queried
    or changed, and no visible desktop window is opened. Dashboard values are
    representative sample data for documentation.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [ValidateSet('Dashboard', 'Tamper')]
    [string]$State = 'Dashboard'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName WindowsBase

Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class DefenderControlCaptureDpi {
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
}
'@
[DefenderControlCaptureDpi]::SetProcessDPIAware() | Out-Null

$rootPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$sourcePath = Join-Path $rootPath 'DefenderControl.ps1'
$source = Get-Content -LiteralPath $sourcePath -Raw
$match = [regex]::Match(
    $source,
    '(?s)\[xml\]\$xaml\s*=\s*@"\r?\n(?<xaml><Window.*?</Window>)\r?\n"@'
)
if (-not $match.Success) {
    throw 'Could not extract the WPF XAML from DefenderControl.ps1.'
}
if ($source -notmatch '\$script:Version\s*=\s*"(?<Version>[^"]+)"') {
    throw 'Could not read the product version from DefenderControl.ps1.'
}
$version = $Matches.Version

[xml]$xaml = $match.Groups['xaml'].Value
$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)
$brush = [System.Windows.Media.BrushConverter]::new()

function Set-TextState {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Color
    )
    $control = $window.FindName($Name)
    if (-not $control) { throw "Missing XAML control: $Name" }
    $control.Text = $Text
    $control.Foreground = $brush.ConvertFromString($Color)
}

Set-TextState 'txtSubtitle' 'Windows 11 Pro  |  Build 26200  |  Administrator' '#7f8c8d'
Set-TextState 'txtVersion' "v$version  |  Sample status" '#7f8c8d'
Set-TextState 'txtStatus' 'PROTECTED' '#2ecc71'
Set-TextState 'txtTamper' 'Tamper Protection: Off  |  Ready for controlled maintenance' '#95a5a6'
Set-TextState 'dashRTP' 'ON' '#2ecc71'
Set-TextState 'dashTamper' 'OFF' '#2ecc71'
Set-TextState 'dashCloud' 'ON' '#2ecc71'
Set-TextState 'dashFirewall' 'ON (untouched)' '#2ecc71'
Set-TextState 'dashService' 'RUNNING' '#2ecc71'
Set-TextState 'dashAntiSpy' 'ON' '#2ecc71'
Set-TextState 'dashPplMsMpEng' 'PROTECTED' '#3498db'
Set-TextState 'dashPplWdFilter' 'PROTECTED' '#3498db'
Set-TextState 'dashPplWdNisDrv' 'PROTECTED' '#3498db'
Set-TextState 'dashMode' 'NORMAL' '#2ecc71'
Set-TextState 'dashPlatform' '4.18.25080.5' '#3498db'
Set-TextState 'dashMde' 'NOT MANAGED' '#95a5a6'
Set-TextState 'dashDefUpdate' '2 minutes ago' '#ecf0f1'

$window.FindName('chkVerbose').IsChecked = $true
$window.FindName('cmbScheduleHours').SelectedIndex = 3
$window.FindName('txtScheduleStatus').Text = 'No automatic restore is scheduled'

if ($State -eq 'Tamper') {
    $window.FindName('tamperWarningPanel').Visibility = 'Visible'
    Set-TextState 'txtStatus' 'ACTION REQUIRED' '#e67e22'
    Set-TextState 'txtTamper' 'Tamper Protection must be turned off before disabling Defender' '#e8a0a0'
    Set-TextState 'dashTamper' 'ON' '#e74c3c'
}

$log = $window.FindName('rtbLog')
$log.Document.Blocks.Clear()
$entries = @(
    @{ Time = '06:32:14'; Text = 'Status refresh started'; Color = '#95a5a6' },
    @{ Time = '06:32:15'; Text = 'Defender mode: Normal'; Color = '#3498db' },
    @{ Time = '06:32:15'; Text = 'Firewall integrity snapshot: unchanged'; Color = '#2ecc71' },
    @{ Time = '06:32:16'; Text = 'Tamper Protection: Off'; Color = '#2ecc71' },
    @{ Time = '06:32:16'; Text = 'System is ready for controlled maintenance'; Color = '#ecf0f1' }
)
if ($State -eq 'Tamper') {
    $entries[3] = @{ Time = '06:32:16'; Text = 'Tamper Protection: On'; Color = '#e74c3c' }
    $entries[4] = @{ Time = '06:32:16'; Text = 'Disable is blocked until Tamper Protection is off'; Color = '#e67e22' }
}
foreach ($entry in $entries) {
    $paragraph = [System.Windows.Documents.Paragraph]::new()
    $paragraph.Margin = [System.Windows.Thickness]::new(0, 1, 0, 1)
    $timeRun = [System.Windows.Documents.Run]::new("[$($entry.Time)]  ")
    $timeRun.Foreground = $brush.ConvertFromString('#7f8c8d')
    $messageRun = [System.Windows.Documents.Run]::new($entry.Text)
    $messageRun.Foreground = $brush.ConvertFromString($entry.Color)
    $paragraph.Inlines.Add($timeRun)
    $paragraph.Inlines.Add($messageRun)
    $log.Document.Blocks.Add($paragraph)
}

$width = 880
$height = 920
$window.WindowStartupLocation = 'Manual'
$window.Left = -32000
$window.Top = -32000
$window.ShowActivated = $false
$window.ShowInTaskbar = $false
$window.WindowStyle = 'None'
$window.Width = $width
$window.Height = $height
$window.Show()
$window.Dispatcher.Invoke(
    [Action]{},
    [System.Windows.Threading.DispatcherPriority]::Render
)
$window.UpdateLayout()

$bitmap = [System.Windows.Media.Imaging.RenderTargetBitmap]::new(
    $width,
    $height,
    96,
    96,
    [System.Windows.Media.PixelFormats]::Pbgra32
)
$bitmap.Render($window)

$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
$directory = Split-Path -Parent $resolvedOutput
if ($directory) { [System.IO.Directory]::CreateDirectory($directory) | Out-Null }
$encoder = [System.Windows.Media.Imaging.PngBitmapEncoder]::new()
$encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
$stream = [System.IO.File]::Open($resolvedOutput, [System.IO.FileMode]::Create)
try {
    $encoder.Save($stream)
} finally {
    $stream.Dispose()
    $window.Close()
}

Write-Host "Captured $State sample state to $resolvedOutput"
