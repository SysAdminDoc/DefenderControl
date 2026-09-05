[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$failures = 0

function Assert-Marketing {
    param([bool]$Condition, [string]$Label)
    if ($Condition) {
        Write-Host ("[PASS] {0}" -f $Label)
    } else {
        Write-Host ("[FAIL] {0}" -f $Label)
        $script:failures++
    }
}

$mainPath = Join-Path $root 'DefenderControl.ps1'
$main = Get-Content -LiteralPath $mainPath -Raw
$readme = Get-Content -LiteralPath (Join-Path $root 'README.md') -Raw
$capture = Get-Content -LiteralPath (Join-Path $root '.factory\capture-marketing.ps1') -Raw
$marketingBuild = Get-Content -LiteralPath (Join-Path $root '.factory\build-marketing-assets.ps1') -Raw
if ($main -notmatch '\$script:Version\s*=\s*"(?<Version>[^"]+)"') {
    throw 'Could not read the product version.'
}
$version = $Matches.Version

Assert-Marketing ($readme -match [regex]::Escape("version-$version-")) 'README badge matches the product version'
Assert-Marketing ($readme -match [regex]::Escape("DefenderControl-v$version.zip")) 'README release path matches the product version'
Assert-Marketing ($main -match '<DrawingImage x:Key="AppIcon">') 'WPF resources contain the native app mark'
Assert-Marketing ($main -match '\$window\.Icon\s*=\s*\$window\.Resources\[''AppIcon''\]') 'WPF window uses the native app mark'
Assert-Marketing ($capture -match '\$window\.ShowActivated\s*=\s*\$false') 'marketing capture cannot activate its hidden window'
Assert-Marketing ($capture -match '\$window\.Left\s*=\s*-32000') 'marketing capture stays offscreen'
Assert-Marketing ($capture -notmatch '(?m)^\s*(?:Set-MpPreference|Set-ItemProperty|Remove-ItemProperty|New-ScheduledTask)\b') 'marketing capture has no Defender mutation command'
Assert-Marketing ($marketingBuild -match 'dashboard-v\$version\.png') 'social preview build follows the product version'

$svgPath = Join-Path $root 'assets\defender-control-mark.svg'
try {
    [xml]$svg = Get-Content -LiteralPath $svgPath -Raw
    Assert-Marketing ($svg.DocumentElement.LocalName -eq 'svg') 'brand source is valid SVG'
} catch {
    Assert-Marketing $false ("brand source is valid SVG: {0}" -f $_.Exception.Message)
}

Add-Type -AssemblyName System.Drawing
foreach ($size in @(16, 32, 48, 64, 128, 256, 512, 1024)) {
    $path = Join-Path $root "assets\icons\defender-control-$size.png"
    Assert-Marketing (Test-Path -LiteralPath $path) "${size}px icon exists"
    if (Test-Path -LiteralPath $path) {
        $image = [System.Drawing.Bitmap]::new($path)
        try {
            Assert-Marketing ($image.Width -eq $size -and $image.Height -eq $size) "${size}px icon dimensions are exact"
            Assert-Marketing ($image.PixelFormat.ToString() -match 'Alpha|Argb') "${size}px icon has alpha transparency"
            Assert-Marketing ($image.GetPixel(0, 0).A -eq 0) "${size}px icon has a transparent corner"
        } finally {
            $image.Dispose()
        }
    }
}

$rasterExpectations = @{
    '.github\social-preview.png' = @(1280, 640)
    "screenshots\defender-control-dashboard-v$version.png" = @(880, 920)
    "screenshots\defender-control-tamper-guidance-v$version.png" = @(880, 920)
}
foreach ($relativePath in $rasterExpectations.Keys) {
    $path = Join-Path $root $relativePath
    Assert-Marketing (Test-Path -LiteralPath $path) "$relativePath exists"
    if (Test-Path -LiteralPath $path) {
        $image = [System.Drawing.Image]::FromFile($path)
        try {
            $expected = $rasterExpectations[$relativePath]
            Assert-Marketing ($image.Width -eq $expected[0] -and $image.Height -eq $expected[1]) "$relativePath dimensions are exact"
        } finally {
            $image.Dispose()
        }
    }
}

$icoPath = Join-Path $root 'assets\DefenderControl.ico'
Assert-Marketing (Test-Path -LiteralPath $icoPath) 'Windows ICO exists'
if (Test-Path -LiteralPath $icoPath) {
    $icoBytes = [System.IO.File]::ReadAllBytes($icoPath)
    Assert-Marketing ($icoBytes.Length -ge 6 -and [BitConverter]::ToUInt16($icoBytes, 4) -eq 6) 'Windows ICO contains six size frames'
    $icon = [System.Drawing.Icon]::new($icoPath)
    $icon.Dispose()
}

if ($failures -gt 0) {
    Write-Error ("Marketing asset validation failed with {0} failure(s)." -f $failures)
    exit 1
}

Write-Host 'Marketing assets: OK'
