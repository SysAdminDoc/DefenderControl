<#
.SYNOPSIS
    Builds the 1280 by 640 GitHub social preview from verified local assets.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$baseSvg = Join-Path $root '.github\social-preview-base.svg'
$icon = Join-Path $root 'assets\icons\defender-control-128.png'
$main = Get-Content -LiteralPath (Join-Path $root 'DefenderControl.ps1') -Raw
if ($main -notmatch '\$script:Version\s*=\s*"(?<Version>[^"]+)"') {
    throw 'Could not read the product version.'
}
$version = $Matches.Version
$screenshot = Join-Path $root "screenshots\defender-control-dashboard-v$version.png"
$output = Join-Path $root '.github\social-preview.png'
$defaultMagick = 'C:\Program Files\ImageMagick-7.1.2-Q16-HDRI\magick.exe'
$magickCommand = Get-Command magick.exe -ErrorAction SilentlyContinue
$magick = if ($magickCommand) { $magickCommand.Source } elseif (Test-Path -LiteralPath $defaultMagick) { $defaultMagick } else { $null }

foreach ($required in @($baseSvg, $icon, $screenshot)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required marketing input missing: $required" }
}
if (-not $magick) { throw 'ImageMagick 7 is required to build the social preview.' }

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("defendercontrol-marketing-" + [guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
try {
    $base = Join-Path $tempRoot 'base.png'
    $screen = Join-Path $tempRoot 'screen.png'
    $mask = Join-Path $tempRoot 'mask.png'
    $roundedScreen = Join-Path $tempRoot 'screen-rounded.png'
    $smallIcon = Join-Path $tempRoot 'icon.png'

    & $magick -background none $baseSvg $base
    if ($LASTEXITCODE -ne 0) { throw 'Could not render the social preview base.' }

    & $magick $screenshot -resize '546x572^' -gravity center -extent 546x572 $screen
    if ($LASTEXITCODE -ne 0) { throw 'Could not size the product screenshot.' }
    & $magick -size 546x572 xc:none -fill white -draw 'roundrectangle 0,0 545,571 18,18' $mask
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the product screenshot mask.' }
    & $magick $screen $mask -alpha off -compose CopyOpacity -composite $roundedScreen
    if ($LASTEXITCODE -ne 0) { throw 'Could not mask the product screenshot.' }
    & $magick $icon -resize 70x70 $smallIcon
    if ($LASTEXITCODE -ne 0) { throw 'Could not size the product icon.' }

    & $magick $base $roundedScreen -geometry '+694+42' -compose over -composite $smallIcon -geometry '+68+50' -compose over -composite $output
    if ($LASTEXITCODE -ne 0) { throw 'Could not assemble the social preview.' }

    $dimensions = (& $magick identify -format '%wx%h' $output).Trim()
    if ($dimensions -ne '1280x640') { throw "Unexpected social preview size: $dimensions" }
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

Write-Host 'Built .github\social-preview.png at 1280x640'
