<#
.SYNOPSIS
    Renders the DefenderControl vector mark into Windows and README assets.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$source = Join-Path $root 'assets\defender-control-mark.svg'
$iconDirectory = Join-Path $root 'assets\icons'
$defaultMagick = 'C:\Program Files\ImageMagick-7.1.2-Q16-HDRI\magick.exe'
$magickCommand = Get-Command magick.exe -ErrorAction SilentlyContinue
$magick = if ($magickCommand) { $magickCommand.Source } elseif (Test-Path -LiteralPath $defaultMagick) { $defaultMagick } else { $null }

if (-not (Test-Path -LiteralPath $source)) {
    throw "Vector mark not found: $source"
}
if (-not $magick) {
    throw 'ImageMagick 7 is required to rebuild the brand assets.'
}

[System.IO.Directory]::CreateDirectory($iconDirectory) | Out-Null
$sizes = @(16, 32, 48, 64, 128, 256, 512, 1024)
$pngPaths = @()
foreach ($size in $sizes) {
    $output = Join-Path $iconDirectory "defender-control-$size.png"
    & $magick -background none $source -resize "${size}x${size}" $output
    if ($LASTEXITCODE -ne 0) { throw "ImageMagick failed while rendering $output" }
    $channels = (& $magick identify -format '%[channels]' $output).Trim()
    if ($channels -notmatch 'a') { throw "$output has no alpha channel: $channels" }
    $pngPaths += $output
}

$icoInputs = @(16, 32, 48, 64, 128, 256) | ForEach-Object {
    Join-Path $iconDirectory "defender-control-$_.png"
}
$icoPath = Join-Path $root 'assets\DefenderControl.ico'
& $magick @icoInputs $icoPath
if ($LASTEXITCODE -ne 0) { throw "ImageMagick failed while rendering $icoPath" }

Write-Host "Rendered $($pngPaths.Count) transparent PNGs and assets\DefenderControl.ico"
