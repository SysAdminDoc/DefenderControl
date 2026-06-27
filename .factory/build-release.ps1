<#
.SYNOPSIS
    Builds the portable DefenderControl release ZIP.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$scriptPath = Join-Path $root 'DefenderControl.ps1'
$readmePath = Join-Path $root 'README.md'
$licensePath = Join-Path $root 'LICENSE'
$checksumPath = Join-Path $root 'SHA256SUMS.txt'

function Get-Sha256Hex {
    param([Parameter(Mandatory)][string]$Path)

    $hashCommand = Get-Command Get-FileHash -ErrorAction SilentlyContinue
    if ($hashCommand) {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $resolvedPath = (Resolve-Path -LiteralPath $Path).ProviderPath
    $stream = [System.IO.File]::OpenRead($resolvedPath)
    $sha = $null
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        return (($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $stream.Dispose()
        if ($sha) { $sha.Dispose() }
    }
}

foreach ($required in @($scriptPath, $readmePath, $licensePath)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required payload file missing: $required"
    }
}

$scriptText = Get-Content -Raw -LiteralPath $scriptPath
if ($scriptText -notmatch '\$script:Version\s*=\s*"(?<Version>[^"]+)"') {
    throw 'Could not determine DefenderControl version from DefenderControl.ps1'
}

$version = $Matches.Version
$dist = Join-Path $root 'dist'
$stage = Join-Path $dist "DefenderControl-v$version"
$zipPath = Join-Path $dist "DefenderControl-v$version.zip"
$releaseSumsPath = Join-Path $dist 'SHA256SUMS.txt'

if (Test-Path -LiteralPath $dist) {
    $resolvedRoot = (Resolve-Path -LiteralPath $root).ProviderPath
    $resolvedDist = (Resolve-Path -LiteralPath $dist).ProviderPath
    if (-not $resolvedDist.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean unexpected dist path: $resolvedDist"
    }
    Remove-Item -LiteralPath $dist -Recurse -Force
}

New-Item -Path $stage -ItemType Directory -Force | Out-Null

foreach ($fileName in @('DefenderControl.ps1', 'README.md', 'LICENSE')) {
    Copy-Item -LiteralPath (Join-Path $root $fileName) -Destination (Join-Path $stage $fileName) -Force
}

Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -Force
Remove-Item -LiteralPath $stage -Recurse -Force

$scriptHash = Get-Sha256Hex -Path $scriptPath
$zipHash = Get-Sha256Hex -Path $zipPath

Set-Content -LiteralPath $checksumPath -Value ("$scriptHash *DefenderControl.ps1") -Encoding ASCII
Set-Content -LiteralPath $releaseSumsPath -Value @(
    "$scriptHash *DefenderControl.ps1"
    "$zipHash *DefenderControl-v$version.zip"
) -Encoding ASCII

Write-Host "Built dist/DefenderControl-v$version.zip"
Write-Host "Updated SHA256SUMS.txt"
