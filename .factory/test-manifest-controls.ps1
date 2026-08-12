$ErrorActionPreference = 'Stop'

$source = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\DefenderControl.ps1')
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Select-Object -First 1).Message }

$needed = @(
    'Get-DefenderControlManifestDirectory', 'Get-DefenderControlManifestFiles',
    'Get-DefenderControlManifestSummary', 'Remove-DefenderControlManifests',
    'ConvertTo-RedactedDefenderControlText', 'ConvertTo-RedactedDefenderControlValue',
    'Export-DefenderControlRedactedData'
)
foreach ($functionName in $needed) {
    $functionAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $functionName
    }, $true)
    if (-not $functionAst) { throw "Function not found: $functionName" }
    Invoke-Expression $functionAst.Extent.Text
}

$script:ManifestRetentionDays = 30
$script:ManifestMaxCount = 50
$root = Join-Path $env:TEMP ('DefenderControl-Manifest-Test-' + [guid]::NewGuid().ToString('N'))
$zipPath = Join-Path $env:TEMP ('DefenderControl-Redacted-Test-' + [guid]::NewGuid().ToString('N') + '.zip')
$failures = 0

function Assert-ManifestTest {
    param([bool]$Condition, [string]$Label)
    if ($Condition) { Write-Host "[PASS] $Label" }
    else { Write-Host "[FAIL] $Label"; $script:failures++ }
}

try {
    New-Item -Path $root -ItemType Directory -Force | Out-Null
    $manifest = [ordered]@{
        schemaVersion = 1
        operation = 'Disable'
        host = 'TESTHOST'
        thirdPartyAV = @('Acme AV')
        transactionLog = @(@{
            Name = 'SensitiveValue'
            Path = 'HKLM:\SOFTWARE\Sensitive'
            Before = 'secret-before'
            After = 'secret-after'
        })
        message = 'TESTHOST C:\Users\alice\Desktop\secret.txt'
    }
    foreach ($name in @('Disable-old.json', 'Enable-recent.json', 'Disable-recent.json')) {
        $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root $name) -Encoding UTF8
    }
    (Get-Item -LiteralPath (Join-Path $root 'Disable-old.json')).LastWriteTime = (Get-Date).AddDays(-40)

    $summary = Get-DefenderControlManifestSummary -Directory $root
    Assert-ManifestTest ($summary.Count -eq 3 -and $summary.RetentionDays -eq 30 -and $summary.MaxCount -eq 50) 'manifest list reports default retention'

    $redacted = Export-DefenderControlRedactedData -Directory $root -OutputPath $zipPath `
        -LogEntries @(@{ Time = '12:00:00'; Message = 'TESTHOST HKCU:\Software\Sensitive C:\Users\alice\secret.log' })
    Assert-ManifestTest ($redacted.ManifestIncluded -and $redacted.LogIncluded -and (Test-Path -LiteralPath $zipPath)) 'redacted export creates manifest and log ZIP'

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        $names = @($zip.Entries | ForEach-Object { $_.FullName })
        Assert-ManifestTest ('manifest-redacted.json' -in $names) 'redacted manifest entry exists'
        Assert-ManifestTest ('operation-log-redacted.txt' -in $names) 'redacted operation log entry exists'
        $manifestEntry = $zip.GetEntry('manifest-redacted.json')
        $reader = New-Object IO.StreamReader($manifestEntry.Open())
        try { $manifestText = $reader.ReadToEnd() } finally { $reader.Dispose() }
        Assert-ManifestTest ($manifestText -notmatch 'TESTHOST|Acme AV|SensitiveValue|secret-before|HKLM:|C:\\Users\\alice') 'manifest redaction removes sensitive values'
    } finally { $zip.Dispose() }

    $pruned = Remove-DefenderControlManifests -Directory $root -RetentionDays 30 -MaxCount 50
    Assert-ManifestTest ($pruned.RemovedCount -eq 1 -and -not (Test-Path -LiteralPath (Join-Path $root 'Disable-old.json'))) 'prune removes manifests outside retention window'
} finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
}

if ($failures -gt 0) { throw "$failures manifest control assertion(s) failed" }
Write-Host 'Manifest controls harness: OK'
