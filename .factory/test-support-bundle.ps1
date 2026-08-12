$ErrorActionPreference = 'Stop'

$source = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\DefenderControl.ps1')
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Select-Object -First 1).Message }

$functionAst = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'New-DefenderControlSupportBundle'
}, $true)
if (-not $functionAst) { throw 'Support bundle function not found' }
Invoke-Expression $functionAst.Extent.Text

$sharedAssignment = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$script:SharedFunctions'
}, $true) | Where-Object { $_.Operator -eq 'Equals' } | Select-Object -First 1)
if (-not $sharedAssignment) { throw 'SharedFunctions assignment not found' }
Invoke-Expression $sharedAssignment.Extent.Text
$supportAppend = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$script:SharedFunctions'
}, $true) | Where-Object { $_.Operator -eq 'PlusEquals' } | Select-Object -First 1)
if (-not $supportAppend) { throw 'Support bundle injection assignment not found' }
Invoke-Expression $supportAppend.Extent.Text
$sharedTokens = $null
$sharedErrors = $null
[System.Management.Automation.Language.Parser]::ParseInput($script:SharedFunctions, [ref]$sharedTokens, [ref]$sharedErrors) | Out-Null
if ($sharedErrors.Count -gt 0) { throw ($sharedErrors | Select-Object -First 1).Message }
if ($script:SharedFunctions -notmatch 'function New-DefenderControlSupportBundle') {
    throw 'Support bundle function was not injected into SharedFunctions'
}
Invoke-Expression $script:SharedFunctions

$outputPath = Join-Path $env:TEMP ('DefenderControl-Support-Test-' + [guid]::NewGuid().ToString('N') + '.zip')
$fakeState = [ordered]@{
    Version = 'test'
    Timestamp = (Get-Date).ToString('o')
    Computer = 'TEST'
    OS = 'Windows 11'
    OSBuild = 26100
    DefenderMode = 'Normal'
    DefenderPlatformVersion = '4.18.1.2'
    ManagedDevice = $false
    Services = [ordered]@{}
    PolicyKeys = [ordered]@{}
}

try {
    $bundle = New-DefenderControlSupportBundle -OutputPath $outputPath -State $fakeState `
        -LogEntries @(@{ Time = '12:00:00'; Message = 'test log' }) `
        -Version 'test' -OSDetail 'Windows 11 (Build 26100)'
    if (-not (Test-Path -LiteralPath $bundle.Path)) { throw 'Bundle was not created' }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($bundle.Path)
    try {
        $names = @($zip.Entries | ForEach-Object { $_.FullName })
        foreach ($required in @('Health.json', 'operation-log.txt', 'events.json', 'bundle-metadata.json')) {
            if ($required -notin $names) { throw "Missing required bundle entry: $required" }
        }
    } finally {
        $zip.Dispose()
    }
    Write-Host 'Support bundle harness: OK'
} finally {
    if (Test-Path -LiteralPath $outputPath) {
        Remove-Item -LiteralPath $outputPath -Force -ErrorAction SilentlyContinue
    }
}
