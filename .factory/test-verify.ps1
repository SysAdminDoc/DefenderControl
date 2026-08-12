# Isolated tests for Invoke-VerifyMode logic.
# Stubs Get-DefenderState in child powershell.exe processes so exit() is testable.

$ErrorActionPreference = 'Stop'

$script:Version  = '3.3.3'
$script:OSBuild  = 26100
$script:OSDetail = "Windows 11 (Build $script:OSBuild)"

$repoScript = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\DefenderControl.ps1')).ProviderPath
$src = Get-Content -Raw -LiteralPath $repoScript
$tokens = $null
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errs)
if ($errs -and $errs.Count -gt 0) {
    $errs | ForEach-Object { Write-Error $_.Message }
    exit 1
}

$wanted = @('Write-CliLine', 'Invoke-VerifyMode')
$funcs = $ast.FindAll({
    param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $wanted
}, $true)

$found = @($funcs | ForEach-Object { $_.Name })
foreach ($name in $wanted) {
    if ($name -notin $found) {
        Write-Error "Could not extract required function: $name"
        exit 1
    }
}

$functionText = (($funcs | Sort-Object { [array]::IndexOf($wanted, $_.Name) } | ForEach-Object {
    $_.Extent.Text
}) -join [Environment]::NewLine)

function Invoke-VerifyIsolated {
    param([hashtable]$FakeState, [string]$Expect, [bool]$WantJson)

    $stateJson = $FakeState | ConvertTo-Json -Depth 6 -Compress
    $modeArgs = if ($WantJson) { "-Expect '$Expect' -Json" } else { "-Expect '$Expect'" }
    $script = @(
        '$script:Version = ''3.3.3'''
        '$script:OSBuild = 26100'
        '$script:OSDetail = ''Windows 11 (Build 26100)'''
        '$script:EXIT_OK = 0'
        '$script:EXIT_PARTIAL = 1'
        '$script:EXIT_TAMPER_BLOCKED = 2'
        '$script:EXIT_SAFEMODE = 3'
        '$script:EXIT_USAGE = 4'
        '$script:EXIT_VERIFY_FAIL = 5'
        '$script:Silent = $false'
        $functionText
        '$fakeStateJson = @'''
        $stateJson
        '''@'
        'function Get-DefenderState {'
        '    param([switch]$Extended)'
        '    $obj = $fakeStateJson | ConvertFrom-Json'
        '    $ht = [ordered]@{}'
        '    foreach ($p in $obj.PSObject.Properties) { $ht[$p.Name] = $p.Value }'
        '    return $ht'
        '}'
        "Invoke-VerifyMode $modeArgs"
    ) -join [Environment]::NewLine

    $tmp = [System.IO.Path]::GetTempFileName() + '.ps1'
    [System.IO.File]::WriteAllText($tmp, $script, [System.Text.Encoding]::UTF8)
    try {
        $proc = Start-Process -FilePath 'powershell.exe' `
            -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$tmp `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput ($tmp + '.out') `
            -RedirectStandardError  ($tmp + '.err')
        $out = Get-Content -Raw ($tmp + '.out') -ErrorAction SilentlyContinue
        $err = Get-Content -Raw ($tmp + '.err') -ErrorAction SilentlyContinue
        return @{ ExitCode = $proc.ExitCode; Output = $out; Error = $err }
    } finally {
        Remove-Item -LiteralPath $tmp,($tmp + '.out'),($tmp + '.err') -Force -ErrorAction SilentlyContinue
    }
}

$failures = 0
function Assert-ExitCode {
    param([hashtable]$Result, [int]$Expected, [string]$Label)
    if ($Result.ExitCode -ne $Expected) {
        Write-Host "[FAIL] $Label exit=$($Result.ExitCode) want=$Expected"
        if ($Result.Output) { Write-Host $Result.Output }
        if ($Result.Error) { Write-Host $Result.Error }
        $script:failures++
    } else {
        Write-Host "[PASS] $Label exit=$Expected"
    }
}

$enabled = @{
    Version='3.3.3'; Timestamp=(Get-Date).ToString('o'); Computer='TEST'; OS='Win11'; OSBuild=26100
    RealTimeProtectionEnabled=$true; AntivirusEnabled=$true; AntispywareEnabled=$true
    BehaviorMonitorEnabled=$true; NISEnabled=$true; OnAccessProtectionEnabled=$true
    AMServiceEnabled=$true; IsTamperProtected=$false
    WinDefendStatus='Running'; WinDefendStartType='Automatic'; PolicyDisableAntiSpyware=$null
    DefenderEffectivelyEnabled=$true
}

$disabled = @{
    Version='3.3.3'; Timestamp=(Get-Date).ToString('o'); Computer='TEST'; OS='Win11'; OSBuild=26100
    RealTimeProtectionEnabled=$false; AntivirusEnabled=$false; AntispywareEnabled=$false
    WinDefendStatus='Stopped'; WinDefendStartType='Disabled'; PolicyDisableAntiSpyware=1
    IsTamperProtected=$false; DefenderEffectivelyEnabled=$false
}

Assert-ExitCode (Invoke-VerifyIsolated -FakeState $enabled -Expect 'Enabled' -WantJson $false) 0 'Enabled + Expect Enabled'
Assert-ExitCode (Invoke-VerifyIsolated -FakeState $enabled -Expect 'Disabled' -WantJson $false) 5 'Enabled + Expect Disabled'
Assert-ExitCode (Invoke-VerifyIsolated -FakeState $disabled -Expect 'Disabled' -WantJson $false) 0 'Disabled + Expect Disabled'

$tamper = $enabled.Clone()
$tamper.IsTamperProtected = $true
Assert-ExitCode (Invoke-VerifyIsolated -FakeState $tamper -Expect 'Enabled' -WantJson $false) 2 'TamperProtected'

$jsonResult = Invoke-VerifyIsolated -FakeState $enabled -Expect 'Enabled' -WantJson $true
Assert-ExitCode $jsonResult 0 'JSON shape exit'
try {
    $parsed = $jsonResult.Output | ConvertFrom-Json
    if (-not $parsed.checks -or $parsed.overall -ne 'PASS') {
        Write-Host '[FAIL] JSON shape content'
        $script:failures++
    } else {
        Write-Host "[PASS] JSON shape content checks=$($parsed.checks.Count)"
    }
} catch {
    Write-Host "[FAIL] JSON parse: $($_.Exception.Message)"
    Write-Host $jsonResult.Output
    $script:failures++
}

if ($failures -gt 0) {
    Write-Error "$failures verify harness assertion(s) failed"
    exit 1
}

Write-Host 'Verify harness: OK'
