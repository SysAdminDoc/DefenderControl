# Isolated test harness for Get-DefenderState without triggering self-elevation
# Runs only the state-query function after stubbing the script-scope vars it expects.

$script:Version  = '3.3.2'
$script:OSBuild  = [System.Environment]::OSVersion.Version.Build
$script:OSName   = if ($script:OSBuild -ge 22000) { "Windows 11" } elseif ($script:OSBuild -ge 10240) { "Windows 10" } else { "Unknown" }
$script:OSDetail = "$script:OSName (Build $script:OSBuild)"

# Read the script and extract the function definitions we need.
$src = Get-Content -Raw (Join-Path $PSScriptRoot '..\DefenderControl.ps1')

$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errs)
if ($errs -and $errs.Count -gt 0) {
    $errs | ForEach-Object { Write-Error $_.Message }
    exit 1
}

$funcs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -in @('Get-DefenderState') }, $true)

foreach ($f in $funcs) {
    Invoke-Expression $f.Extent.Text
}

Write-Host '== Get-DefenderState (basic) =='
$basic = Get-DefenderState
$basic | Format-List

Write-Host ''
Write-Host '== Get-DefenderState -Extended (JSON) =='
$ext = Get-DefenderState -Extended
$json = $ext | ConvertTo-Json -Depth 6
# Validate round-trip parse
$null = $json | ConvertFrom-Json
Write-Host 'JSON round-trip: OK'
Write-Host ('JSON length: ' + $json.Length + ' chars')
Write-Host ('Keys: ' + ($ext.Keys -join ', '))
