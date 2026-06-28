# Isolated tests for transaction metadata and undo replay.
# Uses HKCU test keys only; does not touch Defender or HKLM service state.

$ErrorActionPreference = 'Stop'

$repoScript = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\DefenderControl.ps1')).ProviderPath
$src = Get-Content -Raw -LiteralPath $repoScript
$tokens = $null
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errs)
if ($errs -and $errs.Count -gt 0) {
    $errs | ForEach-Object { Write-Error $_.Message }
    exit 1
}

$assignment = $ast.Find({
    param($n)
    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -eq '$script:SharedFunctions'
}, $true)

if (-not $assignment) {
    Write-Error 'Could not find SharedFunctions assignment'
    exit 1
}

Invoke-Expression $assignment.Extent.Text

$LogQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
$StatusQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
$DashQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
$TxLog = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
$DryRun = $false

Invoke-Expression $script:SharedFunctions

$testKey = "HKCU:\Software\DefenderControlUndoReplayTest_$([Guid]::NewGuid().ToString('N'))"
$failures = 0

function Assert-True {
    param([bool]$Condition, [string]$Label)
    if ($Condition) {
        Write-Host "[PASS] $Label"
    } else {
        Write-Host "[FAIL] $Label"
        $script:failures++
    }
}

try {
    New-Item -Path $testKey -Force | Out-Null
    New-ItemProperty -LiteralPath $testKey -Name 'ExistingDword' -Value 5 -PropertyType DWord -Force | Out-Null

    Assert-True (Set-RegValue -Path $testKey -Name 'ExistingDword' -Value 42 -Type 'DWord') 'set existing dword'
    Assert-True (Remove-RegValue -Path $testKey -Name 'ExistingDword') 'remove existing dword'
    Assert-True (Set-RegValue -Path $testKey -Name 'NewString' -Value 'created-by-test' -Type 'String') 'set new string'

    $entries = [System.Collections.ArrayList]::new()
    $entry = $null
    while ($TxLog.TryDequeue([ref]$entry)) { $entries.Add($entry) | Out-Null }

    Assert-True ($entries.Count -eq 3) 'transaction count'
    Assert-True ([bool]$entries[0].BeforeExists -eq $true -and $entries[0].Before -eq 5 -and $entries[0].BeforeType -eq 'DWord') 'set records prior dword'
    Assert-True ([bool]$entries[2].BeforeExists -eq $false -and $entries[2].AfterType -eq 'String') 'new value records prior absence'

    $summary = Invoke-UndoTransactionReplay -TransactionLog @($entries)
    Assert-True ($summary.restored -eq 2 -and $summary.removed -eq 1 -and $summary.failed -eq 0) 'replay summary'

    $snapshotExisting = Get-RegValueSnapshot -Path $testKey -Name 'ExistingDword'
    $snapshotNew = Get-RegValueSnapshot -Path $testKey -Name 'NewString'
    Assert-True ($snapshotExisting.Exists -and $snapshotExisting.Value -eq 5 -and $snapshotExisting.Type -eq 'DWord') 'existing dword restored'
    Assert-True (-not $snapshotNew.Exists) 'new string removed'
} finally {
    Remove-Item -LiteralPath $testKey -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures -gt 0) {
    Write-Error "$failures undo replay assertion(s) failed"
    exit 1
}

Write-Host 'Undo replay harness: OK'
