[CmdletBinding()]
param(
    [switch]$ParseOnly
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$mainScript = Join-Path $repoRoot 'DefenderControl.ps1'

function Get-ParsedSource {
    param([Parameter(Mandatory)][string]$Path)

    $source = Get-Content -Raw -LiteralPath $Path
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $source, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        throw ("{0}: {1}" -f $Path, (($errors | Select-Object -First 1).Message))
    }
    return $ast
}

if ($ParseOnly.IsPresent) {
    $null = Get-ParsedSource -Path $mainScript
    Write-Host 'WinPS parser: OK'
    exit 0
}

$script:Failures = 0

function Write-Check {
    param([string]$Message)
    Write-Host ("`n== {0} ==" -f $Message)
}

function Assert-Check {
    param([bool]$Condition, [string]$Label)
    if ($Condition) {
        Write-Host ("[PASS] {0}" -f $Label)
    } else {
        Write-Host ("[FAIL] {0}" -f $Label)
        $script:Failures++
    }
}

function Invoke-ChildScript {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Arguments = @()
    )

    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = $stdoutPath + '.err'
    try {
        $childArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Path) + $Arguments
        $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $childArgs `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        if ($process.ExitCode -eq 0) {
            Write-Host ("[PASS] {0}" -f $Label)
            return
        }

        Write-Host ("[FAIL] {0} exit={1}" -f $Label, $process.ExitCode)
        $childOutput = Get-Content -Raw -LiteralPath $stdoutPath -ErrorAction SilentlyContinue
        $childError = Get-Content -Raw -LiteralPath $stderrPath -ErrorAction SilentlyContinue
        if ($childOutput) { Write-Host (($childOutput -split "`r?`n" | Select-Object -Last 40) -join "`n") }
        if ($childError) { Write-Host (($childError -split "`r?`n" | Select-Object -Last 40) -join "`n") }
        $script:Failures++
    } catch {
        Write-Host ("[FAIL] {0}: {1}" -f $Label, $_.Exception.Message)
        $script:Failures++
    } finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

Write-Check 'Parse checks'
$mainAst = Get-ParsedSource -Path $mainScript
Assert-Check ($null -ne $mainAst) 'PowerShell parser accepts DefenderControl.ps1'
Invoke-ChildScript -Label 'Windows PowerShell 5.1 parser accepts DefenderControl.ps1' `
    -Path $PSCommandPath -Arguments @('-ParseOnly')

$mainSource = Get-Content -Raw -LiteralPath $mainScript
$xamlMatch = [regex]::Match($mainSource, '(?s)\[xml\]\$xaml = @"(.*?)"@')
Assert-Check $xamlMatch.Success 'XAML here-string found'
if ($xamlMatch.Success) {
    try {
        $xamlXml = [xml]$xamlMatch.Groups[1].Value
        Assert-Check ($null -ne $xamlXml.DocumentElement) 'XAML is well-formed XML'
        if (Get-Command Add-Type -ErrorAction SilentlyContinue) {
            try {
                Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
                $xamlReader = New-Object System.Xml.XmlNodeReader $xamlXml
                $null = [Windows.Markup.XamlReader]::Load($xamlReader)
                Assert-Check $true 'WPF XAML loader accepts accessibility metadata'
            } catch {
                Assert-Check $false ("WPF XAML loader accepts accessibility metadata: {0}" -f $_.Exception.Message)
            }
        }
        $automationCount = ([regex]::Matches($xamlMatch.Groups[1].Value, 'AutomationProperties\.')).Count
        Assert-Check ($automationCount -ge 30) ("XAML exposes broad AutomationProperties metadata ({0} attributes)" -f $automationCount)
    } catch {
        Assert-Check $false ("XAML XML parse: {0}" -f $_.Exception.Message)
    }
}

Write-Check 'SharedFunctions extraction and parity'
$assignments = @($mainAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -eq '$script:SharedFunctions'
    }, $true))
$sharedAssignment = @($assignments | Where-Object { $_.Operator -eq 'Equals' } | Select-Object -First 1)
$supportAppend = @($assignments | Where-Object { $_.Operator -eq 'PlusEquals' } | Select-Object -First 1)
Assert-Check ($null -ne $sharedAssignment) 'SharedFunctions base here-string found'
Assert-Check ($null -ne $supportAppend) 'Support bundle injection assignment found'

$supportFunction = @($mainAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'New-DefenderControlSupportBundle'
    }, $true) | Select-Object -First 1)
Assert-Check ($null -ne $supportFunction) 'Support bundle writer definition found'
if ($supportFunction -and $sharedAssignment -and $supportAppend) {
    $null = Invoke-Expression $supportFunction.Extent.Text
    $null = Invoke-Expression $sharedAssignment.Extent.Text
    $null = Invoke-Expression $supportAppend.Extent.Text

    $sharedTokens = $null
    $sharedErrors = $null
    $sharedAst = [System.Management.Automation.Language.Parser]::ParseInput(
        $script:SharedFunctions, [ref]$sharedTokens, [ref]$sharedErrors)
    if ($sharedErrors -and $sharedErrors.Count -gt 0) {
        throw ("SharedFunctions parse failed: {0}" -f (($sharedErrors | Select-Object -First 1).Message))
    }

    $sharedNames = @($sharedAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true) | ForEach-Object { $_.Name } | Sort-Object -Unique)
    $requiredSharedFunctions = @(
        'Queue-Log', 'Queue-Success', 'Queue-Warn', 'Queue-Err', 'Queue-Info',
        'Queue-Verbose', 'Queue-Phase', 'Queue-Status', 'Queue-Dashboard',
        'Get-DefenderEndpointState', 'Get-TxField', 'Get-RegValueSnapshot',
        'Convert-ProviderPathToLocalMachineKey', 'Restore-RegValueForReplay',
        'Invoke-UndoTransactionReplay', 'Set-RegValue', 'Remove-RegValue',
        'Set-ProtectedRegValue', 'Set-ServiceStart', 'Set-ServicePPL',
        'Get-FirewallSnapshot', 'Test-FirewallIntact', 'Get-ThirdPartyAVList',
        'New-DefenderControlManifest', 'Save-DefenderControlManifest',
        'Write-DefenderControlEvent', 'New-DefenderControlSupportBundle'
    )
    $missingFunctions = @($requiredSharedFunctions | Where-Object { $_ -notin $sharedNames })
    Assert-Check ($missingFunctions.Count -eq 0) 'SharedFunctions contains every runspace helper' 
    if ($missingFunctions.Count -gt 0) {
        Write-Host ("Missing shared functions: {0}" -f ($missingFunctions -join ', '))
    }
    Assert-Check (($sharedNames | Group-Object | Where-Object Count -gt 1).Count -eq 0) `
        'SharedFunctions contains no duplicate function definitions'
    Write-Host ("SharedFunctions parity: {0} functions parsed" -f $sharedNames.Count)
}

Write-Check 'State, verify, transaction, and support tests'
foreach ($testName in @('test-state.ps1', 'test-verify.ps1', 'test-undo-replay.ps1', 'test-support-bundle.ps1', 'test-manifest-controls.ps1')) {
    $testPath = Join-Path $PSScriptRoot $testName
    if (-not (Test-Path -LiteralPath $testPath)) {
        Write-Host ("[FAIL] Missing validation script: {0}" -f $testName)
        $script:Failures++
        continue
    }
    Invoke-ChildScript -Label $testName -Path $testPath
}

Write-Check 'PSScriptAnalyzer baseline'
$analyzer = Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue
if (-not $analyzer) {
    Write-Host '[FAIL] Invoke-ScriptAnalyzer is not installed'
    $script:Failures++
} else {
    # These are documented baseline suppressions for the legacy single-file GUI.
    # Any new rule is intentionally unsuppressed and fails this harness.
    $baselineSuppressions = @{
        PSAvoidUsingEmptyCatchBlock = 'Best-effort event/log/cleanup paths.'
        PSAvoidUsingPositionalParameters = 'Existing Windows cmdlet compatibility calls.'
        PSReviewUnusedParameter = 'Public callback and compatibility signatures.'
        PSUseApprovedVerbs = 'Existing GUI and registry helper names.'
        PSUseBOMForUnicodeEncodedFile = 'Legacy single-file distribution encoding.'
        PSUseDeclaredVarsMoreThanAssignments = 'WPF event and compatibility variables.'
        PSUseOutputTypeCorrectly = 'Mixed GUI/CLI helper return shapes.'
        PSUseShouldProcessForStateChangingFunctions = 'GUI operations intentionally mutate state.'
        PSUseSingularNouns = 'Existing compatibility noun in a public helper.'
    }
    $findings = @(Invoke-ScriptAnalyzer -Path $mainScript -Severity Error,Warning,Information)
    $unexpected = @($findings | Where-Object { $_.RuleName -notin $baselineSuppressions.Keys })
    foreach ($rule in ($findings | Group-Object RuleName | Sort-Object Name)) {
        $reason = if ($baselineSuppressions.ContainsKey($rule.Name)) { $baselineSuppressions[$rule.Name] } else { 'NOT SUPPRESSED' }
        Write-Host ("{0}: {1} ({2})" -f $rule.Name, $rule.Count, $reason)
    }
    if ($unexpected.Count -gt 0) {
        foreach ($finding in $unexpected) {
            Write-Host ("[FAIL] {0}:{1} {2}" -f $finding.Line, $finding.Column, $finding.RuleName)
        }
        $script:Failures += $unexpected.Count
    } else {
        Write-Host ("[PASS] PSScriptAnalyzer findings are limited to {0} documented baseline rules" -f $baselineSuppressions.Count)
    }
}

if ($script:Failures -gt 0) {
    Write-Error ("Validation harness failed with {0} failure(s)." -f $script:Failures)
    exit 1
}

Write-Host "`nValidation harness: OK"
exit 0
