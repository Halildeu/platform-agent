$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")
Set-Location $repoRoot

if ($PSVersionTable.PSVersion.Major -ne 5) {
    throw "This gate must run under Windows PowerShell 5.1 via powershell.exe; got $($PSVersionTable.PSVersion)."
}

Write-Host "Windows PowerShell version: $($PSVersionTable.PSVersion)"

$parseTargets = @(
    "installers\windows\bootstrap-package.ps1",
    "installers\windows\install.ps1",
    "installers\windows\uninstall.ps1",
    "installers\windows\bootstrap-package.Tests.ps1",
    "installers\windows\install.Tests.ps1"
)
$parsedAsts = @{}

foreach ($relativePath in $parseTargets) {
    $path = Join-Path $repoRoot $relativePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing PowerShell test target: $relativePath"
    }

    $tokens = $null
    $errors = $null
    $parsedAsts[$relativePath] = [System.Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$errors
    )

    if ($errors -and $errors.Count -gt 0) {
        Write-Host "Parser errors in ${relativePath}:"
        foreach ($parseError in $errors) {
            Write-Host "  line=$($parseError.Extent.StartLineNumber) column=$($parseError.Extent.StartColumnNumber) error=$($parseError.Message)"
        }
        throw "PowerShell 5.1 parser rejected $relativePath"
    }

    Write-Host "Parse OK: $relativePath"
}

$installAst = $parsedAsts["installers\windows\install.ps1"]
# This static guard covers literal command and string forms. Dynamic command
# construction is not an accepted installer pattern and remains review-gated.
$unblockReferences = @($installAst.FindAll({
    param($node)
    ($node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq "Unblock-File") -or
    ($node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $node.Value -eq "Unblock-File")
}, $true))
if ($unblockReferences.Count -ne 0) {
    throw "install.ps1 must preserve Mark-of-the-Web; found $($unblockReferences.Count) Unblock-File reference(s)."
}
Write-Host "Installer Mark-of-the-Web preservation guard PASS"

$pester = Get-Module -ListAvailable Pester |
    Where-Object { $_.Version.Major -eq 3 -or $_.Version.Major -eq 4 } |
    Sort-Object Version -Descending |
    Select-Object -First 1

if (-not $pester) {
    throw "Pester 3.x/4.x is not available on the Windows runner; installer helper tests use legacy Should syntax."
}

Write-Host "Using Pester $($pester.Version) from $($pester.Path)"
Import-Module $pester.Path -Force

$failedCount = 0
$pesterTargets = @(
    "installers\windows\bootstrap-package.Tests.ps1",
    "installers\windows\install.Tests.ps1"
)

foreach ($relativeTestPath in $pesterTargets) {
    $result = Invoke-Pester -Path (Join-Path $repoRoot $relativeTestPath) -PassThru

    if ($null -ne $result) {
        if ($result.PSObject.Properties.Name -contains "FailedCount") {
            $failedCount += [int]$result.FailedCount
        } elseif ($result.PSObject.Properties.Name -contains "Failed") {
            $failedCount += [int]$result.Failed
        }
    }
}

if ($failedCount -gt 0) {
    throw "Installer Pester tests failed: $failedCount"
}

Write-Host "Windows PowerShell 5.1 installer gate PASS"
