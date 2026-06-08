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
    "installers\windows\install.Tests.ps1"
)

foreach ($relativePath in $parseTargets) {
    $path = Join-Path $repoRoot $relativePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing PowerShell test target: $relativePath"
    }

    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$errors
    ) | Out-Null

    if ($errors -and $errors.Count -gt 0) {
        Write-Host "Parser errors in ${relativePath}:"
        foreach ($parseError in $errors) {
            Write-Host "  line=$($parseError.Extent.StartLineNumber) column=$($parseError.Extent.StartColumnNumber) error=$($parseError.Message)"
        }
        throw "PowerShell 5.1 parser rejected $relativePath"
    }

    Write-Host "Parse OK: $relativePath"
}

$pester = Get-Module -ListAvailable Pester |
    Where-Object { $_.Version.Major -eq 3 -or $_.Version.Major -eq 4 } |
    Sort-Object Version -Descending |
    Select-Object -First 1

if (-not $pester) {
    throw "Pester 3.x/4.x is not available on the Windows runner; installer helper tests use legacy Should syntax."
}

Write-Host "Using Pester $($pester.Version) from $($pester.Path)"
Import-Module $pester.Path -Force

$result = Invoke-Pester -Path (Join-Path $repoRoot "installers\windows\install.Tests.ps1") -PassThru

$failedCount = 0
if ($null -ne $result) {
    if ($result.PSObject.Properties.Name -contains "FailedCount") {
        $failedCount = [int]$result.FailedCount
    } elseif ($result.PSObject.Properties.Name -contains "Failed") {
        $failedCount = [int]$result.Failed
    }
}

if ($failedCount -gt 0) {
    throw "Installer Pester tests failed: $failedCount"
}

Write-Host "Windows PowerShell 5.1 installer gate PASS"
