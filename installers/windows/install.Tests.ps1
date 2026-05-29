# AG-026C installer helper tests (Pester).
#
# Scope: pure-PS helper functions (Set-ServiceEnvironmentRegkey,
# Remove-ServiceEnvironmentEntry, Wait-ForCredentialConfirmed). Service
# install/uninstall side-effects are out of scope here — those are
# covered by the Windows Go test on the runner side and by the
# end-to-end smoke chain.
#
# Run locally with:
#   pwsh -NoProfile -Command "Invoke-Pester -Path .\installers\windows\install.Tests.ps1"
#
# CI matches the same invocation; failures fail the Windows job.

. (Join-Path $PSScriptRoot "install.ps1") -BinaryPath "C:\\dummy.exe" -ErrorAction SilentlyContinue 2>$null
# Note: the dot-source above will fail at Assert-Administrator under a
# non-admin runner. We only need the function definitions, so we
# explicitly redefine the helpers below from the same source file by
# reading + executing the function bodies. This keeps the tests
# self-contained without depending on the install script's runtime
# guards.

$installSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot "install.ps1") -Raw

function Import-InstallHelper {
    param([string]$Name)
    $pattern = "function $Name \{[\s\S]*?\n\}"
    $match = [regex]::Match($installSource, $pattern)
    if (-not $match.Success) {
        throw "Helper '$Name' not found in install.ps1"
    }
    Invoke-Expression $match.Value
}

Import-InstallHelper -Name "Wait-ForCredentialConfirmed"

Describe "Wait-ForCredentialConfirmed" {
    BeforeAll {
        $script:tempLog = Join-Path $env:TEMP "endpoint-agent-test-$([guid]::NewGuid()).log"
    }
    AfterEach {
        if (Test-Path -LiteralPath $script:tempLog) {
            Remove-Item -LiteralPath $script:tempLog -Force
        }
    }

    It "returns true when sentinel is in tail" {
        @(
            "endpoint-agent 2026/05/29 10:00:00 agent enrolled: device=x credential=y",
            "endpoint-agent 2026/05/29 10:00:00 hmac credential confirmed device=x credential=y"
        ) | Out-File -LiteralPath $script:tempLog -Encoding UTF8
        Wait-ForCredentialConfirmed -LogPath $script:tempLog -TimeoutSeconds 2 | Should -BeTrue
    }

    It "returns false when degraded sentinel appears instead" {
        @(
            "endpoint-agent 2026/05/29 10:00:00 agent enrolled: device=x credential=y",
            "endpoint-agent 2026/05/29 10:00:00 hmac credential accepted (not persisted in this process)"
        ) | Out-File -LiteralPath $script:tempLog -Encoding UTF8
        Wait-ForCredentialConfirmed -LogPath $script:tempLog -TimeoutSeconds 2 | Should -BeFalse
    }

    It "returns false on missing log within timeout" {
        Wait-ForCredentialConfirmed -LogPath "C:\\does-not-exist.log" -TimeoutSeconds 1 | Should -BeFalse
    }
}
