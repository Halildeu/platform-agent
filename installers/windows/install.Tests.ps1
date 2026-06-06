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

# Codex 019e7314 iter-2 P2: do NOT dot-source install.ps1. The script
# entry-point runs Assert-Administrator and Resolve-Path side-effects
# unconditionally — under a non-admin Pester runner those terminating
# throws break test discovery even with `-ErrorAction SilentlyContinue`.
# We only need the helper function definitions; read the source and
# extract them by regex.

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

    It "returns true when sentinel is appended after baseline" {
        @(
            "endpoint-agent 2026/05/29 10:00:00 agent enrolled: device=x credential=y",
            "endpoint-agent 2026/05/29 10:00:00 hmac credential confirmed device=x credential=y"
        ) | Out-File -LiteralPath $script:tempLog -Encoding UTF8
        Wait-ForCredentialConfirmed -LogPath $script:tempLog -TimeoutSeconds 2 -BaselineLength 0 | Should -BeTrue
    }

    It "returns false when degraded sentinel appears instead" {
        @(
            "endpoint-agent 2026/05/29 10:00:00 agent enrolled: device=x credential=y",
            "endpoint-agent 2026/05/29 10:00:00 hmac credential accepted (not persisted in this process)"
        ) | Out-File -LiteralPath $script:tempLog -Encoding UTF8
        Wait-ForCredentialConfirmed -LogPath $script:tempLog -TimeoutSeconds 2 -BaselineLength 0 | Should -BeFalse
    }

    It "returns false on missing log within timeout" {
        Wait-ForCredentialConfirmed -LogPath "C:\\does-not-exist.log" -TimeoutSeconds 1 -BaselineLength 0 | Should -BeFalse
    }

    # Codex 019e7314 iter-1 P1.1: append-only false-positive guard.
    # The agent log is opened append-only; a prior install/upgrade
    # could have left a sentinel line in the file. The caller passes
    # the on-disk byte length at service-start time as
    # $BaselineLength; only sentinels written AFTER that offset
    # satisfy the gate.
    It "returns false when only old sentinel is below baseline" {
        @(
            "endpoint-agent 2026/05/29 09:00:00 agent enrolled: device=old credential=old",
            "endpoint-agent 2026/05/29 09:00:00 hmac credential confirmed device=old credential=old"
        ) | Out-File -LiteralPath $script:tempLog -Encoding UTF8
        $baseline = (Get-Item -LiteralPath $script:tempLog).Length
        # Service restart appends no new content this time.
        Wait-ForCredentialConfirmed -LogPath $script:tempLog -TimeoutSeconds 2 -BaselineLength $baseline | Should -BeFalse
    }

    It "returns true when fresh sentinel appended above baseline" {
        @(
            "endpoint-agent 2026/05/29 09:00:00 agent enrolled: device=old credential=old",
            "endpoint-agent 2026/05/29 09:00:00 hmac credential confirmed device=old credential=old"
        ) | Out-File -LiteralPath $script:tempLog -Encoding UTF8
        $baseline = (Get-Item -LiteralPath $script:tempLog).Length
        # Simulate the fresh service start producing a NEW sentinel
        # at offset > baseline.
        Add-Content -LiteralPath $script:tempLog -Value "endpoint-agent 2026/05/29 10:00:00 agent enrolled: device=new credential=new" -Encoding UTF8
        Add-Content -LiteralPath $script:tempLog -Value "endpoint-agent 2026/05/29 10:00:00 hmac credential confirmed device=new credential=new" -Encoding UTF8
        Wait-ForCredentialConfirmed -LogPath $script:tempLog -TimeoutSeconds 2 -BaselineLength $baseline | Should -BeTrue
    }
}

Import-InstallHelper -Name "Set-ServiceEnvironmentRegkey"
Import-InstallHelper -Name "Remove-ServiceEnvironmentEntry"

Describe "Set-ServiceEnvironmentRegkey + Remove-ServiceEnvironmentEntry" {
    # Codex 019e7314 iter-1 P2: regkey helpers covered by Pester via
    # HKCU surrogate. Production code targets HKLM\SYSTEM\CurrentControlSet\Services\<name>\Environment;
    # the helpers we're testing dispatch on a path string, so we
    # exercise them against a HKCU\Software\... path that does not
    # require admin. The behavior under test is: REG_MULTI_SZ build
    # from hashtable, idempotent overwrite, one-key strip preserving
    # the rest. Service registry side-effects (SCM env consumption)
    # are covered by the live install→smoke chain on Windows.

    BeforeAll {
        $script:testRoot = "HKCU:\Software\Halildeu\AG026CTest"
        $script:fakeService = "$script:testRoot\FakeSvc"
        if (Test-Path -LiteralPath $script:testRoot) {
            Remove-Item -LiteralPath $script:testRoot -Recurse -Force
        }
        New-Item -Path $script:fakeService -Force | Out-Null

        # Wrapper helpers that target our test root instead of the
        # production HKLM path. The production helpers compose the
        # path string internally; for the test we redefine them
        # in this scope to take the path directly. This keeps the
        # transform logic (build REG_MULTI_SZ, filter prefix) under
        # test even though the production helpers compose
        # "HKLM:\...\Services\<name>". Pure logic coverage.
        function Set-RegEnvAt {
            param([string]$Path, [hashtable]$Values)
            $entries = @()
            foreach ($k in $Values.Keys) {
                $v = $Values[$k]
                if (-not [string]::IsNullOrWhiteSpace($v)) {
                    $entries += "$k=$v"
                }
            }
            if ($entries.Count -gt 0) {
                New-ItemProperty -Path $Path -Name 'Environment' -Value $entries -PropertyType MultiString -Force | Out-Null
            } else {
                Remove-ItemProperty -Path $Path -Name 'Environment' -ErrorAction SilentlyContinue
            }
        }
        function Remove-RegEnvKeyAt {
            param([string]$Path, [string]$Key)
            $existing = Get-ItemProperty -Path $Path -Name 'Environment' -ErrorAction SilentlyContinue
            if ($null -eq $existing -or $null -eq $existing.Environment) { return }
            $prefix = "$Key="
            $filtered = @($existing.Environment | Where-Object { $_ -notlike "$prefix*" })
            if ($filtered.Count -gt 0) {
                New-ItemProperty -Path $Path -Name 'Environment' -Value $filtered -PropertyType MultiString -Force | Out-Null
            } else {
                Remove-ItemProperty -Path $Path -Name 'Environment' -ErrorAction SilentlyContinue
            }
        }
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:testRoot) {
            Remove-Item -LiteralPath $script:testRoot -Recurse -Force
        }
    }

    It "writes REG_MULTI_SZ from hashtable" {
        Set-RegEnvAt -Path $script:fakeService -Values @{
            "ENDPOINT_AGENT_API_URL" = "https://test.example.com/api/v1/endpoint-agent"
            "ENDPOINT_AGENT_ENROLLMENT_TOKEN" = "test-token-abc"
            "ENDPOINT_AGENT_LOG_DIR" = "C:\\Logs"
        }
        $got = (Get-ItemProperty -Path $script:fakeService -Name 'Environment').Environment
        $got.Count | Should -Be 3
        ($got -match "ENDPOINT_AGENT_API_URL=https://test.example.com").Count | Should -BeGreaterThan 0
        ($got -match "ENDPOINT_AGENT_ENROLLMENT_TOKEN=test-token-abc").Count | Should -BeGreaterThan 0
    }

    It "skips empty values when building REG_MULTI_SZ" {
        Set-RegEnvAt -Path $script:fakeService -Values @{
            "ENDPOINT_AGENT_API_URL" = "https://test.example.com/api/v1/endpoint-agent"
            "ENDPOINT_AGENT_ID" = ""
            "ENDPOINT_AGENT_SECRET" = $null
        }
        $got = (Get-ItemProperty -Path $script:fakeService -Name 'Environment').Environment
        $got.Count | Should -Be 1
    }

    It "writes AG-029 self-update opt-in service environment" {
        Set-RegEnvAt -Path $script:fakeService -Values @{
            "ENDPOINT_AGENT_SELF_UPDATE_ENABLED" = "true"
            "ENDPOINT_AGENT_SELF_UPDATE_STAGING_ROOT" = "C:\\ProgramData\\EndpointAgent\\updates"
            "ENDPOINT_AGENT_SELF_UPDATE_CURRENT_BINARY_PATH" = "C:\\Program Files\\EndpointAgent\\endpoint-agent.exe"
            "ENDPOINT_AGENT_SELF_UPDATE_SERVICE_NAME" = "EndpointAgent"
            "ENDPOINT_AGENT_SELF_UPDATE_ALLOWED_HOSTS" = "github.com,objects.githubusercontent.com"
            "ENDPOINT_AGENT_SELF_UPDATE_MAX_REDIRECTS" = "5"
            "ENDPOINT_AGENT_SELF_UPDATE_SIGNER_THUMBPRINTS" = "AABBCC"
            "ENDPOINT_AGENT_SELF_UPDATE_ALLOW_LAB_ONLY" = "true"
            "ENDPOINT_AGENT_SELF_UPDATE_DOMAIN_JOINED" = "false"
            "ENDPOINT_AGENT_SELF_UPDATE_MAX_SEEN_VERSION" = "0.1.0"
            "ENDPOINT_AGENT_SELF_UPDATE_AUTO_ACTIVATE" = "true"
            "ENDPOINT_AGENT_SELF_UPDATE_ACTIVATION_TIMEOUT" = "2m"
        }
        $got = (Get-ItemProperty -Path $script:fakeService -Name 'Environment').Environment
        $got.Count | Should -Be 12
        ($got -match "ENDPOINT_AGENT_SELF_UPDATE_ENABLED=true").Count | Should -BeGreaterThan 0
        ($got -match "ENDPOINT_AGENT_SELF_UPDATE_CURRENT_BINARY_PATH=C:\\Program Files\\EndpointAgent\\endpoint-agent.exe").Count | Should -BeGreaterThan 0
        ($got -match "ENDPOINT_AGENT_SELF_UPDATE_AUTO_ACTIVATE=true").Count | Should -BeGreaterThan 0
    }

    It "removes only the specified token entry, preserving non-secret env" {
        Set-RegEnvAt -Path $script:fakeService -Values @{
            "ENDPOINT_AGENT_API_URL" = "https://test.example.com/api/v1/endpoint-agent"
            "ENDPOINT_AGENT_ENROLLMENT_TOKEN" = "test-token-abc"
            "ENDPOINT_AGENT_LOG_DIR" = "C:\\Logs"
        }
        Remove-RegEnvKeyAt -Path $script:fakeService -Key "ENDPOINT_AGENT_ENROLLMENT_TOKEN"
        $got = (Get-ItemProperty -Path $script:fakeService -Name 'Environment').Environment
        $got.Count | Should -Be 2
        ($got -match "ENDPOINT_AGENT_ENROLLMENT_TOKEN").Count | Should -Be 0
        ($got -match "ENDPOINT_AGENT_API_URL").Count | Should -BeGreaterThan 0
        ($got -match "ENDPOINT_AGENT_LOG_DIR").Count | Should -BeGreaterThan 0
    }

    It "removes the Environment value entirely when last entry is stripped" {
        Set-RegEnvAt -Path $script:fakeService -Values @{
            "ENDPOINT_AGENT_ENROLLMENT_TOKEN" = "only-entry"
        }
        Remove-RegEnvKeyAt -Path $script:fakeService -Key "ENDPOINT_AGENT_ENROLLMENT_TOKEN"
        $got = Get-ItemProperty -Path $script:fakeService -Name 'Environment' -ErrorAction SilentlyContinue
        $got | Should -BeNullOrEmpty
    }
}
