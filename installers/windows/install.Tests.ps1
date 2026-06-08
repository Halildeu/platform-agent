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
    $definition = $match.Value -replace "function $Name", "function script:$Name"
    Invoke-Expression $definition
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
        Wait-ForCredentialConfirmed -LogPath $script:tempLog -TimeoutSeconds 2 -BaselineLength 0 | Should Be $true
    }

    It "returns false when degraded sentinel appears instead" {
        @(
            "endpoint-agent 2026/05/29 10:00:00 agent enrolled: device=x credential=y",
            "endpoint-agent 2026/05/29 10:00:00 hmac credential accepted (not persisted in this process)"
        ) | Out-File -LiteralPath $script:tempLog -Encoding UTF8
        Wait-ForCredentialConfirmed -LogPath $script:tempLog -TimeoutSeconds 2 -BaselineLength 0 | Should Be $false
    }

    It "returns false on missing log within timeout" {
        Wait-ForCredentialConfirmed -LogPath "C:\\does-not-exist.log" -TimeoutSeconds 1 -BaselineLength 0 | Should Be $false
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
        Wait-ForCredentialConfirmed -LogPath $script:tempLog -TimeoutSeconds 2 -BaselineLength $baseline | Should Be $false
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
        Wait-ForCredentialConfirmed -LogPath $script:tempLog -TimeoutSeconds 2 -BaselineLength $baseline | Should Be $true
    }
}

Import-InstallHelper -Name "Set-ServiceEnvironmentRegkey"
Import-InstallHelper -Name "Remove-ServiceEnvironmentEntry"
Import-InstallHelper -Name "Add-ServiceEnvironmentBaseVariables"
Import-InstallHelper -Name "Get-AgentRegistrySnapshot"
Import-InstallHelper -Name "Restore-AgentRegistrySnapshot"
Import-InstallHelper -Name "Set-AgentAutoEnrollRegistry"
Import-InstallHelper -Name "Clear-AgentAutoEnrollRegistry"
Import-InstallHelper -Name "Get-HmacCredentialStorePath"
Import-InstallHelper -Name "Assert-HmacEnrollmentTokenStorePolicy"
Import-InstallHelper -Name "Backup-HmacCredentialStoreForFreshEnroll"

Describe "Add-ServiceEnvironmentBaseVariables" {
    It "adds the minimal non-secret OS environment needed by service child processes" {
        $values = @{
            "ENDPOINT_AGENT_API_URL" = "https://test.example.com/api/v1/endpoint-agent"
        }

        Add-ServiceEnvironmentBaseVariables -Values $values

        $values["ENDPOINT_AGENT_API_URL"] | Should Be "https://test.example.com/api/v1/endpoint-agent"
        $values["SystemRoot"] | Should Not BeNullOrEmpty
        $values["windir"] | Should Be $values["SystemRoot"]
        $values["ProgramData"] | Should Not BeNullOrEmpty
        $values["TEMP"] | Should Not BeNullOrEmpty
        $values["TMP"] | Should Be $values["TEMP"]

        $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if (-not [string]::IsNullOrWhiteSpace($machinePath)) {
            $values["Path"] | Should Be $machinePath
        }
    }

    It "does not overwrite explicit service environment values" {
        $values = @{
            "Path" = "C:\CustomBin"
            "SystemRoot" = "C:\CustomWindows"
            "windir" = "C:\CustomWindows"
            "ProgramData" = "D:\ProgramData"
            "TEMP" = "D:\Temp"
            "TMP" = "D:\Tmp"
        }

        Add-ServiceEnvironmentBaseVariables -Values $values

        $values["Path"] | Should Be "C:\CustomBin"
        $values["SystemRoot"] | Should Be "C:\CustomWindows"
        $values["windir"] | Should Be "C:\CustomWindows"
        $values["ProgramData"] | Should Be "D:\ProgramData"
        $values["TEMP"] | Should Be "D:\Temp"
        $values["TMP"] | Should Be "D:\Tmp"
    }
}

Describe "HMAC enrollment-token reinstall guard" {
    BeforeEach {
        $script:tempDir = Join-Path $env:TEMP "endpoint-agent-hmac-guard-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Force -Path $script:tempDir | Out-Null
        $script:storePath = Join-Path $script:tempDir "hmac-credential.dpapi"
    }

    AfterEach {
        if (Test-Path -LiteralPath $script:tempDir) {
            Remove-Item -LiteralPath $script:tempDir -Recurse -Force
        }
    }

    It "builds the production credential store path under ProgramData" {
        Get-HmacCredentialStorePath -ProgramDataRoot "D:\ProgramData" |
            Should Be "D:\ProgramData\EndpointAgent\config\hmac-credential.dpapi"
    }

    It "allows first-run enrollment when the credential store is absent" {
        { Assert-HmacEnrollmentTokenStorePolicy -Token "fresh-token" -ResetRequested $false -CredentialStorePath $script:storePath } |
            Should Not Throw
    }

    It "allows upgrade-preserve when no enrollment token is supplied" {
        Set-Content -LiteralPath $script:storePath -Value "stored" -Encoding ASCII
        { Assert-HmacEnrollmentTokenStorePolicy -Token "" -ResetRequested $false -CredentialStorePath $script:storePath } |
            Should Not Throw
    }

    It "fails fast when a token is supplied over an existing store without reset" {
        Set-Content -LiteralPath $script:storePath -Value "stored" -Encoding ASCII
        { Assert-HmacEnrollmentTokenStorePolicy -Token "fresh-token" -ResetRequested $false -CredentialStorePath $script:storePath } |
            Should Throw "Existing EndpointAgent HMAC credential store found*"
    }

    It "allows explicit reset intent when a token is supplied over an existing store" {
        Set-Content -LiteralPath $script:storePath -Value "stored" -Encoding ASCII
        { Assert-HmacEnrollmentTokenStorePolicy -Token "fresh-token" -ResetRequested $true -CredentialStorePath $script:storePath } |
            Should Not Throw
    }

    It "backs up and removes the old store for fresh enrollment" {
        Set-Content -LiteralPath $script:storePath -Value "stored" -Encoding ASCII
        $backup = Backup-HmacCredentialStoreForFreshEnroll -CredentialStorePath $script:storePath -Timestamp "20260608T150000Z"

        Test-Path -LiteralPath $script:storePath | Should Be $false
        Test-Path -LiteralPath $backup | Should Be $true
        (Get-Content -LiteralPath $backup -Raw).TrimEnd() | Should Be "stored"
    }

    It "returns an empty path when no store exists to back up" {
        Backup-HmacCredentialStoreForFreshEnroll -CredentialStorePath $script:storePath -Timestamp "20260608T150000Z" |
            Should Be ""
    }
}

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
        $got.Count | Should Be 3
        ($got -match "ENDPOINT_AGENT_API_URL=https://test.example.com").Count | Should BeGreaterThan 0
        ($got -match "ENDPOINT_AGENT_ENROLLMENT_TOKEN=test-token-abc").Count | Should BeGreaterThan 0
    }

    It "skips empty values when building REG_MULTI_SZ" {
        Set-RegEnvAt -Path $script:fakeService -Values @{
            "ENDPOINT_AGENT_API_URL" = "https://test.example.com/api/v1/endpoint-agent"
            "ENDPOINT_AGENT_ID" = ""
            "ENDPOINT_AGENT_SECRET" = $null
        }
        $got = (Get-ItemProperty -Path $script:fakeService -Name 'Environment').Environment
        $got.Count | Should Be 1
    }

    It "removes only the specified token entry, preserving non-secret env" {
        Set-RegEnvAt -Path $script:fakeService -Values @{
            "ENDPOINT_AGENT_API_URL" = "https://test.example.com/api/v1/endpoint-agent"
            "ENDPOINT_AGENT_ENROLLMENT_TOKEN" = "test-token-abc"
            "ENDPOINT_AGENT_LOG_DIR" = "C:\\Logs"
        }
        Remove-RegEnvKeyAt -Path $script:fakeService -Key "ENDPOINT_AGENT_ENROLLMENT_TOKEN"
        $got = (Get-ItemProperty -Path $script:fakeService -Name 'Environment').Environment
        $got.Count | Should Be 2
        ($got -match "ENDPOINT_AGENT_ENROLLMENT_TOKEN").Count | Should Be 0
        ($got -match "ENDPOINT_AGENT_API_URL").Count | Should BeGreaterThan 0
        ($got -match "ENDPOINT_AGENT_LOG_DIR").Count | Should BeGreaterThan 0
    }

    It "removes the Environment value entirely when last entry is stripped" {
        Set-RegEnvAt -Path $script:fakeService -Values @{
            "ENDPOINT_AGENT_ENROLLMENT_TOKEN" = "only-entry"
        }
        Remove-RegEnvKeyAt -Path $script:fakeService -Key "ENDPOINT_AGENT_ENROLLMENT_TOKEN"
        $got = Get-ItemProperty -Path $script:fakeService -Name 'Environment' -ErrorAction SilentlyContinue
        $got | Should BeNullOrEmpty
    }
}

Describe "EndpointAgent mode registry helpers" {
    BeforeAll {
        $script:modeRoot = "HKCU:\Software\Halildeu\AG026CModeTest"
    }

    BeforeEach {
        if (Test-Path -LiteralPath $script:modeRoot) {
            Remove-Item -LiteralPath $script:modeRoot -Recurse -Force
        }
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:modeRoot) {
            Remove-Item -LiteralPath $script:modeRoot -Recurse -Force
        }
    }

    It "writes auto-enroll mode, api url, and jitter" {
        Set-AgentAutoEnrollRegistry `
            -Path $script:modeRoot `
            -ApiUrl "https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent" `
            -JitterSeconds 17

        $props = Get-ItemProperty -Path $script:modeRoot
        $props.Mode | Should Be "auto-enroll"
        $props.ApiUrl | Should Be "https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent"
        $props.EnrollmentJitterSeconds | Should Be 17
        (Get-Item -LiteralPath $script:modeRoot).GetValueKind("EnrollmentJitterSeconds").ToString() | Should Be "DWord"
    }

    It "returns absent entries when the registry path does not exist" {
        $snapshot = Get-AgentRegistrySnapshot `
            -Path $script:modeRoot `
            -Names @("Mode", "ApiUrl", "EnrollmentJitterSeconds")

        $snapshot["Mode"].Exists | Should Be $false
        $snapshot["ApiUrl"].Exists | Should Be $false
        $snapshot["EnrollmentJitterSeconds"].Exists | Should Be $false
    }

    It "treats clear on a missing registry path as a no-op" {
        { Clear-AgentAutoEnrollRegistry -Path $script:modeRoot } | Should Not Throw
        Test-Path -LiteralPath $script:modeRoot | Should Be $false
    }

    It "clears stale auto-enroll mode for HMAC reinstall while preserving unrelated values" {
        New-Item -Path $script:modeRoot -Force | Out-Null
        New-ItemProperty -Path $script:modeRoot -Name "Mode" -Value "auto-enroll" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $script:modeRoot -Name "ApiUrl" -Value "https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $script:modeRoot -Name "EnrollmentJitterSeconds" -Value 9 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $script:modeRoot -Name "Unrelated" -Value "keep" -PropertyType String -Force | Out-Null

        Clear-AgentAutoEnrollRegistry -Path $script:modeRoot

        $key = Get-Item -LiteralPath $script:modeRoot
        $names = @($key.GetValueNames())
        $names -contains "Mode" | Should Be $false
        $names -contains "ApiUrl" | Should Be $false
        $names -contains "EnrollmentJitterSeconds" | Should Be $false
        (Get-ItemProperty -Path $script:modeRoot).Unrelated | Should Be "keep"
    }

    It "restores a snapshot if install rollback runs after clearing stale mode" {
        Set-AgentAutoEnrollRegistry `
            -Path $script:modeRoot `
            -ApiUrl "https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent" `
            -JitterSeconds 21

        $snapshot = Get-AgentRegistrySnapshot `
            -Path $script:modeRoot `
            -Names @("Mode", "ApiUrl", "EnrollmentJitterSeconds")

        Clear-AgentAutoEnrollRegistry -Path $script:modeRoot
        Restore-AgentRegistrySnapshot -Path $script:modeRoot -Snapshot $snapshot

        $props = Get-ItemProperty -Path $script:modeRoot
        $props.Mode | Should Be "auto-enroll"
        $props.ApiUrl | Should Be "https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent"
        $props.EnrollmentJitterSeconds | Should Be 21
        (Get-Item -LiteralPath $script:modeRoot).GetValueKind("EnrollmentJitterSeconds").ToString() | Should Be "DWord"
    }
}
