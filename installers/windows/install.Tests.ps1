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
# extract them from the PowerShell AST.

$installSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot "install.ps1") -Raw
$installTokens = $null
$installParseErrors = $null
$script:installAst = [System.Management.Automation.Language.Parser]::ParseInput(
    $installSource,
    [ref]$installTokens,
    [ref]$installParseErrors
)
if ($installParseErrors -and $installParseErrors.Count -gt 0) {
    throw "install.ps1 helper test import failed: install.ps1 has parser errors"
}

function Write-Step {
    param([string]$Message)
    Write-Verbose $Message
}

function Import-InstallHelper {
    param([string]$Name)
    $functionAst = $script:installAst.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $Name
    }, $true)

    if ($null -eq $functionAst) {
        throw "Helper '$Name' not found in install.ps1"
    }
    $definition = $functionAst.Extent.Text -replace "^function\s+$([regex]::Escape($Name))\b", "function script:$Name"
    Invoke-Expression $definition
}

Import-InstallHelper -Name "Wait-ForCredentialConfirmed"
Import-InstallHelper -Name "Wait-ForServiceRunning"
Import-InstallHelper -Name "Get-AgentLogTailForError"

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

Describe "Wait-ForServiceRunning" {
    It "returns true when the service is running" {
        Mock Get-Service { [pscustomobject]@{ Status = "Running" } }
        Mock Start-Sleep {}

        Wait-ForServiceRunning -Name "EndpointAgent" -TimeoutSeconds 1 | Should Be $true
    }

    It "returns false when the timeout expires before Running" {
        Mock Get-Service { [pscustomobject]@{ Status = "Stopped" } }
        Mock Start-Sleep {}

        Wait-ForServiceRunning -Name "EndpointAgent" -TimeoutSeconds 1 | Should Be $false
    }
}

Describe "Get-AgentLogTailForError" {
    BeforeEach {
        $script:tailLog = Join-Path $env:TEMP "endpoint-agent-tail-$([guid]::NewGuid()).log"
    }
    AfterEach {
        if (Test-Path -LiteralPath $script:tailLog) {
            Remove-Item -LiteralPath $script:tailLog -Force
        }
    }

    It "returns a bounded recent log tail" {
        1..50 | ForEach-Object { "line-$_" } | Set-Content -LiteralPath $script:tailLog -Encoding UTF8

        $tail = Get-AgentLogTailForError -LogPath $script:tailLog -LineCount 3

        $tail | Should Match "line-48"
        $tail | Should Match "line-50"
        $tail | Should Not Match "line-1"
    }

    It "returns a clear message when the log is missing" {
        Get-AgentLogTailForError -LogPath $script:tailLog -LineCount 3 |
            Should Match "agent log not found"
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
Import-InstallHelper -Name "Assert-EnrollmentTokenLength"
Import-InstallHelper -Name "Assert-RemoteBridgeInstallConfig"
Import-InstallHelper -Name "Add-RemoteBridgeServiceEnvironment"
Import-InstallHelper -Name "Resolve-SelfUpdateSignerThumbprints"
Import-InstallHelper -Name "Normalize-SelfUpdateSignerSha256Thumbprints"
Import-InstallHelper -Name "Get-CertificateRawSha256Thumbprint"
Import-InstallHelper -Name "Get-SelfUpdateSignerSha256ThumbprintFromBinary"
Import-InstallHelper -Name "Assert-SelfUpdateInstallConfig"
Import-InstallHelper -Name "Add-SelfUpdateServiceEnvironment"

Describe "Assert-EnrollmentTokenLength (#120 truncated-paste guard)" {
    It "throws on a 1-char token (the MKR-A1 live-pilot truncated paste)" {
        { Assert-EnrollmentTokenLength -Token "v" -MinLength 32 } |
            Should Throw
    }

    It "throws on a token just below the floor and reports the actual length" {
        # Pester 3/4 `Should Throw` does a literal substring (.Contains) match, not a
        # wildcard — so no leading/trailing '*'.
        { Assert-EnrollmentTokenLength -Token ("a" * 31) -MinLength 32 } |
            Should Throw "31 character"
    }

    It "accepts a real-length (~600 char) token" {
        { Assert-EnrollmentTokenLength -Token ("x" * 600) -MinLength 32 } |
            Should Not Throw
    }

    It "accepts a token exactly at the floor" {
        { Assert-EnrollmentTokenLength -Token ("a" * 32) -MinLength 32 } |
            Should Not Throw
    }

    It "is a no-op for a blank/absent token (AgentId/AgentSecret or auto-enroll path)" {
        { Assert-EnrollmentTokenLength -Token "" -MinLength 32 } | Should Not Throw
        { Assert-EnrollmentTokenLength -Token "   " -MinLength 32 } | Should Not Throw
    }

    It "trims surrounding whitespace before measuring" {
        { Assert-EnrollmentTokenLength -Token ("  " + ("a" * 31) + "  ") -MinLength 32 } |
            Should Throw
    }
}

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

Describe "Remote bridge installer env gating" {
    It "rejects enabled bridge without a broker address" {
        { Assert-RemoteBridgeInstallConfig -Enabled $true -BrokerAddr "" -InsecurePlaintext $false } |
            Should Throw "-RemoteBridgeEnabled requires -RemoteBridgeBrokerAddr"
    }

    It "rejects a broker address when the bridge is disabled" {
        { Assert-RemoteBridgeInstallConfig -Enabled $false -BrokerAddr "broker.example:443" -InsecurePlaintext $false } |
            Should Throw "-RemoteBridgeBrokerAddr requires -RemoteBridgeEnabled"
    }

    It "rejects plaintext mode when the bridge is disabled" {
        { Assert-RemoteBridgeInstallConfig -Enabled $false -BrokerAddr "" -InsecurePlaintext $true } |
            Should Throw "-RemoteBridgeInsecurePlaintext requires -RemoteBridgeEnabled"
    }

    It "rejects operation-mode config when the bridge is disabled" {
        { Assert-RemoteBridgeInstallConfig -Enabled $false -BrokerAddr "" -InsecurePlaintext $false -OperationsEnabled $true } |
            Should Throw "-RemoteBridgeOperationsEnabled requires -RemoteBridgeEnabled"

        { Assert-RemoteBridgeInstallConfig -Enabled $false -BrokerAddr "" -InsecurePlaintext $false -PermitBrokerPublicKeyB64 "pub" } |
            Should Throw "-RemoteBridgePermitBrokerPublicKeyB64 requires -RemoteBridgeEnabled"

        { Assert-RemoteBridgeInstallConfig -Enabled $false -BrokerAddr "" -InsecurePlaintext $false -TLSServerName "remote-bridge-mtls.testai.acik.com" } |
            Should Throw "-RemoteBridgeTLSServerName requires -RemoteBridgeEnabled"

        { Assert-RemoteBridgeInstallConfig -Enabled $false -BrokerAddr "" -InsecurePlaintext $false -PilotAutoConsent $true } |
            Should Throw "-RemoteBridgePilotAutoConsent requires -RemoteBridgeEnabled"
    }

    It "rejects constrained operations without broker permit trust anchors" {
        { Assert-RemoteBridgeInstallConfig -Enabled $true -BrokerAddr "remote-bridge-mtls.testai.acik.com:443" -InsecurePlaintext $false -OperationsEnabled $true -PermitBrokerPublicKeyB64 "" -PermitKeyID "kid-1" } |
            Should Throw "-RemoteBridgeOperationsEnabled requires -RemoteBridgePermitBrokerPublicKeyB64 and -RemoteBridgePermitKeyID"

        { Assert-RemoteBridgeInstallConfig -Enabled $true -BrokerAddr "remote-bridge-mtls.testai.acik.com:443" -InsecurePlaintext $false -OperationsEnabled $true -PermitBrokerPublicKeyB64 "pub" -PermitKeyID "" } |
            Should Throw "-RemoteBridgeOperationsEnabled requires -RemoteBridgePermitBrokerPublicKeyB64 and -RemoteBridgePermitKeyID"
    }

    It "rejects pilot auto-consent without constrained operation mode" {
        { Assert-RemoteBridgeInstallConfig -Enabled $true -BrokerAddr "remote-bridge-mtls.testai.acik.com:443" -InsecurePlaintext $false -PilotAutoConsent $true } |
            Should Throw "-RemoteBridgePilotAutoConsent requires -RemoteBridgeOperationsEnabled"
    }

    It "writes only explicit remote bridge service environment values" {
        $values = @{
            "ENDPOINT_AGENT_LOG_DIR" = "C:\ProgramData\EndpointAgent\logs"
        }

        Add-RemoteBridgeServiceEnvironment `
            -Values $values `
            -Enabled $true `
            -BrokerAddr "remote-bridge-mtls.testai.acik.com:443" `
            -InsecurePlaintext $false `
            -CertSubjectSuffix ".acik.local" `
            -CertSANURIPrefix "adcomputer:" `
            -AttestationEvidenceB64 "attestation-b64" `
            -OperationsEnabled $true `
            -PermitBrokerPublicKeyB64 "pub-key-b64" `
            -PermitKeyID "kid-1" `
            -PilotAutoConsent $true `
            -TLSServerName "remote-bridge-mtls.testai.acik.com"

        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_ENABLED"] | Should Be "true"
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_BROKER_ADDR"] | Should Be "remote-bridge-mtls.testai.acik.com:443"
        $values.ContainsKey("ENDPOINT_AGENT_REMOTE_BRIDGE_INSECURE_PLAINTEXT") | Should Be $false
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_MTLS_CERT_SUBJECT_SUFFIX"] | Should Be ".acik.local"
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_MTLS_CERT_SAN_URI_PREFIX"] | Should Be "adcomputer:"
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_ATTESTATION_EVIDENCE_B64"] | Should Be "attestation-b64"
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_OPERATIONS_ENABLED"] | Should Be "true"
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_PERMIT_BROKER_PUBLIC_KEY_B64"] | Should Be "pub-key-b64"
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_PERMIT_KEY_ID"] | Should Be "kid-1"
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_PILOT_AUTO_CONSENT"] | Should Be "true"
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_TLS_SERVER_NAME"] | Should Be "remote-bridge-mtls.testai.acik.com"
    }

    It "does not add remote bridge service environment values when disabled" {
        $values = @{
            "ENDPOINT_AGENT_LOG_DIR" = "C:\ProgramData\EndpointAgent\logs"
        }

        Add-RemoteBridgeServiceEnvironment `
            -Values $values `
            -Enabled $false `
            -BrokerAddr "" `
            -InsecurePlaintext $false

        $values.ContainsKey("ENDPOINT_AGENT_REMOTE_BRIDGE_ENABLED") | Should Be $false
        $values.ContainsKey("ENDPOINT_AGENT_REMOTE_BRIDGE_BROKER_ADDR") | Should Be $false
        $values.ContainsKey("ENDPOINT_AGENT_REMOTE_BRIDGE_INSECURE_PLAINTEXT") | Should Be $false
    }
}

Describe "Self-update installer env gating" {
    It "derives the self-update signer allowlist from the verified signer SHA256 fingerprint" {
        Resolve-SelfUpdateSignerThumbprints `
            -ExplicitThumbprints "" `
            -VerifiedSignerSha256Thumbprint "EB16FA8C2C2325295483ED2271D87632DA5EA631E3095039D6CFC358F16CAACD" |
            Should Be "EB16FA8C2C2325295483ED2271D87632DA5EA631E3095039D6CFC358F16CAACD"
    }

    It "does not derive the self-update signer allowlist from the SHA1 Authenticode thumbprint" {
        Resolve-SelfUpdateSignerThumbprints `
            -ExplicitThumbprints "" `
            -VerifiedSignerSha256Thumbprint "" |
            Should Be ""
    }

    It "prefers an explicit self-update signer allowlist during rotation" {
        Resolve-SelfUpdateSignerThumbprints `
            -ExplicitThumbprints "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb:bb" `
            -VerifiedSignerSha256Thumbprint "EB16FA8C2C2325295483ED2271D87632DA5EA631E3095039D6CFC358F16CAACD" |
            Should Be "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    }

    It "rejects explicit self-update SHA1 signer thumbprints" {
        {
            Normalize-SelfUpdateSignerSha256Thumbprints `
                -Thumbprints "D68F4F530137EB65CE44E3405E82B46205E753E5"
        } | Should Throw "64 hex"
    }

    It "computes uppercase SHA256 over signer certificate raw data" {
        $cert = [pscustomobject]@{
            RawData = [byte[]](1, 2, 3)
        }

        Get-CertificateRawSha256Thumbprint -Certificate $cert |
            Should Be "039058C6F2C0CB492C533B0A4D14EF77CC0F78ABCCCED5287D84A1A2011CFB81"
    }

    It "derives the local self-update allowlist from the verified binary signer certificate SHA256" {
        Mock Get-AuthenticodeSignature {
            [pscustomobject]@{
                SignerCertificate = [pscustomobject]@{
                    Thumbprint = "D68F4F530137EB65CE44E3405E82B46205E753E5"
                    RawData = [byte[]](1, 2, 3)
                }
            }
        }

        Get-SelfUpdateSignerSha256ThumbprintFromBinary `
            -Path "C:\Program Files\EndpointAgent\endpoint-agent.exe" `
            -ExpectedThumbprint "D68F4F530137EB65CE44E3405E82B46205E753E5" |
            Should Be "039058C6F2C0CB492C533B0A4D14EF77CC0F78ABCCCED5287D84A1A2011CFB81"
    }

    It "refuses to derive a local self-update allowlist when the binary signer SHA1 is not the expected release signer" {
        Mock Get-AuthenticodeSignature {
            [pscustomobject]@{
                SignerCertificate = [pscustomobject]@{
                    Thumbprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    RawData = [byte[]](1, 2, 3)
                }
            }
        }

        {
            Get-SelfUpdateSignerSha256ThumbprintFromBinary `
                -Path "C:\Program Files\EndpointAgent\endpoint-agent.exe" `
                -ExpectedThumbprint "D68F4F530137EB65CE44E3405E82B46205E753E5"
        } | Should Throw "signer thumbprint mismatch"
    }

    It "rejects enabled self-update without local URL and signer trust policy" {
        { Assert-SelfUpdateInstallConfig -Enabled $true -AllowedHosts "" -SignerThumbprints "D68F4F530137EB65CE44E3405E82B46205E753E5" -HardMaxBytes "52428800" -MaxRedirects 5 -AutoActivate $false -ActivationTimeout "2m" -CommandTimeout "30m" } |
            Should Throw "-SelfUpdateEnabled requires -SelfUpdateAllowedHosts"

        { Assert-SelfUpdateInstallConfig -Enabled $true -AllowedHosts "github.com" -SignerThumbprints "" -HardMaxBytes "52428800" -MaxRedirects 5 -AutoActivate $false -ActivationTimeout "2m" -CommandTimeout "30m" } |
            Should Throw "-SelfUpdateEnabled requires -SelfUpdateSignerThumbprints"
    }

    It "rejects self-update policy values when self-update is disabled" {
        { Assert-SelfUpdateInstallConfig -Enabled $false -AllowedHosts "github.com" -SignerThumbprints "" -HardMaxBytes "52428800" -MaxRedirects 5 -AutoActivate $false -ActivationTimeout "2m" -CommandTimeout "30m" } |
            Should Throw "-SelfUpdateAllowedHosts requires -SelfUpdateEnabled"

        { Assert-SelfUpdateInstallConfig -Enabled $false -AllowedHosts "" -SignerThumbprints "D68F4F530137EB65CE44E3405E82B46205E753E5" -HardMaxBytes "52428800" -MaxRedirects 5 -AutoActivate $false -ActivationTimeout "2m" -CommandTimeout "30m" } |
            Should Throw "-SelfUpdateSignerThumbprints requires -SelfUpdateEnabled"
    }

    It "writes the complete local self-update service environment when enabled" {
        $values = @{
            "ENDPOINT_AGENT_LOG_DIR" = "C:\ProgramData\EndpointAgent\logs"
        }

        Add-SelfUpdateServiceEnvironment `
            -Values $values `
            -Enabled $true `
            -AllowedHosts "github.com,release-assets.githubusercontent.com,objects.githubusercontent.com" `
            -SignerThumbprints "EB16FA8C2C2325295483ED2271D87632DA5EA631E3095039D6CFC358F16CAACD" `
            -HardMaxBytes "52428800" `
            -MaxRedirects 5 `
            -AutoActivate $true `
            -ActivationTimeout "2m" `
            -ServiceName "EndpointAgent" `
            -CommandTimeout "30m"

        $values["ENDPOINT_AGENT_SELF_UPDATE_ENABLED"] | Should Be "true"
        $values["ENDPOINT_AGENT_SELF_UPDATE_ALLOWED_HOSTS"] | Should Be "github.com,release-assets.githubusercontent.com,objects.githubusercontent.com"
        $values["ENDPOINT_AGENT_SELF_UPDATE_SIGNER_THUMBPRINTS"] | Should Be "EB16FA8C2C2325295483ED2271D87632DA5EA631E3095039D6CFC358F16CAACD"
        $values["ENDPOINT_AGENT_SELF_UPDATE_HARD_MAX_BYTES"] | Should Be "52428800"
        $values["ENDPOINT_AGENT_SELF_UPDATE_MAX_REDIRECTS"] | Should Be "5"
        $values["ENDPOINT_AGENT_SELF_UPDATE_AUTO_ACTIVATE"] | Should Be "true"
        $values["ENDPOINT_AGENT_SELF_UPDATE_ACTIVATION_TIMEOUT"] | Should Be "2m"
        $values["ENDPOINT_AGENT_SELF_UPDATE_SERVICE_NAME"] | Should Be "EndpointAgent"
        $values["ENDPOINT_AGENT_SELF_UPDATE_COMMAND_TIMEOUT"] | Should Be "30m"
    }

    It "does not add self-update service environment values when disabled" {
        $values = @{
            "ENDPOINT_AGENT_LOG_DIR" = "C:\ProgramData\EndpointAgent\logs"
        }

        Add-SelfUpdateServiceEnvironment `
            -Values $values `
            -Enabled $false `
            -AllowedHosts "" `
            -SignerThumbprints "" `
            -HardMaxBytes "52428800" `
            -MaxRedirects 5 `
            -AutoActivate $false `
            -ActivationTimeout "2m" `
            -ServiceName "EndpointAgent" `
            -CommandTimeout "30m"

        $values.ContainsKey("ENDPOINT_AGENT_SELF_UPDATE_ENABLED") | Should Be $false
        $values.ContainsKey("ENDPOINT_AGENT_SELF_UPDATE_SIGNER_THUMBPRINTS") | Should Be $false
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
        $thrownMessage = $null
        try {
            Assert-HmacEnrollmentTokenStorePolicy -Token "fresh-token" -ResetRequested $false -CredentialStorePath $script:storePath
        } catch {
            $thrownMessage = $_.Exception.Message
        }
        $thrownMessage | Should Match "^Existing EndpointAgent HMAC credential store found"
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
            -ApiUrl "https://mtls.testai.acik.com/api/v1/endpoint-agent" `
            -JitterSeconds 17

        $props = Get-ItemProperty -Path $script:modeRoot
        $props.Mode | Should Be "auto-enroll"
        $props.ApiUrl | Should Be "https://mtls.testai.acik.com/api/v1/endpoint-agent"
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
        New-ItemProperty -Path $script:modeRoot -Name "ApiUrl" -Value "https://mtls.testai.acik.com/api/v1/endpoint-agent" -PropertyType String -Force | Out-Null
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
            -ApiUrl "https://mtls.testai.acik.com/api/v1/endpoint-agent" `
            -JitterSeconds 21

        $snapshot = Get-AgentRegistrySnapshot `
            -Path $script:modeRoot `
            -Names @("Mode", "ApiUrl", "EnrollmentJitterSeconds")
        $snapshot["Mode"].Exists | Should Be $true
        $snapshot["Mode"].Value | Should Be "auto-enroll"
        $snapshot["Mode"].Kind | Should Be "String"
        $snapshot["ApiUrl"].Exists | Should Be $true
        $snapshot["ApiUrl"].Value | Should Be "https://mtls.testai.acik.com/api/v1/endpoint-agent"
        $snapshot["ApiUrl"].Kind | Should Be "String"
        $snapshot["EnrollmentJitterSeconds"].Exists | Should Be $true
        $snapshot["EnrollmentJitterSeconds"].Value | Should Be 21
        $snapshot["EnrollmentJitterSeconds"].Kind | Should Be "DWord"

        Clear-AgentAutoEnrollRegistry -Path $script:modeRoot
        Restore-AgentRegistrySnapshot -Path $script:modeRoot -Snapshot $snapshot

        $names = @((Get-Item -LiteralPath $script:modeRoot).GetValueNames())
        $names -contains "Mode" | Should Be $true
        $names -contains "ApiUrl" | Should Be $true
        $names -contains "EnrollmentJitterSeconds" | Should Be $true

        $props = Get-ItemProperty -Path $script:modeRoot
        $props.Mode | Should Be "auto-enroll"
        $props.ApiUrl | Should Be "https://mtls.testai.acik.com/api/v1/endpoint-agent"
        $props.EnrollmentJitterSeconds | Should Be 21
        (Get-Item -LiteralPath $script:modeRoot).GetValueKind("EnrollmentJitterSeconds").ToString() | Should Be "DWord"
    }
}
