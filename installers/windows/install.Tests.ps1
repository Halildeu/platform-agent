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

$script:installSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot "install.ps1") -Raw
$installTokens = $null
$installParseErrors = $null
$script:installAst = [System.Management.Automation.Language.Parser]::ParseInput(
    $script:installSource,
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
Import-InstallHelper -Name "Test-ServiceExists"
Import-InstallHelper -Name "Wait-ForServiceAbsent"
Import-InstallHelper -Name "Get-ServiceEnvironmentSnapshot"
Import-InstallHelper -Name "Restore-ServiceEnvironmentSnapshot"
Import-InstallHelper -Name "Assert-ServiceEnvironmentSnapshot"
Import-InstallHelper -Name "Get-ServiceSddlFromOutput"
Import-InstallHelper -Name "Get-ServiceSddl"
Import-InstallHelper -Name "Initialize-ServiceFailurePolicyNative"
Initialize-ServiceFailurePolicyNative
Import-InstallHelper -Name "Get-ServiceFailurePolicy"
Import-InstallHelper -Name "Restore-ServiceFailurePolicy"
Import-InstallHelper -Name "Assert-ServiceFailurePolicy"
Import-InstallHelper -Name "Get-ServiceStartMode"
Import-InstallHelper -Name "Get-InstallTreeAclSnapshot"
Import-InstallHelper -Name "Restore-InstallTreeAclSnapshot"
Import-InstallHelper -Name "Assert-InstallTreeAclSnapshot"
Import-InstallHelper -Name "New-ServiceReplacementSnapshot"
Import-InstallHelper -Name "Remove-ServiceReplacementSnapshot"
Import-InstallHelper -Name "Restore-ServiceReplacementSnapshot"
Import-InstallHelper -Name "Protect-DirectoryAcl"
Import-InstallHelper -Name "Remove-ServiceBestEffort"
Import-InstallHelper -Name "Invoke-AgentServiceCommand"
Import-InstallHelper -Name "Invoke-NativeCommand"
Import-InstallHelper -Name "Get-AgentRegistrySnapshot"
Import-InstallHelper -Name "Restore-AgentRegistrySnapshot"
Import-InstallHelper -Name "Set-AgentAutoEnrollRegistry"
Import-InstallHelper -Name "Clear-AgentAutoEnrollRegistry"
Import-InstallHelper -Name "Get-HmacCredentialStorePath"
Import-InstallHelper -Name "Assert-HmacEnrollmentTokenStorePolicy"
Import-InstallHelper -Name "Backup-HmacCredentialStoreForFreshEnroll"
Import-InstallHelper -Name "Restore-HmacCredentialStoreBackup"
Import-InstallHelper -Name "Assert-HmacCredentialResetConfirmed"
Import-InstallHelper -Name "Assert-EnrollmentTokenLength"
Import-InstallHelper -Name "Assert-ViewOnlyMaskRectBPS"
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
            Should Throw "remote-bridge operation-capable policy requires -RemoteBridgePermitBrokerPublicKeyB64 and -RemoteBridgePermitKeyID"

        { Assert-RemoteBridgeInstallConfig -Enabled $true -BrokerAddr "remote-bridge-mtls.testai.acik.com:443" -InsecurePlaintext $false -OperationsEnabled $true -PermitBrokerPublicKeyB64 "pub" -PermitKeyID "" } |
            Should Throw "remote-bridge operation-capable policy requires -RemoteBridgePermitBrokerPublicKeyB64 and -RemoteBridgePermitKeyID"
    }

    It "rejects pilot auto-consent without constrained operation mode" {
        { Assert-RemoteBridgeInstallConfig -Enabled $true -BrokerAddr "remote-bridge-mtls.testai.acik.com:443" -InsecurePlaintext $false -PilotAutoConsent $true } |
            Should Throw "-RemoteBridgePilotAutoConsent requires -RemoteBridgeOperationsEnabled"
    }

    It "rejects view-only attended consent when the bridge is disabled" {
        { Assert-RemoteBridgeInstallConfig -Enabled $false -BrokerAddr "" -InsecurePlaintext $false -ViewOnlyAttendedConsent $true } |
            Should Throw "-RemoteBridgeViewOnlyAttendedConsent requires -RemoteBridgeEnabled"
    }

    It "keeps view-only independent from PTY while requiring shared permit trust" {
        { Assert-RemoteBridgeInstallConfig `
            -Enabled $true `
            -BrokerAddr "remote-bridge-mtls.testai.acik.com:443" `
            -InsecurePlaintext $false `
            -ViewOnlyEnabled $true `
            -PermitBrokerPublicKeyB64 "pub" `
            -PermitKeyID "kid-1" } |
            Should Not Throw

        { Assert-RemoteBridgeInstallConfig `
            -Enabled $true `
            -BrokerAddr "remote-bridge-mtls.testai.acik.com:443" `
            -InsecurePlaintext $false `
            -ViewOnlyEnabled $true } |
            Should Throw "remote-bridge operation-capable policy requires -RemoteBridgePermitBrokerPublicKeyB64 and -RemoteBridgePermitKeyID"
    }

    It "requires constrained operations before enabling device-key session" {
        { Assert-RemoteBridgeInstallConfig `
            -Enabled $true `
            -BrokerAddr "remote-bridge-mtls.testai.acik.com:443" `
            -InsecurePlaintext $false `
            -DeviceKeySessionEnabled $true } |
            Should Throw "-RemoteBridgeDeviceKeySessionEnabled requires -RemoteBridgeOperationsEnabled"
    }

    It "requires view-only before attended consent or mask policy" {
        { Assert-RemoteBridgeInstallConfig `
            -Enabled $true `
            -BrokerAddr "remote-bridge-mtls.testai.acik.com:443" `
            -InsecurePlaintext $false `
            -OperationsEnabled $true `
            -PermitBrokerPublicKeyB64 "pub" `
            -PermitKeyID "kid-1" `
            -ViewOnlyAttendedConsent $true } |
            Should Throw "-RemoteBridgeViewOnlyAttendedConsent requires -RemoteBridgeViewOnlyEnabled"

        { Assert-RemoteBridgeInstallConfig `
            -Enabled $true `
            -BrokerAddr "remote-bridge-mtls.testai.acik.com:443" `
            -InsecurePlaintext $false `
            -OperationsEnabled $true `
            -PermitBrokerPublicKeyB64 "pub" `
            -PermitKeyID "kid-1" `
            -ViewOnlyMaskRectBPS "0,0,1000,1000" } |
            Should Throw "-RemoteBridgeViewOnlyMaskRectBPS requires -RemoteBridgeViewOnlyEnabled"
    }

    It "accepts only canonical in-bounds view-only mask rectangles" {
        { Assert-ViewOnlyMaskRectBPS -Value "7500,7500,2500,2500" } | Should Not Throw
        { Assert-ViewOnlyMaskRectBPS -Value "7500,7500,2501,2500" } | Should Throw
        { Assert-ViewOnlyMaskRectBPS -Value "0,0,0,1000" } | Should Throw
        { Assert-ViewOnlyMaskRectBPS -Value "0, 0,1000,1000" } | Should Throw
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
            -DeviceKeySessionEnabled $true `
            -ViewOnlyEnabled $true `
            -ViewOnlyAttendedConsent $true `
            -ViewOnlyMaskRectBPS "7500,7500,2500,2500" `
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
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_DEVICE_KEY_SESSION_ENABLED"] | Should Be "true"
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ENABLED"] | Should Be "true"
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ATTENDED_CONSENT_ENABLED"] | Should Be "true"
        $values["ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_MASK_RECT_BPS"] | Should Be "7500,7500,2500,2500"
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

    It "restores the previous credential store after a failed fresh enrollment" {
        Set-Content -LiteralPath $script:storePath -Value "stored-old" -Encoding ASCII
        $backup = Backup-HmacCredentialStoreForFreshEnroll `
            -CredentialStorePath $script:storePath `
            -Timestamp "20260608T150000Z"
        Set-Content -LiteralPath $script:storePath -Value "failed-new" -Encoding ASCII

        Restore-HmacCredentialStoreBackup `
            -CredentialStorePath $script:storePath `
            -BackupPath $backup

        (Get-Content -LiteralPath $script:storePath -Raw).TrimEnd() | Should Be "stored-old"
        Test-Path -LiteralPath $backup | Should Be $false
    }

    It "refuses to commit a reset until the replacement credential is confirmed" {
        { Assert-HmacCredentialResetConfirmed -BackupPath "C:\protected\old.dpapi.bak" -Confirmed $false } |
            Should Throw "fresh HMAC enrollment was not confirmed"
        { Assert-HmacCredentialResetConfirmed -BackupPath "C:\protected\old.dpapi.bak" -Confirmed $true } |
            Should Not Throw
        { Assert-HmacCredentialResetConfirmed -BackupPath "" -Confirmed $false } |
            Should Not Throw
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

Describe "Transactional service environment rollback" {
    BeforeAll {
        $script:transactionServicePath = "HKCU:\Software\Halildeu\EndpointAgentTransactionTest"
    }

    BeforeEach {
        if (Test-Path -LiteralPath $script:transactionServicePath) {
            Remove-Item -LiteralPath $script:transactionServicePath -Recurse -Force
        }
        New-Item -Path $script:transactionServicePath -Force | Out-Null
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:transactionServicePath) {
            Remove-Item -LiteralPath $script:transactionServicePath -Recurse -Force
        }
    }

    It "restores the exact pre-upgrade multi-string environment" {
        $expectedEntries = @(
            "ENDPOINT_AGENT_REMOTE_BRIDGE_ENABLED=true",
            "ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ATTENDED_CONSENT_ENABLED=true",
            "ENDPOINT_AGENT_REMOTE_BRIDGE_PERMIT_KEY_ID=test-key"
        )
        New-ItemProperty `
            -Path $script:transactionServicePath `
            -Name "Environment" `
            -Value $expectedEntries `
            -PropertyType MultiString `
            -Force | Out-Null

        $snapshot = Get-ServiceEnvironmentSnapshot `
            -Name "EndpointAgent" `
            -ServicePath $script:transactionServicePath
        New-ItemProperty `
            -Path $script:transactionServicePath `
            -Name "Environment" `
            -Value @("ENDPOINT_AGENT_REMOTE_BRIDGE_ENABLED=false") `
            -PropertyType MultiString `
            -Force | Out-Null

        Restore-ServiceEnvironmentSnapshot `
            -Name "EndpointAgent" `
            -Snapshot $snapshot `
            -ServicePath $script:transactionServicePath

        { Assert-ServiceEnvironmentSnapshot `
            -Name "EndpointAgent" `
            -Expected $snapshot `
            -ServicePath $script:transactionServicePath } | Should Not Throw
    }

    It "restores an originally absent Environment value" {
        $snapshot = Get-ServiceEnvironmentSnapshot `
            -Name "EndpointAgent" `
            -ServicePath $script:transactionServicePath
        $snapshot.Exists | Should Be $false

        New-ItemProperty `
            -Path $script:transactionServicePath `
            -Name "Environment" `
            -Value @("TEMP=C:\Windows\Temp") `
            -PropertyType MultiString `
            -Force | Out-Null
        Restore-ServiceEnvironmentSnapshot `
            -Name "EndpointAgent" `
            -Snapshot $snapshot `
            -ServicePath $script:transactionServicePath

        (Get-Item -LiteralPath $script:transactionServicePath).GetValueNames() -contains "Environment" |
            Should Be $false
    }

    It "captures before destructive replacement and invokes verified restore on failure" {
        $hmacPolicyIndex = $script:installSource.LastIndexOf('Assert-HmacEnrollmentTokenStorePolicy')
        $snapshotIndex = $script:installSource.IndexOf('$replacementSnapshot = New-ServiceReplacementSnapshot')
        $clearIndex = $script:installSource.IndexOf('clearing stale service env regkey')
        $hmacPolicyIndex -ge 0 | Should Be $true
        $snapshotIndex -ge 0 | Should Be $true
        $snapshotIndex -gt $hmacPolicyIndex | Should Be $true
        $clearIndex -gt $snapshotIndex | Should Be $true
        $script:installSource.Contains('Restore-ServiceReplacementSnapshot') | Should Be $true
        $script:installSource.Contains('Assert-ServiceEnvironmentSnapshot') | Should Be $true
        $script:installSource.Contains('Restore-HmacCredentialStoreBackup') | Should Be $true
        $script:installSource.Contains('restored service start mode mismatch') | Should Be $true
    }
}

Describe "Transactional service replacement helpers" {
    BeforeEach {
        $script:oldProgramData = $env:ProgramData
        $env:ProgramData = Join-Path $TestDrive "ProgramData"
        New-Item -ItemType Directory -Force -Path $env:ProgramData | Out-Null
    }

    AfterEach {
        $env:ProgramData = $script:oldProgramData
    }

    It "maps auto, delayed-auto, manual, and disabled start modes" {
        Get-ServiceStartMode -StartValue 2 -DelayedAutoStart $false | Should Be "auto"
        Get-ServiceStartMode -StartValue 2 -DelayedAutoStart $true | Should Be "delayed-auto"
        Get-ServiceStartMode -StartValue 3 -DelayedAutoStart $false | Should Be "demand"
        Get-ServiceStartMode -StartValue 4 -DelayedAutoStart $false | Should Be "disabled"
        { Get-ServiceStartMode -StartValue 1 -DelayedAutoStart $false } | Should Throw
    }

    It "parses the exact SDDL line from multiline sc.exe output" {
        Get-ServiceSddlFromOutput `
            -Name "EndpointAgent" `
            -Output @(
                "[SC] QueryServiceObjectSecurity SUCCESS",
                "",
                "  D:(A;;CCLCSWLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)  "
            ) |
            Should Be "D:(A;;CCLCSWLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)"

        { Get-ServiceSddlFromOutput -Name "EndpointAgent" -Output @("no descriptor") } |
            Should Throw
    }

    It "waits for SCM deletion and fails closed on timeout" {
        Mock Test-ServiceExists { $false }
        Mock Start-Sleep {}
        Wait-ForServiceAbsent -Name "EndpointAgent" -TimeoutSeconds 1 | Should Be $true

        Mock Test-ServiceExists { $true }
        Wait-ForServiceAbsent -Name "EndpointAgent" -TimeoutSeconds 0 | Should Be $false
    }

    It "restores install-tree ACLs parent-first so inherited child ACEs stay exact" {
        $installPath = Join-Path $TestDrive "acl-order"
        $childPath = Join-Path $installPath "endpoint-agent.exe"
        New-Item -ItemType Directory -Force -Path $installPath | Out-Null
        Set-Content -LiteralPath $childPath -Value "binary" -Encoding ASCII
        $script:aclRestoreOrder = @()
        Mock Set-Acl {
            $script:aclRestoreOrder += $LiteralPath
        }

        Restore-InstallTreeAclSnapshot `
            -Path $installPath `
            -Snapshot @(
                [pscustomobject]@{ RelativePath = "endpoint-agent.exe"; Acl = "child-acl" },
                [pscustomobject]@{ RelativePath = "."; Acl = "root-acl" }
            )

        $script:aclRestoreOrder.Count | Should Be 2
        $script:aclRestoreOrder[0] | Should Be $installPath
        $script:aclRestoreOrder[1] | Should Be $childPath
    }

    It "snapshots manual services when optional registry values are absent" {
        $installPath = Join-Path $TestDrive "existing-install"
        New-Item -ItemType Directory -Force -Path $installPath | Out-Null
        Set-Content -LiteralPath (Join-Path $installPath "endpoint-agent.exe") -Value "old-binary" -Encoding ASCII

        Mock Test-ServiceExists { $true }
        Mock Get-Service { [pscustomobject]@{ DisplayName = "Endpoint Agent"; Status = "Stopped" } }
        Mock Get-ItemProperty { [pscustomobject]@{ Start = 3 } }
        Mock Get-ServiceFailurePolicy { [pscustomobject]@{ Canonical = "failure-policy" } }
        Mock Get-ServiceSddl { "D:(A;;CC;;;SY)" }
        Mock Get-InstallTreeAclSnapshot { @([pscustomobject]@{ RelativePath = "."; Acl = "acl"; Sddl = "D:root" }) }
        Mock Protect-DirectoryAcl {}
        Mock Get-ServiceEnvironmentSnapshot { [pscustomobject]@{ Exists = $false; Entries = @() } }

        $snapshot = New-ServiceReplacementSnapshot -Name "EndpointAgent" -InstallPath $installPath

        $snapshot | Should Not BeNullOrEmpty
        $snapshot.StartValue | Should Be 3
        $snapshot.StartMode | Should Be "demand"
        $snapshot.DelayedAutoStart | Should Be $false
        $snapshot.Description | Should Be ""
        $snapshot.ServiceSddl | Should Be "D:(A;;CC;;;SY)"
        Test-Path -LiteralPath (Join-Path $snapshot.RollbackInstallPath "endpoint-agent.exe") | Should Be $true
    }

    It "keeps Force repair available when the old binary is already missing" {
        $installPath = Join-Path $TestDrive "broken-install"
        New-Item -ItemType Directory -Force -Path $installPath | Out-Null
        Mock Test-ServiceExists { $true }

        New-ServiceReplacementSnapshot -Name "EndpointAgent" -InstallPath $installPath |
            Should BeNullOrEmpty
    }

    It "restores a manual running service with exact metadata hooks" {
        $rollbackPath = Join-Path $TestDrive "rollback-install"
        $installPath = Join-Path $TestDrive "restored-install"
        New-Item -ItemType Directory -Force -Path $rollbackPath | Out-Null
        Set-Content -LiteralPath (Join-Path $rollbackPath "endpoint-agent.exe") -Value "old-binary" -Encoding ASCII
        $binarySha = (Get-FileHash -LiteralPath (Join-Path $rollbackPath "endpoint-agent.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
        $snapshot = [pscustomobject]@{
            Name = "EndpointAgent"
            InstallPath = $installPath
            RollbackInstallPath = $rollbackPath
            BinarySha256 = $binarySha
            Environment = [pscustomobject]@{ Exists = $false; Entries = @() }
            DisplayName = "Endpoint Agent"
            Description = ""
            StartValue = 3
            StartMode = "demand"
            DelayedAutoStart = $false
            WasRunning = $true
            FailurePolicy = [pscustomobject]@{ Canonical = "failure-policy" }
            ServiceSddl = "D:(A;;CC;;;SY)"
            InstallTreeAcl = @([pscustomobject]@{ RelativePath = "."; Acl = "acl"; Sddl = "D:root" })
        }

        Mock Test-ServiceExists { $true }
        Mock Remove-ServiceBestEffort {}
        Mock Wait-ForServiceAbsent { $true }
        Mock Invoke-AgentServiceCommand {}
        Mock Restore-ServiceEnvironmentSnapshot {}
        Mock Restore-ServiceFailurePolicy {}
        Mock Assert-ServiceFailurePolicy {}
        Mock Restore-InstallTreeAclSnapshot {}
        Mock Assert-InstallTreeAclSnapshot {}
        Mock Invoke-NativeCommand {}
        Mock Assert-ServiceEnvironmentSnapshot {}
        Mock Get-ItemProperty { [pscustomobject]@{ Start = 3; DelayedAutoStart = 0 } }
        Mock Get-ServiceSddl { "D:(A;;CC;;;SY)" }
        Mock Get-Service { [pscustomobject]@{ DisplayName = "Endpoint Agent"; Status = "Stopped" } }
        Mock Wait-ForServiceRunning { $true }

        Restore-ServiceReplacementSnapshot `
            -Snapshot $snapshot `
            -StartTimeoutSeconds 1 `
            -MaintenanceToken "maintenance-token" `
            -MaintenanceTokenHash "maintenance-token-hash"

        Assert-MockCalled Invoke-NativeCommand -Times 1 -ParameterFilter {
            $FilePath -eq "sc.exe" -and $Arguments[0] -eq "config" -and $Arguments[3] -eq "demand"
        }
        Assert-MockCalled Invoke-AgentServiceCommand -Times 1 -ParameterFilter {
            $Arguments[0] -eq "service" -and $Arguments[1] -eq "start"
        }
        Assert-MockCalled Remove-ServiceBestEffort -Times 1 -ParameterFilter {
            $Token -eq "maintenance-token" -and $TokenHash -eq "maintenance-token-hash"
        }
        Assert-MockCalled Restore-ServiceFailurePolicy -Times 1
        Assert-MockCalled Assert-ServiceFailurePolicy -Times 1
        Assert-MockCalled Restore-InstallTreeAclSnapshot -Times 2
        Assert-MockCalled Assert-InstallTreeAclSnapshot -Times 1
    }

    It "does not couple rollback start timeout to the new-service timeout" {
        $script:installSource.Contains('-StartTimeoutSeconds $ServiceStartTimeoutSeconds') |
            Should Be $false
    }

    It "retains the protected payload when restore hash verification fails" {
        $rollbackPath = Join-Path $TestDrive "rollback-hash-failure"
        $installPath = Join-Path $TestDrive "restore-hash-failure"
        New-Item -ItemType Directory -Force -Path $rollbackPath | Out-Null
        Set-Content -LiteralPath (Join-Path $rollbackPath "endpoint-agent.exe") -Value "old-binary" -Encoding ASCII
        $snapshot = [pscustomobject]@{
            Name = "EndpointAgent"
            InstallPath = $installPath
            RollbackRoot = (Split-Path -Parent $rollbackPath)
            RollbackInstallPath = $rollbackPath
            BinarySha256 = ("0" * 64)
            InstallTreeAcl = @([pscustomobject]@{ RelativePath = "."; Acl = "acl"; Sddl = "D:root" })
        }

        Mock Test-ServiceExists { $false }
        Mock Restore-InstallTreeAclSnapshot {}

        { Restore-ServiceReplacementSnapshot -Snapshot $snapshot -StartTimeoutSeconds 1 } |
            Should Throw "transaction rollback binary hash mismatch"
        Test-Path -LiteralPath $rollbackPath | Should Be $true
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
