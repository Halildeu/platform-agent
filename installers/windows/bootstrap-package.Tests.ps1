# EndpointAgent bootstrap-package.ps1 helper tests.
#
# Scope: pure helper functions only. The bootstrap entry point downloads and
# installs the package, so tests import selected functions from the PowerShell
# AST instead of dot-sourcing the script.

$bootstrapSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot "bootstrap-package.ps1") -Raw
$bootstrapTokens = $null
$bootstrapParseErrors = $null
$script:bootstrapAst = [System.Management.Automation.Language.Parser]::ParseInput(
    $bootstrapSource,
    [ref]$bootstrapTokens,
    [ref]$bootstrapParseErrors
)
if ($bootstrapParseErrors -and $bootstrapParseErrors.Count -gt 0) {
    throw "bootstrap-package.ps1 helper test import failed: bootstrap-package.ps1 has parser errors"
}

function Import-BootstrapHelper {
    param([string]$Name)
    $functionAst = $script:bootstrapAst.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $Name
    }, $true)

    if ($null -eq $functionAst) {
        throw "Helper '$Name' not found in bootstrap-package.ps1"
    }
    $definition = $functionAst.Extent.Text -replace "^function\s+$([regex]::Escape($Name))\b", "function script:$Name"
    Invoke-Expression $definition
}

Import-BootstrapHelper -Name "Get-PackageUrlHost"
Import-BootstrapHelper -Name "Resolve-BootstrapApiUrls"
Import-BootstrapHelper -Name "Assert-Sha256"
Import-BootstrapHelper -Name "Assert-PackageSha256Sums"
Import-BootstrapHelper -Name "Get-RemoteBridgeAttestationEvidence"

Describe "Resolve-BootstrapApiUrls" {
    It "derives test API and mTLS API from a testai package URL" {
        $resolved = Resolve-BootstrapApiUrls `
            -PackageUrl "https://testai.acik.com/artifacts/endpoint-agent/current/EndpointAgent.zip" `
            -ApiUrl "" `
            -AutoEnrollApiUrl "" `
            -ApiUrlExplicit $false `
            -AutoEnrollApiUrlExplicit $false

        $resolved.PackageHost | Should Be "testai.acik.com"
        $resolved.ApiUrl | Should Be "https://testai.acik.com/api/v1/endpoint-agent"
        $resolved.AutoEnrollApiUrl | Should Be "https://mtls.testai.acik.com/api/v1/endpoint-agent"
    }

    It "derives prod API and mTLS API from a prod package URL" {
        $resolved = Resolve-BootstrapApiUrls `
            -PackageUrl "https://ai.acik.com/artifacts/endpoint-agent/current/EndpointAgent.zip" `
            -ApiUrl "" `
            -AutoEnrollApiUrl "" `
            -ApiUrlExplicit $false `
            -AutoEnrollApiUrlExplicit $false

        $resolved.PackageHost | Should Be "ai.acik.com"
        $resolved.ApiUrl | Should Be "https://ai.acik.com/api/v1/endpoint-agent"
        $resolved.AutoEnrollApiUrl | Should Be "https://mtls.ai.acik.com/api/v1/endpoint-agent"
    }

    It "keeps explicit API overrides authoritative" {
        $resolved = Resolve-BootstrapApiUrls `
            -PackageUrl "https://ai.acik.com/artifacts/endpoint-agent/current/EndpointAgent.zip" `
            -ApiUrl "https://override.example/api/v1/endpoint-agent" `
            -AutoEnrollApiUrl "https://override-mtls.example/api/v1/endpoint-agent" `
            -ApiUrlExplicit $true `
            -AutoEnrollApiUrlExplicit $true

        $resolved.ApiUrl | Should Be "https://override.example/api/v1/endpoint-agent"
        $resolved.AutoEnrollApiUrl | Should Be "https://override-mtls.example/api/v1/endpoint-agent"
    }

    It "derives a blank explicit API value rather than passing an empty string" {
        $resolved = Resolve-BootstrapApiUrls `
            -PackageUrl "https://testai.acik.com/artifacts/endpoint-agent/current/EndpointAgent.zip" `
            -ApiUrl " " `
            -AutoEnrollApiUrl " " `
            -ApiUrlExplicit $true `
            -AutoEnrollApiUrlExplicit $true

        $resolved.ApiUrl | Should Be "https://testai.acik.com/api/v1/endpoint-agent"
        $resolved.AutoEnrollApiUrl | Should Be "https://mtls.testai.acik.com/api/v1/endpoint-agent"
    }

    It "rejects package URLs without an absolute host" {
        { Get-PackageUrlHost -Url "EndpointAgent.zip" } |
            Should Throw "-PackageUrl must be an absolute URL with a host."
    }
}

Describe "Get-RemoteBridgeAttestationEvidence" {
    BeforeEach {
        $testDirectory = Join-Path $TestDrive "package"
        Remove-Item -LiteralPath $testDirectory -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $testDirectory | Out-Null
        $evidencePath = Join-Path $testDirectory "remote-bridge-attestation-evidence.b64"
    }

    It "returns trimmed valid standard base64 without logging the payload" {
        Set-Content -LiteralPath $evidencePath -Value "c2lnbmVkLXByb3ZlbmFuY2U=" -Encoding ascii

        Get-RemoteBridgeAttestationEvidence -Directory $testDirectory |
            Should Be "c2lnbmVkLXByb3ZlbmFuY2U="
    }

    It "rejects a missing evidence file" {
        $thrownMessage = ""
        try {
            Get-RemoteBridgeAttestationEvidence -Directory $testDirectory
        } catch {
            $thrownMessage = $_.Exception.Message
        }
        $thrownMessage | Should Match "^signed remote-bridge attestation evidence missing from package:"
    }

    It "rejects blank evidence" {
        Set-Content -LiteralPath $evidencePath -Value "   " -Encoding ascii

        { Get-RemoteBridgeAttestationEvidence -Directory $testDirectory } |
            Should Throw "signed remote-bridge attestation evidence is blank"
    }

    It "rejects malformed standard base64" {
        Set-Content -LiteralPath $evidencePath -Value "not/base64?" -Encoding ascii

        { Get-RemoteBridgeAttestationEvidence -Directory $testDirectory } |
            Should Throw "signed remote-bridge attestation evidence must be valid standard base64"
    }

    It "rejects embedded whitespace" {
        Set-Content -LiteralPath $evidencePath -Value "c2ln bmVk" -Encoding ascii

        { Get-RemoteBridgeAttestationEvidence -Directory $testDirectory } |
            Should Throw "signed remote-bridge attestation evidence must be single-line standard base64"
    }

    It "rejects evidence above the configured agent limit" {
        Set-Content -LiteralPath $evidencePath -Value ("A" * 17) -Encoding ascii

        { Get-RemoteBridgeAttestationEvidence -Directory $testDirectory -MaxBase64Length 16 } |
            Should Throw "signed remote-bridge attestation evidence exceeds 16 characters"
    }
}

Describe "Assert-PackageSha256Sums required-file contract" {
    BeforeEach {
        $testDirectory = Join-Path $TestDrive "hash-package"
        Remove-Item -LiteralPath $testDirectory -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $testDirectory | Out-Null
        $payloadPath = Join-Path $testDirectory "payload.bin"
        Set-Content -LiteralPath $payloadPath -Value "payload" -Encoding ascii
        $payloadHash = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $sumPath = Join-Path $testDirectory "SHA256SUMS"
    }

    It "accepts a required file covered by a valid hash" {
        Set-Content -LiteralPath $sumPath -Value "$payloadHash  payload.bin" -Encoding ascii

        { Assert-PackageSha256Sums -Directory $testDirectory -RequiredFiles @("payload.bin") } |
            Should Not Throw
    }

    It "rejects a required file omitted from SHA256SUMS" {
        Set-Content -LiteralPath $sumPath -Value "$payloadHash  payload.bin" -Encoding ascii

        { Assert-PackageSha256Sums -Directory $testDirectory -RequiredFiles @("attestation.b64") } |
            Should Throw "required package file is not covered by SHA256SUMS: attestation.b64"
    }

    It "rejects duplicate SHA256SUMS entries" {
        @(
            "$payloadHash  payload.bin",
            "$payloadHash  payload.bin"
        ) | Set-Content -LiteralPath $sumPath -Encoding ascii

        { Assert-PackageSha256Sums -Directory $testDirectory } |
            Should Throw "duplicate SHA256SUMS entry: payload.bin"
    }
}
