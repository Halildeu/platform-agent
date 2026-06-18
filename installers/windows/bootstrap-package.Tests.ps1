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
