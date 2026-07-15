<#
.SYNOPSIS
Downloads, verifies, extracts, and installs the Endpoint Agent ZIP package.

.DESCRIPTION
This is the operator-facing standard-PC bootstrap path for pilot ZIP artifacts.
It avoids manual ZIP transfer, manual extraction, and ad-hoc hash commands. The
script never prints the enrollment token; when omitted it prompts with
Read-Host -AsSecureString.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$PackageUrl,
    [Parameter(Mandatory)] [string]$ExpectedZipSha256,
    [string]$ApiUrl = "",
    [switch]$AutoEnroll,
    [string]$AutoEnrollApiUrl = "",
    [string]$AutoEnrollCertSubjectSuffix = "",
    [string]$AutoEnrollCertSANURIPrefix = "adcomputer:",
    [int]$AutoEnrollJitterSeconds = 0,
    [switch]$RemoteBridgeEnabled,
    [string]$RemoteBridgeBrokerAddr = "",
    [switch]$RemoteBridgeInsecurePlaintext,
    [string]$WorkDir = (Join-Path $env:TEMP "EndpointEnes"),
    [string]$ZipPath = (Join-Path $env:TEMP "EndpointAgent.zip"),
    [string]$EnrollmentToken = "",
    [switch]$Start,
    [switch]$Force,
    [switch]$ResetCredentialStore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "[endpoint-agent-bootstrap] $Message"
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator PowerShell is required."
    }
}

function Assert-Sha256 {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Expected
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "file not found: $Path"
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA256 mismatch for $Path. Expected=$Expected Actual=$actual"
    }
}

function Get-PackageUrlHost {
    param([Parameter(Mandatory)] [string]$Url)

    $uri = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::RelativeOrAbsolute, [ref]$uri)) {
        throw "invalid -PackageUrl: $Url"
    }

    if (-not $uri.IsAbsoluteUri -or [string]::IsNullOrWhiteSpace($uri.Host)) {
        throw "-PackageUrl must be an absolute URL with a host."
    }

    return $uri.Host.ToLowerInvariant()
}

function Resolve-BootstrapApiUrls {
    param(
        [Parameter(Mandatory)] [string]$PackageUrl,
        [string]$ApiUrl,
        [string]$AutoEnrollApiUrl,
        [bool]$ApiUrlExplicit,
        [bool]$AutoEnrollApiUrlExplicit
    )

    $hostName = Get-PackageUrlHost -Url $PackageUrl
    $resolvedApiUrl = $ApiUrl
    $resolvedAutoEnrollApiUrl = $AutoEnrollApiUrl

    if ((-not $ApiUrlExplicit) -or [string]::IsNullOrWhiteSpace($resolvedApiUrl)) {
        $resolvedApiUrl = "https://$hostName/api/v1/endpoint-agent"
    }

    if ((-not $AutoEnrollApiUrlExplicit) -or [string]::IsNullOrWhiteSpace($resolvedAutoEnrollApiUrl)) {
        $resolvedAutoEnrollApiUrl = "https://mtls.$hostName/api/v1/endpoint-agent"
    }

    return [PSCustomObject]@{
        PackageHost = $hostName
        ApiUrl = $resolvedApiUrl
        AutoEnrollApiUrl = $resolvedAutoEnrollApiUrl
    }
}

function Assert-PackageSha256Sums {
    param(
        [Parameter(Mandatory)] [string]$Directory,
        [string[]]$RequiredFiles = @()
    )
    $sumPath = Join-Path $Directory "SHA256SUMS"
    if (-not (Test-Path -LiteralPath $sumPath)) {
        throw "SHA256SUMS missing from package: $sumPath"
    }

    $listedFiles = @{}
    foreach ($line in Get-Content -LiteralPath $sumPath) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }
        $parts = $trimmed -split "\s+", 2
        if ($parts.Count -ne 2) {
            throw "invalid SHA256SUMS line: $trimmed"
        }
        $expected = $parts[0].ToLowerInvariant()
        $name = $parts[1].Trim()
        if ($name.StartsWith("*")) {
            $name = $name.Substring(1)
        }
        if ($name.Contains("..") -or [System.IO.Path]::IsPathRooted($name)) {
            throw "unsafe SHA256SUMS path: $name"
        }
        if ($listedFiles.ContainsKey($name)) {
            throw "duplicate SHA256SUMS entry: $name"
        }
        $listedFiles[$name] = $true
        Assert-Sha256 -Path (Join-Path $Directory $name) -Expected $expected
    }

    foreach ($requiredFile in $RequiredFiles) {
        if (-not $listedFiles.ContainsKey($requiredFile)) {
            throw "required package file is not covered by SHA256SUMS: $requiredFile"
        }
    }
}

function Get-RemoteBridgeAttestationEvidence {
    param(
        [Parameter(Mandatory)] [string]$Directory,
        [int]$MaxBase64Length = (16 * 1024)
    )

    $evidencePath = Join-Path $Directory "remote-bridge-attestation-evidence.b64"
    if (-not (Test-Path -LiteralPath $evidencePath)) {
        throw "signed remote-bridge attestation evidence missing from package: $evidencePath"
    }

    $evidence = (Get-Content -LiteralPath $evidencePath -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($evidence)) {
        throw "signed remote-bridge attestation evidence is blank"
    }
    if ($evidence.Length -gt $MaxBase64Length) {
        throw "signed remote-bridge attestation evidence exceeds $MaxBase64Length characters"
    }
    if ([regex]::IsMatch($evidence, "\s")) {
        throw "signed remote-bridge attestation evidence must be single-line standard base64"
    }

    try {
        $decoded = [Convert]::FromBase64String($evidence)
    } catch {
        throw "signed remote-bridge attestation evidence must be valid standard base64"
    }
    if ($decoded.Length -eq 0) {
        throw "signed remote-bridge attestation evidence decodes to an empty payload"
    }

    return $evidence
}

function Get-EnrollmentToken {
    param([string]$Token)
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        return $Token
    }
    Write-Step "paste one-time enrollment token; input is hidden"
    $secure = Read-Host "Enrollment token" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

Assert-Administrator

$resolvedUrls = Resolve-BootstrapApiUrls `
    -PackageUrl $PackageUrl `
    -ApiUrl $ApiUrl `
    -AutoEnrollApiUrl $AutoEnrollApiUrl `
    -ApiUrlExplicit $PSBoundParameters.ContainsKey("ApiUrl") `
    -AutoEnrollApiUrlExplicit $PSBoundParameters.ContainsKey("AutoEnrollApiUrl")
$ApiUrl = $resolvedUrls.ApiUrl
$AutoEnrollApiUrl = $resolvedUrls.AutoEnrollApiUrl

Write-Step "preparing work directory: $WorkDir"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue

Write-Step "downloading package"
Invoke-WebRequest -UseBasicParsing -Uri $PackageUrl -OutFile $ZipPath

Write-Step "verifying package SHA256"
Assert-Sha256 -Path $ZipPath -Expected $ExpectedZipSha256

Write-Step "extracting package"
Expand-Archive -LiteralPath $ZipPath -DestinationPath $WorkDir -Force

Write-Step "verifying package file hashes"
$requiredPackageFiles = @(
    "endpoint-agent.exe",
    "bootstrap-package.ps1",
    "install.ps1",
    "uninstall.ps1",
    "README.md"
)
if ($RemoteBridgeEnabled) {
    $requiredPackageFiles += "remote-bridge-attestation-evidence.b64"
    $requiredPackageFiles += "remote-bridge-attestation-evidence-summary.json"
}
Assert-PackageSha256Sums -Directory $WorkDir -RequiredFiles $requiredPackageFiles

$installScript = Join-Path $WorkDir "install.ps1"
if (-not (Test-Path -LiteralPath $installScript)) {
    throw "install.ps1 missing after extraction: $installScript"
}

if ($AutoEnroll -and -not [string]::IsNullOrWhiteSpace($EnrollmentToken)) {
    throw "-AutoEnroll is mutually exclusive with -EnrollmentToken."
}
if ($AutoEnroll -and $ResetCredentialStore) {
    throw "-ResetCredentialStore is only valid for the HMAC enrollment-token fallback path."
}
if ($RemoteBridgeEnabled) {
    if ([string]::IsNullOrWhiteSpace($RemoteBridgeBrokerAddr)) {
        throw "-RemoteBridgeEnabled requires -RemoteBridgeBrokerAddr."
    }
    $remoteBridgeAttestationEvidence = Get-RemoteBridgeAttestationEvidence -Directory $WorkDir
} else {
    if (-not [string]::IsNullOrWhiteSpace($RemoteBridgeBrokerAddr)) {
        throw "-RemoteBridgeBrokerAddr requires -RemoteBridgeEnabled."
    }
    if ($RemoteBridgeInsecurePlaintext) {
        throw "-RemoteBridgeInsecurePlaintext requires -RemoteBridgeEnabled."
    }
}

$installArgs = @{}
if ($AutoEnroll) {
    $installArgs["AutoEnroll"] = $true
    $installArgs["AutoEnrollApiUrl"] = $AutoEnrollApiUrl
    $installArgs["AutoEnrollCertSubjectSuffix"] = $AutoEnrollCertSubjectSuffix
    $installArgs["AutoEnrollCertSANURIPrefix"] = $AutoEnrollCertSANURIPrefix
    $installArgs["AutoEnrollJitterSeconds"] = $AutoEnrollJitterSeconds
} else {
    $token = Get-EnrollmentToken -Token $EnrollmentToken
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw "Enrollment token is blank."
    }
    $installArgs["ApiUrl"] = $ApiUrl
    $installArgs["EnrollmentToken"] = $token
}
if ($Start) {
    $installArgs["Start"] = $true
}
if ($Force) {
    $installArgs["Force"] = $true
}
if ($ResetCredentialStore) {
    $installArgs["ResetCredentialStore"] = $true
}
if ($RemoteBridgeEnabled) {
    $installArgs["RemoteBridgeEnabled"] = $true
    $installArgs["RemoteBridgeBrokerAddr"] = $RemoteBridgeBrokerAddr
    $installArgs["RemoteBridgeAttestationEvidenceB64"] = $remoteBridgeAttestationEvidence
    if ($RemoteBridgeInsecurePlaintext) {
        $installArgs["RemoteBridgeInsecurePlaintext"] = $true
    }
}

try {
    Write-Step "running installer"
    & $installScript @installArgs
} finally {
    if (Get-Variable token -ErrorAction SilentlyContinue) {
        Remove-Variable token -ErrorAction SilentlyContinue
    }
    Remove-Variable EnrollmentToken -ErrorAction SilentlyContinue
    Remove-Variable remoteBridgeAttestationEvidence -ErrorAction SilentlyContinue
    Remove-Variable installArgs -ErrorAction SilentlyContinue
}

Write-Step "service state"
Get-CimInstance Win32_Service |
    Where-Object { $_.Name -eq "EndpointAgent" } |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
    Format-List

Write-Step "recent logs"
Get-Content "C:\ProgramData\EndpointAgent\logs\*.log" -Tail 80 -ErrorAction SilentlyContinue
