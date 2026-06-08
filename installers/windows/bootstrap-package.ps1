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
    [string]$ApiUrl = "https://testai.acik.com/api/v1/endpoint-agent",
    [switch]$AutoEnroll,
    [string]$AutoEnrollApiUrl = "https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent",
    [string]$AutoEnrollCertSubjectSuffix = "",
    [string]$AutoEnrollCertSANURIPrefix = "adcomputer:",
    [int]$AutoEnrollJitterSeconds = 0,
    [string]$WorkDir = (Join-Path $env:TEMP "EndpointEnes"),
    [string]$ZipPath = (Join-Path $env:TEMP "EndpointAgent.zip"),
    [string]$EnrollmentToken = "",
    [switch]$Start,
    [switch]$Force
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

function Assert-PackageSha256Sums {
    param([Parameter(Mandatory)] [string]$Directory)
    $sumPath = Join-Path $Directory "SHA256SUMS"
    if (-not (Test-Path -LiteralPath $sumPath)) {
        throw "SHA256SUMS missing from package: $sumPath"
    }

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
        Assert-Sha256 -Path (Join-Path $Directory $name) -Expected $expected
    }
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
Assert-PackageSha256Sums -Directory $WorkDir

$installScript = Join-Path $WorkDir "install.ps1"
if (-not (Test-Path -LiteralPath $installScript)) {
    throw "install.ps1 missing after extraction: $installScript"
}

if ($AutoEnroll -and -not [string]::IsNullOrWhiteSpace($EnrollmentToken)) {
    throw "-AutoEnroll is mutually exclusive with -EnrollmentToken."
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

try {
    Write-Step "running installer"
    & $installScript @installArgs
} finally {
    if (Get-Variable token -ErrorAction SilentlyContinue) {
        Remove-Variable token -ErrorAction SilentlyContinue
    }
    Remove-Variable EnrollmentToken -ErrorAction SilentlyContinue
}

Write-Step "service state"
Get-CimInstance Win32_Service |
    Where-Object { $_.Name -eq "EndpointAgent" } |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
    Format-List

Write-Step "recent logs"
Get-Content "C:\ProgramData\EndpointAgent\logs\*.log" -Tail 80 -ErrorAction SilentlyContinue
