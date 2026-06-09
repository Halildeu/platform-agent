<#
.SYNOPSIS
  Build the Endpoint Agent MSI (Faz 22.5 M4, lab tier) from a staged payload.

.DESCRIPTION
  Runs on a Windows host with the WiX v4 dotnet tool (`dotnet tool install --global wix`).
  Stages the payload (agent exe + install/uninstall/bootstrap/run-agent-install ps1),
  lab self-signs the scripts (and exe if unsigned) AFTER any release patching, builds
  the MSI via `wix build`, then lab self-signs the MSI. Emits a signing-tier manifest.

  LAB TIER ONLY: self-signed. Prod uses Authenticode trusted-signing (Faz 22.2,
  operator cert) through the same manifest — this script marks the artifact non-prod.

.NOTES
  Codex 019ead14 conditions: sign-last (no post-sign mutation), one manifest for
  MSI+EXE+PS1, MSI version obeys first-3-field semantics (CI guards greater-than).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AgentExe,                       # path to endpoint-agent.exe (release- or lab-built)

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+')]      # first 3 fields drive MSI upgrade semantics
    [string]$Version,                        # e.g. 0.1.1  (MSI ProductVersion)

    [string]$InstallersDir = (Split-Path -Parent $PSCommandPath), # installers/windows/msi
    [string]$OutputDir     = (Join-Path (Split-Path -Parent $PSCommandPath) "out"),
    [switch]$SelfSign      = $true,          # lab tier default
    [switch]$NoExeSign                       # skip exe signing if already release-signed
)

$ErrorActionPreference = "Stop"
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }

$windowsDir = Split-Path -Parent $InstallersDir        # installers/windows
$msiVersion = ($Version -split '[-+]')[0]               # strip prerelease/build metadata for MSI

# MSI ProductVersion = strictly numeric first three fields.
$parts = $msiVersion -split '\.'
if ($parts.Count -lt 3) { throw "Version '$Version' must have at least 3 numeric fields" }
$msiVersion = ("{0}.{1}.{2}" -f $parts[0], $parts[1], $parts[2])

Step "MSI ProductVersion = $msiVersion (from $Version)"

# ---- stage payload ----
$payloadDir = Join-Path $OutputDir "payload"
if (Test-Path $payloadDir) { Remove-Item -Recurse -Force $payloadDir }
New-Item -ItemType Directory -Force -Path $payloadDir | Out-Null

Copy-Item $AgentExe (Join-Path $payloadDir "endpoint-agent.exe") -Force
foreach ($s in @("install.ps1", "uninstall.ps1", "bootstrap-package.ps1")) {
    Copy-Item (Join-Path $windowsDir $s) (Join-Path $payloadDir $s) -Force
}
Copy-Item (Join-Path $InstallersDir "run-agent-install.ps1") (Join-Path $payloadDir "run-agent-install.ps1") -Force

# ---- lab self-sign (AFTER staging/patching; sign-last) ----
$cert = $null
if ($SelfSign) {
    Step "Lab self-sign: provisioning ephemeral code-signing cert"
    $cert = New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject "CN=Endpoint Agent Lab Signing (NON-PROD)" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable -KeySpec Signature `
        -NotAfter (Get-Date).AddDays(30)

    # Import the PUBLIC cert into the machine Trusted Root + Trusted Publisher
    # stores so the lab signature validates to 'Valid' AND the signed scripts are
    # actually trusted on this box (AppLocker/WDAC realism). Needs admin (CI
    # runner + SYSTEM smoke both qualify); if import fails we accept the
    # signed-but-untrusted state for the lab tier rather than hard-fail.
    $trusted = $false
    try {
        $tmpCer = Join-Path $OutputDir "ea-lab-signer.cer"
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
        Export-Certificate -Cert $cert -FilePath $tmpCer -Force | Out-Null
        Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
        Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
        Remove-Item $tmpCer -Force -ErrorAction SilentlyContinue
        $trusted = $true
        Step "lab signer imported into LocalMachine Root + TrustedPublisher"
    } catch {
        Step "WARN: trust-store import failed ($($_.Exception.Message)); lab signature will be untrusted"
    }

    $toSign = @(
        (Join-Path $payloadDir "install.ps1"),
        (Join-Path $payloadDir "uninstall.ps1"),
        (Join-Path $payloadDir "bootstrap-package.ps1"),
        (Join-Path $payloadDir "run-agent-install.ps1")
    )
    if (-not $NoExeSign) { $toSign += (Join-Path $payloadDir "endpoint-agent.exe") }
    foreach ($f in $toSign) {
        $r = Set-AuthenticodeSignature -FilePath $f -Certificate $cert -HashAlgorithm SHA256
        Step ("signed {0} -> {1}" -f (Split-Path -Leaf $f), $r.Status)
        # Trusted import => 'Valid'. Without trust => 'UnknownError' (signed but
        # chain not trusted) is acceptable for the lab tier; anything else fails.
        $ok = @('Valid', 'UnknownError')
        if ($r.Status -notin $ok) { throw "sign failed status=$($r.Status) for $f" }
        if ($trusted -and $r.Status -ne 'Valid') {
            throw "lab signer was trusted but signature still $($r.Status) for $f"
        }
    }
}

# ---- build MSI ----
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$msiPath = Join-Path $OutputDir "EndpointAgent-$msiVersion-lab.msi"
$wxs = Join-Path $InstallersDir "EndpointAgent.wxs"

Step "wix build -> $msiPath"
& wix build $wxs `
    -arch x64 `
    -define "ProductVersion=$msiVersion" `
    -define "PayloadDir=$payloadDir" `
    -ext WixToolset.Util.wixext `
    -out $msiPath
if ($LASTEXITCODE -ne 0) { throw "wix build failed (exit $LASTEXITCODE)" }

# ---- lab-sign the MSI ----
if ($SelfSign -and $cert) {
    Step "Lab self-sign MSI"
    $r = Set-AuthenticodeSignature -FilePath $msiPath -Certificate $cert -HashAlgorithm SHA256
    Step "MSI signature -> $($r.Status)"
}

# ---- manifest (one manifest: MSI + EXE + PS1, lab tier) ----
$manifest = [ordered]@{
    artifact_kind = "endpoint-agent-msi"
    signing_tier  = if ($SelfSign) { "lab-self-signed" } else { "unsigned" }
    production    = $false
    product_version = $msiVersion
    source_version  = $Version
    built_at_utc  = (Get-Date).ToUniversalTime().ToString("o")
    files = @{}
}
foreach ($f in @($msiPath, (Join-Path $payloadDir "endpoint-agent.exe"),
                  (Join-Path $payloadDir "install.ps1"),
                  (Join-Path $payloadDir "uninstall.ps1"),
                  (Join-Path $payloadDir "bootstrap-package.ps1"),
                  (Join-Path $payloadDir "run-agent-install.ps1"))) {
    $manifest.files[(Split-Path -Leaf $f)] = (Get-FileHash $f -Algorithm SHA256).Hash
}
$manifestPath = Join-Path $OutputDir "msi-build-manifest.json"
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8

Step "DONE"
Step "  MSI       : $msiPath"
Step "  Manifest  : $manifestPath  (signing_tier=$($manifest.signing_tier), production=false)"
Write-Host "LAB-ONLY / NON-PROD artifact. Prod requires Authenticode trusted-signing + AppLocker/WDAC preflight + GPO domain pilot." -ForegroundColor Yellow
