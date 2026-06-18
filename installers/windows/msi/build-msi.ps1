<#
.SYNOPSIS
  Build the Endpoint Agent MSI (Faz 22.5 M4) from a staged payload. Two modes:
  lab self-signed (non-prod, default) or none (unsigned, for the Linux pipeline).

.DESCRIPTION
  Runs on a Windows host with the WiX v4 dotnet tool. Stages the payload (agent exe
  + install/uninstall/bootstrap/run-agent-install ps1), optionally lab-signs it
  (sign-last), builds the MSI via `wix build`, lab-signs the MSI, then verifies +
  emits a signing-tier manifest. This script NEVER produces a production build.

  SIGNING MODES (-SigningMode):
    lab  (default) — ephemeral self-signed cert, imported to the local trust stores
                     so Authenticode validates Valid. NON-PROD. `production=false`.
    none           — build unsigned. The release pipeline uses this, then signs the
                     built MSI on a self-hosted LINUX runner (osslsigncode + internal
                     OpenSSL CA) and stamps `production=true` only after a windows-
                     hosted `signtool verify /pa` + pinned-root chain gate.
    trusted        — REMOVED (AG-018 Linux pivot, owner: no paid services / no AD CS
                     / no Windows Server). Passing it throws with a pointer to
                     release-msi-signed.yml + scripts/codesign.

  Production signing lives entirely in the Linux pipeline; see
  .github/workflows/release-msi-signed.yml, scripts/codesign/*, and
  docs/22-2-trusted-signing-onboarding.md.

.NOTES
  Codex 019ead14: sign-last (no post-sign mutation; manifest written AFTER signing),
  one manifest for MSI+EXE+PS1. AG-018 (Codex 019eb0dd): in-Windows AD CS signing
  replaced by Linux osslsigncode + internal CA; production=true is stamped only by
  the verify-windows gate, never here.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AgentExe,                       # path to endpoint-agent.exe (release- or lab-built)

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+')]      # first 3 fields drive MSI upgrade semantics
    [string]$Version,                        # e.g. 0.1.1  (MSI ProductVersion)

    [ValidateSet('lab', 'trusted', 'none')]
    [string]$SigningMode = 'lab',

    [string]$InstallersDir = (Split-Path -Parent $PSCommandPath), # installers/windows/msi
    [string]$OutputDir     = (Join-Path (Split-Path -Parent $PSCommandPath) "out"),
    [switch]$NoExeSign,                       # skip exe signing if already release-signed

    # Deprecated back-compat: -SelfSign:$false maps to -SigningMode none.
    [switch]$SelfSign = $true
)

$ErrorActionPreference = "Stop"
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }

# Back-compat: an explicit -SelfSign:$false (old callers) means "no signing".
if ($PSBoundParameters.ContainsKey('SelfSign') -and -not $SelfSign) { $SigningMode = 'none' }

$windowsDir = Split-Path -Parent $InstallersDir        # installers/windows
$msiVersion = ($Version -split '[-+]')[0]               # strip prerelease/build metadata for MSI

# MSI ProductVersion = strictly numeric first three fields.
$parts = $msiVersion -split '\.'
if ($parts.Count -lt 3) { throw "Version '$Version' must have at least 3 numeric fields" }
$msiVersion = ("{0}.{1}.{2}" -f $parts[0], $parts[1], $parts[2])

$tierTag = switch ($SigningMode) { 'lab' { 'lab' } default { 'unsigned' } }
Step "MSI ProductVersion = $msiVersion (from $Version); SigningMode=$SigningMode tierTag=$tierTag"

# ---- trusted signing moved OFF Windows (AG-018 Linux pivot, owner: no paid / no AD CS) ----
# Authenticode signing no longer happens here. The release pipeline builds an
# UNSIGNED MSI on the Windows runner (-SigningMode none) and signs it on a
# self-hosted LINUX runner with osslsigncode + an internal OpenSSL CA, then a
# windows-hosted gate runs `signtool verify /pa` and stamps the production
# manifest. See .github/workflows/release-msi-signed.yml and
# scripts/codesign/*. -SigningMode 'trusted' is therefore REMOVED here.
if ($SigningMode -eq 'trusted') {
    throw "SigningMode 'trusted' (in-Windows AD CS signing) is REMOVED. Signing now runs on the Linux signing runner (release-msi-signed.yml + scripts/codesign). Build with -SigningMode none here; the pipeline signs afterwards."
}

# ---- stage payload ----
$payloadDir = Join-Path $OutputDir "payload"
if (Test-Path $payloadDir) { Remove-Item -Recurse -Force $payloadDir }
New-Item -ItemType Directory -Force -Path $payloadDir | Out-Null

Copy-Item $AgentExe (Join-Path $payloadDir "endpoint-agent.exe") -Force
foreach ($s in @("install.ps1", "uninstall.ps1", "bootstrap-package.ps1")) {
    Copy-Item (Join-Path $windowsDir $s) (Join-Path $payloadDir $s) -Force
}
Copy-Item (Join-Path $InstallersDir "run-agent-install.ps1") (Join-Path $payloadDir "run-agent-install.ps1") -Force

$payloadToSign = @(
    (Join-Path $payloadDir "install.ps1"),
    (Join-Path $payloadDir "uninstall.ps1"),
    (Join-Path $payloadDir "bootstrap-package.ps1"),
    (Join-Path $payloadDir "run-agent-install.ps1")
)
if (-not $NoExeSign) { $payloadToSign += (Join-Path $payloadDir "endpoint-agent.exe") }

# ---- sign payload (BEFORE wix build, since the cab embeds these) ----
$labCert = $null; $labTrusted = $false
if ($SigningMode -eq 'lab') {
    Step "Lab self-sign: provisioning ephemeral code-signing cert"
    $labCert = New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject "CN=Endpoint Agent Lab Signing (NON-PROD)" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable -KeySpec Signature `
        -NotAfter (Get-Date).AddDays(30)
    try {
        $tmpCer = Join-Path $OutputDir "ea-lab-signer.cer"
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
        Export-Certificate -Cert $labCert -FilePath $tmpCer -Force | Out-Null
        Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
        Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
        Remove-Item $tmpCer -Force -ErrorAction SilentlyContinue
        $labTrusted = $true
        Step "lab signer imported into LocalMachine Root + TrustedPublisher"
    } catch {
        Step "WARN: trust-store import failed ($($_.Exception.Message)); lab signature will be untrusted"
    }
    foreach ($f in $payloadToSign) {
        $r = Set-AuthenticodeSignature -FilePath $f -Certificate $labCert -HashAlgorithm SHA256
        Step ("lab-signed {0} -> {1}" -f (Split-Path -Leaf $f), $r.Status)
        if ("$($r.Status)" -notin @('Valid', 'UnknownError')) { throw "sign failed status=$($r.Status) for $f" }
        if ($labTrusted -and $r.Status -ne 'Valid') { throw "lab signer trusted but $f signature $($r.Status)" }
    }
} else {
    Step "SigningMode=none — payload left unsigned (Linux pipeline signs the built MSI)"
}

# ---- build MSI ----
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$msiPath = Join-Path $OutputDir "EndpointAgent-$msiVersion-$tierTag.msi"
$wxs = Join-Path $InstallersDir "EndpointAgent.wxs"

Step "wix build -> $msiPath"
& wix build $wxs `
    -arch x64 `
    -define "ProductVersion=$msiVersion" `
    -define "PayloadDir=$payloadDir" `
    -ext WixToolset.Util.wixext `
    -out $msiPath
if ($LASTEXITCODE -ne 0) { throw "wix build failed (exit $LASTEXITCODE)" }

# ---- sign the MSI (AFTER build) ----
if ($SigningMode -eq 'lab' -and $labCert) {
    $r = Set-AuthenticodeSignature -FilePath $msiPath -Certificate $labCert -HashAlgorithm SHA256
    Step "MSI lab signature -> $($r.Status)"
    if ("$($r.Status)" -notin @('Valid', 'UnknownError')) { throw "MSI signing failed status=$($r.Status)" }
    if ($labTrusted -and $r.Status -ne 'Valid') { throw "lab signer trusted but MSI signature $($r.Status)" }
}

# ---- verify every shipped artifact + collect signature status ----
$allArtifacts = @($msiPath,
                  (Join-Path $payloadDir "endpoint-agent.exe"),
                  (Join-Path $payloadDir "install.ps1"),
                  (Join-Path $payloadDir "uninstall.ps1"),
                  (Join-Path $payloadDir "bootstrap-package.ps1"),
                  (Join-Path $payloadDir "run-agent-install.ps1"))
$sigStatus = @{}
foreach ($f in $allArtifacts) {
    $s = Get-AuthenticodeSignature -FilePath $f
    $sigStatus[(Split-Path -Leaf $f)] = "$($s.Status)"
    Step ("sig {0,-26} -> {1}" -f (Split-Path -Leaf $f), $s.Status)
    if ($SigningMode -eq 'lab') {
        if ("$($s.Status)" -notin @('Valid', 'UnknownError')) { throw "bad signature on $f : $($s.Status)" }
        if ($labTrusted -and "$($s.Status)" -ne 'Valid')       { throw "trusted signer but $f signature $($s.Status)" }
    }
}

# This script never produces a production build: -SigningMode lab is non-prod and
# none is unsigned. The Linux signing pipeline's verify-windows gate is the ONLY
# place that stamps production=true (after signtool /pa + pinned-root chain).
$isProduction = $false
$signingTier  = switch ($SigningMode) { 'lab' { 'lab-self-signed' } default { 'unsigned' } }

# ---- manifest (written AFTER all signing; signed artifacts NOT mutated after) ----
$signerCert = $labCert
$manifest = [ordered]@{
    artifact_kind   = "endpoint-agent-msi"
    signing_tier    = $signingTier
    production      = $isProduction
    trust_scope     = if ($SigningMode -eq 'lab') { 'lab-only' } else { 'unsigned' }
    publicly_trusted = $false
    requires_trusted_publisher_gpo = $false
    product_version = $msiVersion
    source_version  = $Version
    msi_file        = (Split-Path -Leaf $msiPath)
    msi_sha256      = (Get-FileHash $msiPath -Algorithm SHA256).Hash
    built_at_utc    = (Get-Date).ToUniversalTime().ToString("o")
    signer_thumbprint = if ($signerCert) { $signerCert.Thumbprint } else { $null }
    signer_subject  = if ($signerCert) { "$($signerCert.Subject)" } else { $null }
    signer_issuer   = if ($signerCert) { "$($signerCert.Issuer)" } else { $null }
    signer_not_after = if ($signerCert) { $signerCert.NotAfter.ToUniversalTime().ToString("o") } else { $null }
    signatures      = $sigStatus
    timestamp_url   = $null
    timestamped     = $false
    files           = @{}
}
foreach ($f in $allArtifacts) { $manifest.files[(Split-Path -Leaf $f)] = (Get-FileHash $f -Algorithm SHA256).Hash }
$manifestPath = Join-Path $OutputDir "msi-build-manifest.json"
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8

Step "DONE"
Step "  MSI       : $msiPath"
Step "  Manifest  : $manifestPath  (signing_tier=$signingTier, production=$isProduction, trust_scope=$($manifest.trust_scope))"
if ($isProduction) {
    Write-Host "TRUSTED (AD CS, INTERNAL trust) MSI — /pa-verified + RFC3161-timestamped + thumbprint-allowlisted. Public Windows trust is NOT implied; the AD CS root must reach domain machines' Trusted Publisher via GPO. AppLocker/WDAC/EDR preflight + GPO pilot still operator-gated." -ForegroundColor Green
} else {
    Write-Host "NON-PROD artifact (signing_tier=$signingTier). Trusted signing = -SigningMode trusted on the self-hosted AD CS signing runner (docs/22-2-trusted-signing-onboarding.md). Azure Trusted Signing (paid) is EXCLUDED by owner decision." -ForegroundColor Yellow
}
