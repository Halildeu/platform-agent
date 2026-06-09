<#
.SYNOPSIS
  Build the Endpoint Agent MSI (Faz 22.5 M4) from a staged payload, with a tiered
  signing model: lab self-signed (default), AD CS internal trusted (prod), or none.

.DESCRIPTION
  Runs on a Windows host with the WiX v4 dotnet tool. Stages the payload (agent exe
  + install/uninstall/bootstrap/run-agent-install ps1), signs per -SigningMode AFTER
  any release patching (sign-last), builds the MSI via `wix build`, signs the MSI,
  then verifies + emits a signing-tier manifest.

  SIGNING MODES (-SigningMode):
    lab     (default) — ephemeral self-signed cert, imported to the local trust
                        stores so Authenticode validates Valid. `production=false`.
    trusted (Faz 22.2 / AG-018) — AD CS internal code-signing cert (Windows Server
                        Enterprise CA, FREE; ADR-0029) on a self-hosted signing
                        runner whose LocalMachine\My store holds the cert + private
                        key (PFX-in-GitHub FORBIDDEN). FAIL-CLOSED: throws if any
                        ADCS_* env is missing. The cert is PRE-FLIGHTED before
                        signing (private key, validity, Code-Signing EKU, thumbprint
                        allowlist, chain). Each artifact is signtool-verified with
                        /pa (production trust policy, NO import) + RFC3161 timestamp
                        + signer thumbprint allowlist; only then `production=true`.
                        Trust is INTERNAL/AD-domain (not public Windows trust) — the
                        AD CS root is distributed to domain machines' Trusted
                        Publisher via GPO (free). Azure Trusted Signing (paid) is
                        EXCLUDED by owner decision; see docs/22-2-trusted-signing-onboarding.md.
    none    — build unsigned. `production=false`.

  Trusted (AD CS) mode env (set by the self-hosted release-msi-adcs workflow; NO
  PFX/secret — the cert lives in the runner's machine store):
    ADCS_SIGNING_CERT_THUMBPRINT   preferred — exact signer (signtool /sha1)
    ADCS_SIGNING_CERT_SUBJECT      fallback CN (UNIQUE match only; the release-msi-adcs
                                   workflow uses thumbprint — subject is for local/manual debug)
    ADCS_THUMBPRINT_ALLOWLIST      CSV of allowed signer thumbprints (required)
    ADCS_TIMESTAMP_URL             RFC3161 TSA (required; free public option:
                                   http://timestamp.digicert.com)

.NOTES
  Codex 019ead14: sign-last (no post-sign mutation; manifest written AFTER signing),
  one manifest for MSI+EXE+PS1, fail-closed trusted, cert preflight BEFORE signing,
  /pa + timestamp + thumbprint allowlist = production gate, internal trust scope.
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

$tierTag = switch ($SigningMode) { 'lab' { 'lab' } 'trusted' { 'signed' } default { 'unsigned' } }
Step "MSI ProductVersion = $msiVersion (from $Version); SigningMode=$SigningMode tierTag=$tierTag"

$CODE_SIGNING_EKU = '1.3.6.1.5.5.7.3.3'

# Resolve + PRE-FLIGHT the AD CS signing cert BEFORE any signing (Codex: don't sign
# with a wrong cert then fail). Returns the validated X509Certificate2.
function Resolve-AdcsSigningCert {
    param([string]$Thumbprint, [string]$Subject, [string[]]$Allowlist)
    $candidates = @()
    if ($Thumbprint) {
        $tp = ($Thumbprint -replace '\s', '').ToUpperInvariant()
        $candidates = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $tp })
        if ($candidates.Count -ne 1) { throw "ADCS: exactly one LocalMachine\My cert must match thumbprint $tp (found $($candidates.Count))" }
    } else {
        $candidates = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$Subject*" })
        if ($candidates.Count -ne 1) { throw "ADCS: subject '$Subject' must match EXACTLY ONE LocalMachine\My cert (found $($candidates.Count)); use ADCS_SIGNING_CERT_THUMBPRINT" }
    }
    $c = $candidates[0]
    if (-not $c.HasPrivateKey)                       { throw "ADCS: signer cert has no private key ($($c.Thumbprint))" }
    if ($c.NotAfter -lt (Get-Date))                  { throw "ADCS: signer cert expired $($c.NotAfter) ($($c.Thumbprint))" }
    if ($c.NotBefore -gt (Get-Date))                 { throw "ADCS: signer cert not yet valid $($c.NotBefore)" }
    # Code Signing EKU REQUIRED — an EKU-less ("any purpose") cert must NOT pass.
    $ekuExt = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
    if (-not $ekuExt) { throw "ADCS: signer cert has no EKU extension; Code Signing EKU ($CODE_SIGNING_EKU) is required" }
    $ekuOids = @($ekuExt.EnhancedKeyUsages | ForEach-Object { $_.Value })
    if ($ekuOids -notcontains $CODE_SIGNING_EKU) { throw "ADCS: signer cert EKU lacks Code Signing ($CODE_SIGNING_EKU); has: $($ekuOids -join ',')" }
    if ($Allowlist -and ($Allowlist -notcontains $c.Thumbprint.ToUpperInvariant())) {
        throw "ADCS: signer thumbprint $($c.Thumbprint) NOT in ADCS_THUMBPRINT_ALLOWLIST"
    }
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    if (-not $chain.Build($c)) { throw "ADCS: signer cert chain does not build: $(($chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() }) -join '; ')" }
    Step "ADCS preflight OK: thumbprint=$($c.Thumbprint) subject='$($c.Subject)' issuer='$($c.Issuer)' notAfter=$($c.NotAfter)"
    return $c
}

# ---- trusted-mode config (fail-closed) ----
$adcs = $null
if ($SigningMode -eq 'trusted') {
    $tp   = $env:ADCS_SIGNING_CERT_THUMBPRINT
    $subj = $env:ADCS_SIGNING_CERT_SUBJECT
    $tsa  = $env:ADCS_TIMESTAMP_URL
    $allowRaw = $env:ADCS_THUMBPRINT_ALLOWLIST
    if ([string]::IsNullOrWhiteSpace($tp) -and [string]::IsNullOrWhiteSpace($subj)) {
        throw "trusted (AD CS) NOT configured — set ADCS_SIGNING_CERT_THUMBPRINT (preferred) or ADCS_SIGNING_CERT_SUBJECT. See docs/22-2-trusted-signing-onboarding.md."
    }
    if ([string]::IsNullOrWhiteSpace($allowRaw)) { throw "trusted (AD CS) NOT configured — ADCS_THUMBPRINT_ALLOWLIST required" }
    if ([string]::IsNullOrWhiteSpace($tsa))      { throw "trusted (AD CS) NOT configured — ADCS_TIMESTAMP_URL required (e.g. http://timestamp.digicert.com)" }
    $allow = @($allowRaw -split '[,; ]+' | Where-Object { $_ } | ForEach-Object { ($_ -replace '\s', '').ToUpperInvariant() })
    $signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue)?.Source
    if (-not $signtool) {
        $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK signing tools on the self-hosted runner)" }
    $cert = Resolve-AdcsSigningCert -Thumbprint $tp -Subject $subj -Allowlist $allow
    $adcs = @{ Signtool = $signtool; Thumbprint = $cert.Thumbprint; Tsa = $tsa; Allow = $allow; Cert = $cert }
}

# Sign + verify ONE artifact via the AD CS cert. Production gate: signtool verify /pa
# (no import) + RFC3161 timestamp + signer thumbprint in the allowlist.
function Invoke-AdcsSign {
    param([string]$File, [hashtable]$Cfg)
    & $Cfg.Signtool sign /v /sm /sha1 $Cfg.Thumbprint /fd SHA256 /tr $Cfg.Tsa /td SHA256 $File | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "AD CS sign failed (exit $LASTEXITCODE) for $File" }
    $out = (& $Cfg.Signtool verify /pa /v $File 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "signtool verify /pa FAILED for $File`n$out" }
    if ($out -match '(?i)\b(not timestamped|no timestamp)\b') { throw "signature is NOT timestamped for $File`n$out" }
    if ($out -notmatch '(?im)^\s*(The signature is timestamped:|Timestamp Verified by:)') { throw "no positive RFC3161 timestamp evidence for $File`n$out" }
    $auth = Get-AuthenticodeSignature -FilePath $File
    if (-not $auth.TimeStamperCertificate) { throw "no timestamper certificate on $File" }
    if (-not $auth.SignerCertificate -or ($Cfg.Allow -notcontains $auth.SignerCertificate.Thumbprint.ToUpperInvariant())) {
        throw "signer thumbprint $($auth.SignerCertificate.Thumbprint) NOT in allowlist for $File"
    }
    Step ("AD CS-signed + /pa-verified + timestamped {0}" -f (Split-Path -Leaf $File))
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
} elseif ($SigningMode -eq 'trusted') {
    foreach ($f in $payloadToSign) { Invoke-AdcsSign -File $f -Cfg $adcs }
} else {
    Step "SigningMode=none — payload left unsigned"
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
} elseif ($SigningMode -eq 'trusted') {
    Invoke-AdcsSign -File $msiPath -Cfg $adcs
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
    } elseif ($SigningMode -eq 'trusted') {
        if ("$($s.Status)" -ne 'Valid') { throw "trusted artifact $f Authenticode status $($s.Status) (expected Valid on the signing runner)" }
    }
}

# production=true ONLY for a fully verified AD CS trusted build.
$isProduction = ($SigningMode -eq 'trusted')
$signingTier  = switch ($SigningMode) { 'lab' { 'lab-self-signed' } 'trusted' { 'trusted-adcs' } default { 'unsigned' } }

# ---- manifest (written AFTER all signing; signed artifacts NOT mutated after) ----
$signerCert = if ($SigningMode -eq 'trusted') { $adcs.Cert } else { $labCert }
$manifest = [ordered]@{
    artifact_kind   = "endpoint-agent-msi"
    signing_tier    = $signingTier
    production      = $isProduction
    # AD CS = internal/AD-domain trust, NOT public Windows trust (Codex). The AD CS
    # root must be distributed to domain machines' Trusted Publisher via GPO (free).
    trust_scope     = if ($SigningMode -eq 'trusted') { 'internal-ad-domain' } else { 'lab-only' }
    publicly_trusted = $false
    requires_trusted_publisher_gpo = ($SigningMode -eq 'trusted')
    product_version = $msiVersion
    source_version  = $Version
    built_at_utc    = (Get-Date).ToUniversalTime().ToString("o")
    signer_thumbprint = if ($signerCert) { $signerCert.Thumbprint } else { $null }
    signer_subject  = if ($signerCert) { "$($signerCert.Subject)" } else { $null }
    signer_issuer   = if ($signerCert) { "$($signerCert.Issuer)" } else { $null }
    signer_not_after = if ($signerCert) { $signerCert.NotAfter.ToUniversalTime().ToString("o") } else { $null }
    signatures      = $sigStatus
    timestamp_url   = if ($SigningMode -eq 'trusted') { $adcs.Tsa } else { $null }
    timestamped     = ($SigningMode -eq 'trusted')
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
