<#
.SYNOPSIS
  Build the Endpoint Agent MSI (Faz 22.5 M4) from a staged payload, with a tiered
  signing model: lab self-signed (default), Azure Trusted Signing (prod), or none.

.DESCRIPTION
  Runs on a Windows host with the WiX v4 dotnet tool. Stages the payload (agent exe
  + install/uninstall/bootstrap/run-agent-install ps1), signs per -SigningMode AFTER
  any release patching (sign-last), builds the MSI via `wix build`, signs the MSI,
  then verifies + emits a signing-tier manifest.

  SIGNING MODES (-SigningMode):
    lab     (default) — ephemeral self-signed cert, imported to the local trust
                        stores so Authenticode validates Valid. `production=false`.
    trusted (Faz 22.2 / AG-018) — Azure Trusted Signing via signtool /dlib over an
                        active `azure/login@v2` OIDC session. FAIL-CLOSED: throws if
                        any TRUSTED_SIGNING_* env is missing (never ships unsigned as
                        production). Each artifact is signtool-verified with /pa
                        (production trust policy, NO import) AND asserted to carry an
                        RFC3161 timestamp; only then `production=true`.
    none    — build unsigned. `production=false`.

  Trusted mode env (set by the release workflow; NO PFX/secret — only these + the
  azure/login OIDC session):
    TRUSTED_SIGNING_ENDPOINT       e.g. https://eus.codesigning.azure.net/
    TRUSTED_SIGNING_ACCOUNT        Trusted Signing account name
    TRUSTED_SIGNING_CERT_PROFILE   certificate profile name
    TRUSTED_SIGNING_TIMESTAMP_URL  RFC3161 TSA (Azure default TSA is free)
    TRUSTED_SIGNING_DLIB           path to Azure.CodeSigning.Dlib.dll

.NOTES
  Codex 019ead14: sign-last (no post-sign mutation; manifest written AFTER signing),
  one manifest for MSI+EXE+PS1, fail-closed trusted, /pa + timestamp = production gate.
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

# ---- trusted-mode config (fail-closed) ----
$trustedCfg = $null
if ($SigningMode -eq 'trusted') {
    $req = @{
        Endpoint     = $env:TRUSTED_SIGNING_ENDPOINT
        Account      = $env:TRUSTED_SIGNING_ACCOUNT
        CertProfile  = $env:TRUSTED_SIGNING_CERT_PROFILE
        TimestampUrl = $env:TRUSTED_SIGNING_TIMESTAMP_URL
        Dlib         = $env:TRUSTED_SIGNING_DLIB
    }
    $missing = $req.GetEnumerator() | Where-Object { [string]::IsNullOrWhiteSpace($_.Value) } | ForEach-Object { $_.Key }
    if ($missing) {
        throw "trusted signing NOT configured — missing TRUSTED_SIGNING_* for: $($missing -join ', '). " +
              "Complete docs/22-2-trusted-signing-onboarding.md (operator) before a trusted release."
    }
    if (-not (Test-Path -LiteralPath $req.Dlib)) { throw "Azure Trusted Signing dlib not found: $($req.Dlib)" }
    $signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue)?.Source
    if (-not $signtool) {
        $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK signing tools)" }
    $metaJson = Join-Path $OutputDir "trusted-signing-metadata.json"
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    [ordered]@{
        Endpoint               = $req.Endpoint
        CodeSigningAccountName = $req.Account
        CertificateProfileName = $req.CertProfile
    } | ConvertTo-Json | Set-Content -LiteralPath $metaJson -Encoding UTF8
    $trustedCfg = @{ Signtool = $signtool; Dlib = $req.Dlib; Meta = $metaJson; Tsa = $req.TimestampUrl }
    Step "trusted signing configured (endpoint=$($req.Endpoint) account=$($req.Account) profile=$($req.CertProfile))"
}

# Sign + verify ONE artifact via Azure Trusted Signing. Production gate: signtool
# verify /pa (trust policy, no import) MUST pass AND the signature MUST carry an
# RFC3161 timestamp. (Helper boundary so a future swap to azure/trusted-signing-action is local.)
function Invoke-TrustedSign {
    param([string]$File, [hashtable]$Cfg)
    & $Cfg.Signtool sign /v /fd SHA256 /tr $Cfg.Tsa /td SHA256 /dlib $Cfg.Dlib /dmdf $Cfg.Meta $File | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "trusted sign failed (exit $LASTEXITCODE) for $File" }
    $out = (& $Cfg.Signtool verify /pa /v $File 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "signtool verify /pa FAILED for $File`n$out" }
    if ($out -notmatch '(?i)timestamp') { throw "no RFC3161 timestamp in verify output for $File`n$out" }
    Step ("trusted-signed + /pa-verified {0}" -f (Split-Path -Leaf $File))
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
$cert = $null; $labTrusted = $false
if ($SigningMode -eq 'lab') {
    Step "Lab self-sign: provisioning ephemeral code-signing cert"
    $cert = New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject "CN=Endpoint Agent Lab Signing (NON-PROD)" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable -KeySpec Signature `
        -NotAfter (Get-Date).AddDays(30)
    try {
        $tmpCer = Join-Path $OutputDir "ea-lab-signer.cer"
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
        Export-Certificate -Cert $cert -FilePath $tmpCer -Force | Out-Null
        Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
        Import-Certificate -FilePath $tmpCer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
        Remove-Item $tmpCer -Force -ErrorAction SilentlyContinue
        $labTrusted = $true
        Step "lab signer imported into LocalMachine Root + TrustedPublisher"
    } catch {
        Step "WARN: trust-store import failed ($($_.Exception.Message)); lab signature will be untrusted"
    }
    foreach ($f in $payloadToSign) {
        $r = Set-AuthenticodeSignature -FilePath $f -Certificate $cert -HashAlgorithm SHA256
        Step ("lab-signed {0} -> {1}" -f (Split-Path -Leaf $f), $r.Status)
        if ("$($r.Status)" -notin @('Valid', 'UnknownError')) { throw "sign failed status=$($r.Status) for $f" }
        if ($labTrusted -and $r.Status -ne 'Valid') { throw "lab signer trusted but $f signature $($r.Status)" }
    }
} elseif ($SigningMode -eq 'trusted') {
    foreach ($f in $payloadToSign) { Invoke-TrustedSign -File $f -Cfg $trustedCfg }
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
if ($SigningMode -eq 'lab' -and $cert) {
    $r = Set-AuthenticodeSignature -FilePath $msiPath -Certificate $cert -HashAlgorithm SHA256
    Step "MSI lab signature -> $($r.Status)"
    if ("$($r.Status)" -notin @('Valid', 'UnknownError')) { throw "MSI signing failed status=$($r.Status)" }
    if ($labTrusted -and $r.Status -ne 'Valid') { throw "lab signer trusted but MSI signature $($r.Status)" }
} elseif ($SigningMode -eq 'trusted') {
    Invoke-TrustedSign -File $msiPath -Cfg $trustedCfg
}

# ---- verify every shipped artifact + collect signature status ----
$allArtifacts = @($msiPath,
                  (Join-Path $payloadDir "endpoint-agent.exe"),
                  (Join-Path $payloadDir "install.ps1"),
                  (Join-Path $payloadDir "uninstall.ps1"),
                  (Join-Path $payloadDir "bootstrap-package.ps1"),
                  (Join-Path $payloadDir "run-agent-install.ps1"))
$sigStatus = @{}; $thumbprints = @{}
foreach ($f in $allArtifacts) {
    $s = Get-AuthenticodeSignature -FilePath $f
    $sigStatus[(Split-Path -Leaf $f)] = "$($s.Status)"
    if ($s.SignerCertificate) { $thumbprints[(Split-Path -Leaf $f)] = $s.SignerCertificate.Thumbprint }
    Step ("sig {0,-26} -> {1}" -f (Split-Path -Leaf $f), $s.Status)
    if ($SigningMode -eq 'lab') {
        if ("$($s.Status)" -notin @('Valid', 'UnknownError')) { throw "bad signature on $f : $($s.Status)" }
        if ($labTrusted -and "$($s.Status)" -ne 'Valid')       { throw "trusted signer but $f signature $($s.Status)" }
    } elseif ($SigningMode -eq 'trusted') {
        # Authenticode metadata must be Valid (the /pa + timestamp gate already ran in Invoke-TrustedSign).
        if ("$($s.Status)" -ne 'Valid') { throw "trusted artifact $f Authenticode status $($s.Status) (expected Valid)" }
    }
}

# production=true ONLY for a fully verified trusted build (/pa + timestamp passed above).
$isProduction = ($SigningMode -eq 'trusted')
$signingTier  = switch ($SigningMode) { 'lab' { 'lab-self-signed' } 'trusted' { 'trusted-azure' } default { 'unsigned' } }

# ---- manifest (written AFTER all signing; signed artifacts are NOT mutated after this) ----
$manifest = [ordered]@{
    artifact_kind   = "endpoint-agent-msi"
    signing_tier    = $signingTier
    production      = $isProduction
    product_version = $msiVersion
    source_version  = $Version
    built_at_utc    = (Get-Date).ToUniversalTime().ToString("o")
    signer_thumbprint = if ($cert) { $cert.Thumbprint } elseif ($thumbprints[(Split-Path -Leaf $msiPath)]) { $thumbprints[(Split-Path -Leaf $msiPath)] } else { $null }
    signatures      = $sigStatus
    timestamp_url   = if ($SigningMode -eq 'trusted') { $trustedCfg.Tsa } else { $null }
    timestamped     = ($SigningMode -eq 'trusted')
    files           = @{}
}
foreach ($f in $allArtifacts) { $manifest.files[(Split-Path -Leaf $f)] = (Get-FileHash $f -Algorithm SHA256).Hash }
$manifestPath = Join-Path $OutputDir "msi-build-manifest.json"
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8

Step "DONE"
Step "  MSI       : $msiPath"
Step "  Manifest  : $manifestPath  (signing_tier=$signingTier, production=$isProduction)"
if ($isProduction) {
    Write-Host "TRUSTED (production) MSI — Authenticode /pa-verified + RFC3161-timestamped. AppLocker/WDAC/EDR preflight + GPO pilot still operator-gated." -ForegroundColor Green
} else {
    Write-Host "NON-PROD artifact (signing_tier=$signingTier). Trusted signing = -SigningMode trusted with operator Azure infra (docs/22-2-trusted-signing-onboarding.md)." -ForegroundColor Yellow
}
