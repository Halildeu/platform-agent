<#
.SYNOPSIS
Patch the release manifest defaults baked into installers/windows/install.ps1.

.DESCRIPTION
The Faz 22.1.0 release foundation (Codex 019e8284 PARTIAL→AGREE plan) ships
`install.ps1` with four `__INJECTED_*__` sentinel defaults — BinaryUrl,
ExpectedSha256, ExpectedSignerThumbprint, SigningTier, ReleaseTag. This script
substitutes those sentinels with real per-release values produced by
`.github/workflows/release.yml` AFTER the agent binary has been built and
signed (so the hash and signer thumbprint are post-sign). The patched copy is
written to -OutputPath and uploaded as a Release asset; the in-tree
install.ps1 stays sentinel-only.

.PARAMETER InputPath
Source install.ps1 with `__INJECTED_*__` sentinels still in place.

.PARAMETER OutputPath
Destination path for the patched copy. Will be overwritten if it exists.

.PARAMETER BinaryUrl
Fully-qualified GitHub Releases URL of the signed endpoint-agent.exe asset.

.PARAMETER ExpectedSha256
Hex SHA-256 of the SIGNED endpoint-agent.exe (post signtool).

.PARAMETER ExpectedSignerThumbprint
Hex thumbprint of the Authenticode signer certificate (post signtool). For
lab-only-evidence releases this is the ephemeral self-signed cert thumbprint
produced by the release workflow; for trusted releases it is the production
code-signing cert thumbprint.

.PARAMETER SigningTier
Either "lab-only-evidence" (Faz 22.1 lab, ephemeral self-signed) or
"trusted" (Faz 22.2+, Authenticode trusted-signing CA-issued cert).

.PARAMETER ReleaseTag
The release tag (e.g. v0.1.0-lab.1) — embedded for operator visibility and
for the lab guardrail error message.

.EXAMPLE
pwsh scripts/release/patch-installer-manifest.ps1 `
    -InputPath installers/windows/install.ps1 `
    -OutputPath dist/release/install.ps1 `
    -BinaryUrl "https://github.com/Halildeu/platform-agent/releases/download/v0.1.0-lab.1/endpoint-agent.exe" `
    -ExpectedSha256 "ABCDEF..." `
    -ExpectedSignerThumbprint "0123..." `
    -SigningTier "lab-only-evidence" `
    -ReleaseTag "v0.1.0-lab.1"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$InputPath,
    [Parameter(Mandatory)] [string]$OutputPath,
    [Parameter(Mandatory)] [string]$BinaryUrl,
    [Parameter(Mandatory)] [string]$ExpectedSha256,
    [Parameter(Mandatory)] [string]$ExpectedSignerThumbprint,
    [Parameter(Mandatory)]
    [ValidateSet("lab-only-evidence","trusted")]
    [string]$SigningTier,
    [Parameter(Mandatory)] [string]$ReleaseTag
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Sanity: SHA256 must be 64 hex chars; thumbprint must be 40 hex chars
# (SHA-1 thumbprint, the only kind Get-AuthenticodeSignature emits).
# Reject malformed inputs loudly here so the workflow fails BEFORE
# publishing a bogus install.ps1.
if ($ExpectedSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
    throw "ExpectedSha256 must be 64 hex chars; got '$ExpectedSha256'"
}
if ($ExpectedSignerThumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
    throw "ExpectedSignerThumbprint must be 40 hex chars (SHA-1); got '$ExpectedSignerThumbprint'"
}
if ($BinaryUrl -notmatch '^https://github\.com/[^/]+/[^/]+/releases/download/[^/]+/[^/]+\.exe$') {
    throw "BinaryUrl must point to a GitHub Releases asset .exe; got '$BinaryUrl'"
}
if ($ReleaseTag -notmatch '^v\d+\.\d+\.\d+(-lab\.\d+)?$') {
    throw "ReleaseTag must be vMAJ.MIN.PATCH or vMAJ.MIN.PATCH-lab.N; got '$ReleaseTag'"
}

if (-not (Test-Path -LiteralPath $InputPath)) {
    throw "Input install.ps1 not found at '$InputPath'"
}

$content = Get-Content -LiteralPath $InputPath -Raw

# The sentinels must all be present in the un-patched script — if any
# are missing the script was already patched (re-run) or someone edited
# the param block, both of which deserve a loud failure rather than a
# silent partial substitution.
$sentinels = @{
    "__INJECTED_BINARY_URL__"           = $BinaryUrl
    "__INJECTED_EXPECTED_SHA256__"      = $ExpectedSha256.ToUpperInvariant()
    "__INJECTED_EXPECTED_THUMBPRINT__"  = $ExpectedSignerThumbprint.ToUpperInvariant()
    "__INJECTED_SIGNING_TIER__"         = $SigningTier
    "__INJECTED_RELEASE_TAG__"          = $ReleaseTag
}

foreach ($sentinel in $sentinels.Keys) {
    $occurrences = ([regex]::Matches($content, [regex]::Escape($sentinel))).Count
    if ($occurrences -lt 1) {
        throw "sentinel '$sentinel' not present in input — was install.ps1 already patched?"
    }
}

foreach ($pair in $sentinels.GetEnumerator()) {
    $content = $content.Replace($pair.Key, $pair.Value)
}

# Double-check: NO `__INJECTED_*__` substring left in the patched content.
$remaining = [regex]::Matches($content, '__INJECTED_[A-Z_]+__')
if ($remaining.Count -gt 0) {
    $names = ($remaining | ForEach-Object { $_.Value }) -join ", "
    throw "leftover sentinel(s) after patch: $names"
}

# Ensure the OutputPath directory exists.
$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

# Preserve LF line endings and emit UTF-8 with BOM. Windows PowerShell 5.1
# treats UTF-8 without BOM as ANSI on many hosts; the release asset must
# parse correctly on standard Windows 10/11 endpoints without operator-side
# encoding fixes.
$lf = "`n"
$content = $content -replace "`r`n", $lf
[System.IO.File]::WriteAllText($OutputPath, $content, [System.Text.UTF8Encoding]::new($true))

Write-Host "patched installer manifest:"
Write-Host "  release tag       = $ReleaseTag"
Write-Host "  signing tier      = $SigningTier"
Write-Host "  binary url        = $BinaryUrl"
Write-Host "  expected sha256   = $($ExpectedSha256.Substring(0,16))..."
Write-Host "  signer thumbprint = $($ExpectedSignerThumbprint.Substring(0,16))..."
Write-Host "  output            = $OutputPath"
