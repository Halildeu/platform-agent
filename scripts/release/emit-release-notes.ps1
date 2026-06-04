<#
.SYNOPSIS
Emit the GitHub Release notes markdown for a platform-agent release.

.DESCRIPTION
Faz 22.1.0 release foundation (Codex 019e8284 PARTIAL→AGREE plan). Extracted
from the `release.yml` inline `run: |` step: a PowerShell double-quoted
here-string (`@"` … `"@`) REQUIRES its terminator `"@` to sit at column 0 with
no leading whitespace, which is fundamentally incompatible with a YAML block
scalar (`run: |`) whose body must stay indented under the step. Inlining the
here-string made `release.yml` an invalid workflow file ("expected a comment or
a line break, but found '*'" at the `> **Signing tier**` line), so GitHub failed
the workflow at validation time on every push. A standalone .ps1 sidesteps the
conflict — here-strings are valid here — and the workflow just invokes this
script (mirrors the sibling `patch-installer-manifest.ps1` pattern).

Inputs are read from the environment (set by the workflow step) and validated
fail-closed before the notes are rendered.

.PARAMETER OutFile
Destination path for the rendered RELEASE_NOTES.md. Parent directory is created
if missing. Defaults to dist/RELEASE_NOTES.md.

.NOTES
Required environment variables:
  TAG    — release tag (e.g. v0.1.0-lab.1)
  TIER   — signing tier (lab-only-evidence | trusted)
  SHA256 — post-sign endpoint-agent.exe hash
  REPO   — github.repository (owner/name); passed via env because GitHub Actions
           `${{ }}` expressions are NOT expanded inside checked-out files.
#>
[CmdletBinding()]
param(
    [string]$OutFile = "dist/RELEASE_NOTES.md"
)

$ErrorActionPreference = "Stop"

foreach ($required in @("TAG", "TIER", "SHA256", "REPO")) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($required))) {
        throw "emit-release-notes.ps1: required environment variable '$required' is empty."
    }
}

$notes = @"
# platform-agent $env:TAG

> **Signing tier**: ``$env:TIER`` — lab-only-evidence releases use an ephemeral self-signed certificate generated on the release runner. They are **not** trusted by Windows out of the box; the install path requires explicit ``-AcceptLabOnlySigning`` opt-in. **Do not install on production endpoints**. Trusted-signing releases (``v*.*.*`` without ``-lab.N``) are parked until Faz 22.2 Azure Trusted Signing.

## One-line lab install

``````powershell
& ([scriptblock]::Create((iwr -useb "https://github.com/$env:REPO/releases/download/$env:TAG/install.ps1").Content)) ``
    -ApiUrl "https://api.acik.com" ``
    -EnrollmentToken `$env:ENROLLMENT_TOKEN ``
    -AcceptLabOnlySigning ``
    -Start
``````

## Artifacts

| Asset | SHA-256 |
|---|---|
| ``endpoint-agent.exe`` | ``$env:SHA256`` |

The ``SHA256SUMS`` and ``release-manifest.json`` assets carry the full set of post-sign hashes for audit. The installer itself embeds the same ``ExpectedSha256`` and ``ExpectedSignerThumbprint`` as its defaults, so a tampered ``install.ps1`` cannot point the operator at a different binary without the operator overriding the values on the command line.

Tracked-by: platform-k8s-gitops Faz 22.5 §3 — agent distribution.
"@

$dir = Split-Path -Parent $OutFile
if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

$notes | Out-File -Encoding utf8 $OutFile
Write-Host "emit-release-notes.ps1: wrote release notes for $env:TAG to $OutFile"
