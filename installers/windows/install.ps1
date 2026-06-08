<# 
.SYNOPSIS
Installs Endpoint Agent as a Windows service.

.DESCRIPTION
Copies endpoint-agent.exe to Program Files, writes machine-level configuration,
creates the Windows service, and optionally starts it. The script avoids printing
secret values and rolls back service/config changes if installation fails.
#>

[CmdletBinding()]
param(
    [string]$BinaryPath = (Join-Path $PSScriptRoot "endpoint-agent.exe"),
    [string]$InstallDir = (Join-Path $env:ProgramFiles "EndpointAgent"),
    [string]$ServiceName = "EndpointAgent",
    [string]$DisplayName = "Endpoint Agent",
    [string]$Description = "Endpoint management platform agent",
    [string]$ApiUrl = "",
    [string]$EnrollmentToken = "",
    [string]$AgentId = "",
    [string]$AgentSecret = "",
    [string]$InstallId = "",
    [string]$LogDir = (Join-Path $env:ProgramData "EndpointAgent\logs"),
    [string]$MaintenanceToken = "",
    [string]$MaintenanceTokenHash = "",
    [string]$ServiceSddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)",
    [switch]$AutoEnroll,
    [string]$AutoEnrollApiUrl = "https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent",
    [string]$AutoEnrollCertSubjectSuffix = "",
    [string]$AutoEnrollCertSANURIPrefix = "adcomputer:",
    [int]$AutoEnrollJitterSeconds = 0,
    [switch]$Start,
    [switch]$Force,
    [switch]$ResetCredentialStore,
    [switch]$DisableTamperProtection,
    # ------------------------------------------------------------------
    # Faz 22.1.0 release-foundation (Codex 019e8284 PARTIAL->AGREE plan):
    # URL-download path lets one PowerShell command fetch the agent
    # binary straight from a GitHub Release. When -BinaryUrl is set the
    # local -BinaryPath default is ignored; the binary is downloaded to
    # a temp file, SHA256-verified against -ExpectedSha256, signature-
    # checked against -ExpectedSignerThumbprint, and only then becomes
    # $sourceBinary for the existing install flow below.
    #
    # The four "__INJECTED_*__" defaults are PATCHED at release-publish
    # time by `.github/workflows/release.yml` + `scripts/release/
    # patch-installer-manifest.ps1`. When this script ships UN-patched
    # (working tree, ad-hoc download, non-release artifact) the
    # defaults stay literal sentinel strings - the URL path refuses to
    # run unless every field is overridden on the command line. The
    # original local -BinaryPath workflow is unchanged.
    #
    # Why not just trust /releases/latest/download/install.ps1 + a
    # SHA256SUMS fetch: explicit-tag URL is the only way to pin a
    # Faz 22.1 prerelease deterministically (GitHub `latest` skips
    # prereleases), and embedding the post-sign hash + signer
    # thumbprint into the script itself eliminates an extra network
    # round-trip on every install while keeping the trust chain
    # release-workflow-controlled. SHA256SUMS still ships as a
    # secondary evidence artifact for audit.
    # ------------------------------------------------------------------
    [string]$BinaryUrl = "__INJECTED_BINARY_URL__",
    [string]$ExpectedSha256 = "__INJECTED_EXPECTED_SHA256__",
    [string]$ExpectedSignerThumbprint = "__INJECTED_EXPECTED_THUMBPRINT__",
    # ValidateSet intentionally NOT used here: the un-patched sentinel
    # value (`__INJECTED_SIGNING_TIER__`) must be allowed at param-bind
    # time so the script parses cleanly when sentinels are still in
    # place. Tier semantics are enforced in the URL-download branch
    # below via an explicit allowlist (Codex 019e8284 iter-1 Q1).
    [string]$SigningTier = "__INJECTED_SIGNING_TIER__",
    [string]$ReleaseTag = "__INJECTED_RELEASE_TAG__",
    # Explicit opt-in for lab-only-evidence (self-signed ephemeral
    # cert) binaries. Without this switch a SigningTier=lab-only-
    # evidence release ABORTs the install: the README primary command
    # must not silently install an ephemeral-signed binary on an
    # unprepared endpoint. (Codex 019e8284 must_fix #1.)
    [switch]$AcceptLabOnlySigning,
    # Tighten the lab boundary: by default lab-only-evidence signing
    # is REFUSED on domain-joined machines (the most common production
    # environment). Parallels VMs and workgroup machines are the
    # explicit lab target. Override only when the lab itself is
    # domain-joined.
    [switch]$AllowLabOnDomainJoined
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$configKeys = @(
    "ENDPOINT_AGENT_API_URL",
    "ENDPOINT_AGENT_ENROLLMENT_TOKEN",
    "ENDPOINT_AGENT_ID",
    "ENDPOINT_AGENT_SECRET",
    "ENDPOINT_AGENT_INSTALL_ID",
    "ENDPOINT_AGENT_LOG_DIR",
    "ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256",
    "ENDPOINT_AGENT_AUTO_ENROLL_API_URL",
    "ENDPOINT_AGENT_AUTO_ENROLL_CERT_SUBJECT_SUFFIX",
    "ENDPOINT_AGENT_AUTO_ENROLL_CERT_SAN_URI_PREFIX"
)

function Write-Step {
    param([string]$Message)
    Write-Host "[endpoint-agent] $Message"
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator PowerShell is required."
    }
}

function Get-MachineEnv {
    param([string]$Name)
    return [Environment]::GetEnvironmentVariable($Name, "Machine")
}

function Set-MachineEnvIfPresent {
    param(
        [hashtable]$OriginalValues,
        [string]$Name,
        [string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return
    }
    if (-not $OriginalValues.ContainsKey($Name)) {
        $OriginalValues[$Name] = Get-MachineEnv -Name $Name
    }
    [Environment]::SetEnvironmentVariable($Name, $Value, "Machine")
    Write-Step "configured $Name"
}

function Restore-MachineEnv {
    param([hashtable]$OriginalValues)
    foreach ($key in $OriginalValues.Keys) {
        [Environment]::SetEnvironmentVariable($key, $OriginalValues[$key], "Machine")
    }
}

function Test-ServiceExists {
    param([string]$Name)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    return $null -ne $service
}

function Invoke-AgentServiceCommand {
    param(
        [string]$ExePath,
        [string[]]$Arguments
    )
    & $ExePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "endpoint-agent.exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Invoke-NativeCommand {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )
    & $FilePath @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function ConvertTo-Sha256Hex {
    param([string]$Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hash = $sha.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Resolve-MaintenanceTokenHash {
    param(
        [string]$Token,
        [string]$Hash
    )
    if (-not [string]::IsNullOrWhiteSpace($Hash)) {
        return $Hash.Trim().ToLowerInvariant()
    }
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        return ConvertTo-Sha256Hex -Value $Token
    }
    return ""
}

function Protect-DirectoryAcl {
    param([string]$Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    Invoke-NativeCommand -FilePath "icacls.exe" -Arguments @($Path, "/inheritance:r")
    Invoke-NativeCommand -FilePath "icacls.exe" -Arguments @(
        $Path,
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F"
    )
}

function Protect-AgentDirectories {
    param(
        [string]$InstallPath,
        [string]$LogPath
    )
    Write-Step "hardening install ACL: $InstallPath"
    Protect-DirectoryAcl -Path $InstallPath
    $programDataRoot = Split-Path -Parent $LogPath
    if (-not [string]::IsNullOrWhiteSpace($programDataRoot)) {
        Write-Step "hardening config/log root ACL: $programDataRoot"
        Protect-DirectoryAcl -Path $programDataRoot
    }
    Write-Step "hardening log ACL: $LogPath"
    Protect-DirectoryAcl -Path $LogPath
}

function Set-AgentServiceHardening {
    param(
        [string]$Name,
        [string]$Sddl
    )
    Write-Step "configuring service delayed auto-start"
    Invoke-NativeCommand -FilePath "sc.exe" -Arguments @("config", $Name, "start=", "delayed-auto")

    Write-Step "configuring service failure restart policy"
    Invoke-NativeCommand -FilePath "sc.exe" -Arguments @(
        "failure",
        $Name,
        "reset=",
        "86400",
        "actions=",
        "restart/60000/restart/60000/restart/60000"
    )
    Invoke-NativeCommand -FilePath "sc.exe" -Arguments @("failureflag", $Name, "1")

    Write-Step "configuring service SDDL"
    Invoke-NativeCommand -FilePath "sc.exe" -Arguments @("sdset", $Name, $Sddl)
}

# AG-026C: build the service-specific Environment regkey value
# (REG_MULTI_SZ at HKLM\SYSTEM\CurrentControlSet\Services\<name>\Environment).
# Windows SCM reads this on every service spawn and overlays it on the
# inherited machine env block, side-stepping the SCM env block cache that
# caused the 3-hour SRB-AIDENETIMPC live-rollout debug session
# (Codex 019e7314). Because this REG_MULTI_SZ becomes the effective service
# process environment on some Windows builds, keep the minimal non-secret OS
# variables needed by child processes, DNS and Windows APIs (Path/SystemRoot/
# windir/ProgramData/TEMP/TMP). Tokens stored here are temporary (cleared by
# Clear-ServiceEnvironmentToken after AG-026D's "hmac credential
# confirmed" sentinel proves the credential persisted to DPAPI).
function Add-ServiceEnvironmentBaseVariables {
    param([hashtable]$Values)

    $path = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if (-not [string]::IsNullOrWhiteSpace($path) -and -not $Values.ContainsKey("Path")) {
        $Values["Path"] = $path
    }

    $systemRoot = [Environment]::GetEnvironmentVariable("SystemRoot", "Machine")
    if ([string]::IsNullOrWhiteSpace($systemRoot)) {
        $systemRoot = $env:SystemRoot
    }
    if ([string]::IsNullOrWhiteSpace($systemRoot)) {
        $systemRoot = "C:\Windows"
    }
    if (-not $Values.ContainsKey("SystemRoot")) {
        $Values["SystemRoot"] = $systemRoot
    }
    if (-not $Values.ContainsKey("windir")) {
        $Values["windir"] = $systemRoot
    }

    $programData = [Environment]::GetEnvironmentVariable("ProgramData", "Machine")
    if ([string]::IsNullOrWhiteSpace($programData)) {
        $programData = $env:ProgramData
    }
    if ([string]::IsNullOrWhiteSpace($programData)) {
        $programData = "C:\ProgramData"
    }
    if (-not $Values.ContainsKey("ProgramData")) {
        $Values["ProgramData"] = $programData
    }

    $temp = [Environment]::GetEnvironmentVariable("TEMP", "Machine")
    if ([string]::IsNullOrWhiteSpace($temp)) {
        $temp = Join-Path $systemRoot "Temp"
    }
    if (-not $Values.ContainsKey("TEMP")) {
        $Values["TEMP"] = $temp
    }
    if (-not $Values.ContainsKey("TMP")) {
        $Values["TMP"] = $temp
    }
}

function Set-ServiceEnvironmentRegkey {
    param(
        [string]$Name,
        [hashtable]$Values
    )
    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path -LiteralPath $servicePath)) {
        throw "Service registry key not found: $servicePath"
    }
    $merged = @{}
    foreach ($key in $Values.Keys) {
        $merged[$key] = $Values[$key]
    }
    if ($merged.Count -gt 0) {
        Add-ServiceEnvironmentBaseVariables -Values $merged
    }
    $entries = @()
    foreach ($key in $merged.Keys) {
        $v = $merged[$key]
        if (-not [string]::IsNullOrWhiteSpace($v)) {
            $entries += "$key=$v"
        }
    }
    if ($entries.Count -gt 0) {
        New-ItemProperty -Path $servicePath -Name 'Environment' -Value $entries -PropertyType MultiString -Force | Out-Null
    } else {
        # No values to set - clear any stale regkey so the next service
        # spawn does not inherit obsolete state.
        Remove-ItemProperty -Path $servicePath -Name 'Environment' -ErrorAction SilentlyContinue
    }
}

# AG-026C: strip a single key from the service-specific Environment
# REG_MULTI_SZ value. Used after enroll confirmation to remove the
# ENROLLMENT_TOKEN entry while keeping the non-secret config (API_URL,
# INSTALL_ID, LOG_DIR, MAINTENANCE_TOKEN_SHA256). The next service
# restart will see the env without the token; AG-026D's DPAPI store
# already holds the issued credential so the token is no longer needed.
function Remove-ServiceEnvironmentEntry {
    param(
        [string]$Name,
        [string]$Key
    )
    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $existing = Get-ItemProperty -Path $servicePath -Name 'Environment' -ErrorAction SilentlyContinue
    if ($null -eq $existing -or $null -eq $existing.Environment) { return }
    $prefix = "$Key="
    $filtered = @($existing.Environment | Where-Object { $_ -notlike "$prefix*" })
    if ($filtered.Count -gt 0) {
        New-ItemProperty -Path $servicePath -Name 'Environment' -Value $filtered -PropertyType MultiString -Force | Out-Null
    } else {
        Remove-ItemProperty -Path $servicePath -Name 'Environment' -ErrorAction SilentlyContinue
    }
}

function Get-AgentRegistrySnapshot {
    param(
        [string[]]$Names,
        [string]$Path = "HKLM:\SOFTWARE\EndpointAgent"
    )
    $snapshot = @{}
    foreach ($name in $Names) {
        $entry = @{
            Exists = $false
            Value  = $null
            Kind   = "String"
        }
        if (Test-Path -LiteralPath $Path) {
            $key = $null
            try {
                $key = Get-Item -LiteralPath $Path -ErrorAction Stop
                if ($null -ne $key -and ($key.GetValueNames() -contains $name)) {
                    $entry.Exists = $true
                    $entry.Value = $key.GetValue($name)
                    $entry.Kind = $key.GetValueKind($name).ToString()
                }
            } finally {
                if ($key) { $key.Dispose() }
            }
        }
        $snapshot[$name] = $entry
    }
    return $snapshot
}

function Restore-AgentRegistrySnapshot {
    param(
        [hashtable]$Snapshot,
        [string]$Path = "HKLM:\SOFTWARE\EndpointAgent"
    )
    foreach ($name in $Snapshot.Keys) {
        $entry = $Snapshot[$name]
        if ($entry.Exists) {
            New-Item -Path $Path -Force | Out-Null
            New-ItemProperty -Path $Path -Name $name -Value $entry.Value -PropertyType $entry.Kind -Force | Out-Null
        } elseif (Test-Path -LiteralPath $Path) {
            Remove-ItemProperty -Path $Path -Name $name -ErrorAction SilentlyContinue
        }
    }
}

function Set-AgentAutoEnrollRegistry {
    param(
        [string]$ApiUrl,
        [int]$JitterSeconds,
        [string]$Path = "HKLM:\SOFTWARE\EndpointAgent"
    )
    New-Item -Path $Path -Force | Out-Null
    New-ItemProperty -Path $Path -Name "Mode" -Value "auto-enroll" -PropertyType String -Force | Out-Null
    if (-not [string]::IsNullOrWhiteSpace($ApiUrl)) {
        New-ItemProperty -Path $Path -Name "ApiUrl" -Value $ApiUrl -PropertyType String -Force | Out-Null
    }
    if ($JitterSeconds -gt 0) {
        New-ItemProperty -Path $Path -Name "EnrollmentJitterSeconds" -Value $JitterSeconds -PropertyType DWord -Force | Out-Null
    }
}

function Clear-AgentAutoEnrollRegistry {
    param([string]$Path = "HKLM:\SOFTWARE\EndpointAgent")
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    foreach ($name in @("Mode", "ApiUrl", "EnrollmentJitterSeconds")) {
        Remove-ItemProperty -Path $Path -Name $name -ErrorAction SilentlyContinue
    }
}

# AG-026C: scan the agent log for the AG-026D "hmac credential
# confirmed" sentinel that proves: (a) the DPAPI store wrote the
# credential, (b) the first signed heartbeat returned 2xx with
# accepted=true, (c) deviceId matched. Only when all three hold does
# AG-026C clear the enrollment token from the service env regkey.
# Returns $true on success, $false on timeout.
#
# Codex 019e7314 iter-1 P1.1: append-only false-positive guard. The
# agent log is opened append-only; a previous install/upgrade may
# have left a "hmac credential confirmed" line in the file. The
# caller MUST capture the on-disk byte length BEFORE service start
# and pass it as $BaselineLength; this function ignores every byte at
# offset <= $BaselineLength so only sentinels written AFTER service
# start in THIS install window can satisfy the gate.
function Wait-ForCredentialConfirmed {
    param(
        [string]$LogPath,
        [int]$TimeoutSeconds = 60,
        [long]$BaselineLength = 0
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $LogPath) {
            $current = (Get-Item -LiteralPath $LogPath -ErrorAction SilentlyContinue).Length
            if ($current -gt $BaselineLength) {
                # Read only the new bytes appended since service
                # start. UTF-8 (no BOM) is the agent logger contract
                # (logger.go); reading bytes + decoding directly
                # avoids the cmdlet's CRLF-bound line truncation
                # when the agent is mid-write.
                $stream = $null
                try {
                    $stream = [System.IO.File]::Open(
                        $LogPath,
                        [System.IO.FileMode]::Open,
                        [System.IO.FileAccess]::Read,
                        [System.IO.FileShare]::ReadWrite)
                    $stream.Position = $BaselineLength
                    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
                    try {
                        $newBytes = $reader.ReadToEnd()
                    } finally {
                        $reader.Close()
                    }
                } finally {
                    if ($stream) { $stream.Dispose() }
                }
                if ($newBytes -match 'hmac credential confirmed') {
                    return $true
                }
            }
        }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Remove-ServiceBestEffort {
    param(
        [string]$Name,
        [string]$ExePath,
        [string]$Token,
        [string]$TokenHash
    )
    if (Test-Path -LiteralPath $ExePath) {
        $arguments = @("service", "uninstall", "--name", $Name)
        if (-not [string]::IsNullOrWhiteSpace($Token)) {
            $arguments += @("--maintenance-token", $Token)
        }
        if (-not [string]::IsNullOrWhiteSpace($TokenHash)) {
            $arguments += @("--maintenance-token-sha256", $TokenHash)
        }
        try {
            Invoke-AgentServiceCommand -ExePath $ExePath -Arguments $arguments
            return
        } catch {
            Write-Warning "agent service uninstall failed: $($_.Exception.Message)"
        }
    }
    try {
        sc.exe stop $Name | Out-Null
    } catch {}
    sc.exe delete $Name | Out-Null
}

function Get-HmacCredentialStorePath {
    param([string]$ProgramDataRoot = "")
    if ([string]::IsNullOrWhiteSpace($ProgramDataRoot)) {
        $ProgramDataRoot = $env:ProgramData
    }
    if ([string]::IsNullOrWhiteSpace($ProgramDataRoot)) {
        $ProgramDataRoot = "C:\ProgramData"
    }
    return (Join-Path $ProgramDataRoot "EndpointAgent\config\hmac-credential.dpapi")
}

function Assert-HmacEnrollmentTokenStorePolicy {
    param(
        [string]$Token,
        [bool]$ResetRequested,
        [string]$CredentialStorePath
    )
    if ([string]::IsNullOrWhiteSpace($Token)) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($CredentialStorePath)) {
        throw "CredentialStorePath is required for HMAC enrollment-token policy check."
    }
    if (-not (Test-Path -LiteralPath $CredentialStorePath)) {
        return
    }
    if ($ResetRequested) {
        return
    }
    throw "Existing EndpointAgent HMAC credential store found at $CredentialStorePath. Supplying -EnrollmentToken does not force fresh enrollment because the agent will prefer the stored credential on cold start. Re-run without -EnrollmentToken for upgrade-preserve, or pass -ResetCredentialStore to back up the store and fresh-enroll."
}

function Backup-HmacCredentialStoreForFreshEnroll {
    param(
        [Parameter(Mandatory)] [string]$CredentialStorePath,
        [string]$Timestamp = ""
    )
    if (-not (Test-Path -LiteralPath $CredentialStorePath)) {
        return ""
    }
    if ([string]::IsNullOrWhiteSpace($Timestamp)) {
        $Timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    }
    $backupPath = "$CredentialStorePath.bak-$Timestamp"
    if (Test-Path -LiteralPath $backupPath) {
        $backupPath = "$backupPath-$([guid]::NewGuid().ToString("N"))"
    }
    # ProgramData lives on the same volume as the store path in supported
    # installs; Move-Item keeps the backup non-destructive and atomic there.
    Move-Item -LiteralPath $CredentialStorePath -Destination $backupPath -Force
    Write-Step "backed up existing HMAC credential store for fresh enrollment: $backupPath"
    return $backupPath
}

Assert-Administrator

if ($AutoEnroll) {
    if (-not [string]::IsNullOrWhiteSpace($EnrollmentToken) -or
        -not [string]::IsNullOrWhiteSpace($AgentId) -or
        -not [string]::IsNullOrWhiteSpace($AgentSecret) -or
        -not [string]::IsNullOrWhiteSpace($InstallId)) {
        throw "-AutoEnroll is mutually exclusive with HMAC enrollment token/id/secret/install-id parameters."
    }
    if ([string]::IsNullOrWhiteSpace($AutoEnrollCertSubjectSuffix) -and
        [string]::IsNullOrWhiteSpace($AutoEnrollCertSANURIPrefix)) {
        throw "-AutoEnroll requires AutoEnrollCertSubjectSuffix or AutoEnrollCertSANURIPrefix."
    }
    if ($AutoEnrollJitterSeconds -lt 0) {
        throw "-AutoEnrollJitterSeconds must be zero or positive."
    }
    if ($ResetCredentialStore) {
        throw "-ResetCredentialStore is only valid for the HMAC enrollment-token fallback path."
    }
}

# ----------------------------------------------------------------------
# Faz 22.1.0 release-foundation - URL download + signature verify
# (Codex 019e8284 PARTIAL->AGREE plan). Runs ONLY when -BinaryUrl is
# set to a non-sentinel value (so the local -BinaryPath workflow stays
# byte-identical when this script ships un-patched or a developer runs
# from the working tree). Every guardrail is fail-closed: a single
# mismatch ABORTs before any service or registry mutation.
# ----------------------------------------------------------------------

$injectedSentinel = "__INJECTED_BINARY_URL__"
$useUrlDownload = ($BinaryUrl -and $BinaryUrl -ne $injectedSentinel)
$downloadTempPath = ""

function Get-IsDomainJoined {
    try {
        return [bool](Get-CimInstance -ClassName Win32_ComputerSystem `
            -ErrorAction Stop).PartOfDomain
    } catch {
        # If WMI is unreachable, refuse the lab path on this machine
        # rather than guessing. Operator can pass -AllowLabOnDomainJoined
        # to explicitly override.
        return $true
    }
}

function Invoke-VerifyDownloadedBinary {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$ExpectedHash,
        [string]$ExpectedThumbprint,
        [string]$Tier
    )

    Write-Step "verifying SHA256 (expected $($ExpectedHash.Substring(0,16))...)"
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ne $ExpectedHash.ToUpperInvariant()) {
        throw "SHA256 mismatch: expected $ExpectedHash, got $actual"
    }

    if ($ExpectedThumbprint) {
        Write-Step "verifying Authenticode signer thumbprint"
        $sig = Get-AuthenticodeSignature -LiteralPath $Path
        if (-not $sig.SignerCertificate) {
            throw "binary is unsigned (tier=$Tier requires a signature)"
        }
        $actualThumb = $sig.SignerCertificate.Thumbprint
        if ($actualThumb -ne $ExpectedThumbprint.ToUpperInvariant()) {
            throw "signer thumbprint mismatch: expected $ExpectedThumbprint, got $actualThumb"
        }

        # Codex 019e8284 iter-1 medium #4: explicit Authenticode Status
        # allowlist per tier, instead of "anything not NotSigned".
        # `HashMismatch` (binary tampered after signing),
        # `NotSupportedFileFormat` (corrupt PE), and bare `UnknownError`
        # would otherwise pass once the thumbprint pin matched, which
        # masks a broken signature blob.
        switch ($Tier) {
            "lab-only-evidence" {
                # Lab self-signed cert chains to an ephemeral CA the
                # runner creates per release. Windows reports the chain
                # state as one of:
                #   - NotTrusted        - most common: untrusted root
                #   - Valid             - operator pre-imported the cert
                #                         into LocalMachine\Root
                #   - UnknownError      - some Windows / PowerShell
                #                         versions surface untrusted-root
                #                         here instead of NotTrusted;
                #                         allowed ONLY when the message
                #                         describes a chain/trust issue.
                # Everything else (HashMismatch, NotSupportedFileFormat,
                # IncompatibleSignature, generic UnknownError) is
                # rejected. (Codex 019e8284 iter-2 medium #2.)
                $okStatus = @("NotTrusted","Valid") -contains $sig.Status
                $msg = "$($sig.StatusMessage)"
                $okUnknownTrustRoot = ($sig.Status -eq "UnknownError") -and `
                    ($msg -match "trust|chain|root|UntrustedRoot")
                if (-not ($okStatus -or $okUnknownTrustRoot)) {
                    throw "lab-only Authenticode status '$($sig.Status)' rejected (expected NotTrusted/Valid; got '$msg')"
                }
            }
            "trusted" {
                # Trusted tier (Faz 22.2+ Azure Trusted Signing) MUST
                # chain to a trusted root on the endpoint at install
                # time. Anything but Valid is rejected.
                if ($sig.Status -ne "Valid") {
                    throw "trusted-signing tier requires Authenticode Status=Valid (got $($sig.Status): $($sig.StatusMessage))"
                }
            }
            default {
                throw "unknown SigningTier '$Tier' - refusing install"
            }
        }
    }
}

if ($useUrlDownload) {
    # Reject if any injected field is still a sentinel - this happens
    # when an unpatched install.ps1 is fetched but -BinaryUrl alone is
    # passed. We need the full quartet to be either real values or
    # explicit command-line overrides.
    foreach ($pair in @(
        @{Name="ExpectedSha256";           Value=$ExpectedSha256;           Sentinel="__INJECTED_EXPECTED_SHA256__"},
        @{Name="ExpectedSignerThumbprint"; Value=$ExpectedSignerThumbprint; Sentinel="__INJECTED_EXPECTED_THUMBPRINT__"},
        @{Name="SigningTier";              Value=$SigningTier;              Sentinel="__INJECTED_SIGNING_TIER__"},
        @{Name="ReleaseTag";               Value=$ReleaseTag;               Sentinel="__INJECTED_RELEASE_TAG__"}
    )) {
        if (-not $pair.Value -or $pair.Value -eq $pair.Sentinel) {
            throw "-$($pair.Name) is required when -BinaryUrl is set (still at sentinel value)"
        }
    }

    # Lab guardrail: require explicit operator opt-in, AND by default
    # refuse on domain-joined machines.
    if ($SigningTier -eq "lab-only-evidence") {
        if (-not $AcceptLabOnlySigning) {
            throw "release '$ReleaseTag' is lab-only-evidence (self-signed ephemeral cert). Pass -AcceptLabOnlySigning to install. Production endpoints must wait for trusted-signing releases (Faz 22.2+)."
        }
        if (-not $AllowLabOnDomainJoined -and (Get-IsDomainJoined)) {
            throw "release '$ReleaseTag' is lab-only-evidence and this machine is domain-joined. Pass -AllowLabOnDomainJoined to override (lab self-hosted on a domain) or use a workgroup/Parallels lab VM."
        }
    }

    $downloadTempPath = Join-Path $env:TEMP ("endpoint-agent-{0}.exe" -f ([System.Guid]::NewGuid().ToString("N")))
    Write-Step "downloading agent binary from $BinaryUrl"
    try {
        $oldProgress = $ProgressPreference
        $ProgressPreference = "SilentlyContinue"
        Invoke-WebRequest -Uri $BinaryUrl `
            -OutFile $downloadTempPath -UseBasicParsing `
            -MaximumRedirection 5 -ErrorAction Stop
    } finally {
        if ($null -ne $oldProgress) { $ProgressPreference = $oldProgress }
    }

    try {
        Invoke-VerifyDownloadedBinary `
            -Path $downloadTempPath `
            -ExpectedHash $ExpectedSha256 `
            -ExpectedThumbprint $ExpectedSignerThumbprint `
            -Tier $SigningTier
    } catch {
        # Wipe the unverified file before throwing - never leave a
        # tampered or mismatched binary on disk for a curious operator
        # to later double-click.
        try { Remove-Item -LiteralPath $downloadTempPath -Force -ErrorAction Stop } catch {}
        throw
    }

    # The verified download is now the binary the existing flow installs.
    $BinaryPath = $downloadTempPath
}

$sourceBinary = Resolve-Path -LiteralPath $BinaryPath -ErrorAction Stop
$targetBinary = Join-Path $InstallDir "endpoint-agent.exe"
$originalValues = @{}
$autoEnrollRegistrySnapshot = $null
$autoEnrollRegistryTouched = $false
$copiedBinary = $false
$installedService = $false
$resolvedMaintenanceTokenHash = Resolve-MaintenanceTokenHash -Token $MaintenanceToken -Hash $MaintenanceTokenHash
$hmacCredentialStorePath = Get-HmacCredentialStorePath
$hmacCredentialStoreBackup = ""

try {
    # Codex 019e7314 iter-2 P1: non-destructive existence check FIRST.
    # An accidental install run without -Force on an existing service
    # MUST NOT touch the service-specific Environment regkey, because
    # the running service is consuming that config and any silent
    # cleanup would leave it credential-less on the next restart.
    if ((Test-ServiceExists -Name $ServiceName) -and -not $Force) {
        throw "Service '$ServiceName' already exists. Use -Force to replace it."
    }

    # AG-026C / #109: a stored HMAC credential wins over
    # ENDPOINT_AGENT_ENROLLMENT_TOKEN on cold start. That is the
    # correct upgrade-preserve default, but it makes "fresh enroll"
    # ambiguous if an operator supplies a new token on an already
    # enrolled machine. Fail before service/config mutation unless the
    # operator explicitly asks to reset the store.
    if (-not $AutoEnroll) {
        Assert-HmacEnrollmentTokenStorePolicy `
            -Token $EnrollmentToken `
            -ResetRequested ([bool]$ResetCredentialStore) `
            -CredentialStorePath $hmacCredentialStorePath
        if (-not [string]::IsNullOrWhiteSpace($EnrollmentToken) -and $ResetCredentialStore) {
            $hmacCredentialStoreBackup = Backup-HmacCredentialStoreForFreshEnroll `
                -CredentialStorePath $hmacCredentialStorePath
        }
    }

    # AG-026C: defuse the regkey override mechanism BEFORE the
    # uninstall + reinstall pair runs. A previous incomplete install
    # or a parallel script may have written
    # `HKLM\...\Services\$ServiceName\Environment` with a stale
    # token; clearing first guarantees the post-install
    # Set-ServiceEnvironmentRegkey write is the SOLE source of
    # agent config for the new install. Only runs in the -Force
    # path now - fresh installs do not need it (no prior service)
    # and the no-Force-on-existing path already threw above.
    if ((Test-ServiceExists -Name $ServiceName) -and $Force) {
        Write-Step "clearing stale service env regkey: $ServiceName\\Environment"
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name 'Environment' -ErrorAction SilentlyContinue
        Write-Step "existing service found; uninstalling $ServiceName"
        $uninstallScript = Join-Path $PSScriptRoot "uninstall.ps1"
        if (Test-Path -LiteralPath $uninstallScript) {
            # Live verify 2026-05-29 surfaced a latent issue: the
            # array-form splat with -Force failed to bind -LogDir to
            # uninstall.ps1 (PowerShell 5.1 reported
            # InvalidArgument / PositionalParameterNotFound for the
            # path that followed). Use hashtable-form splat instead -
            # bindings are explicit and values containing backslashes
            # are never re-parsed by the array element walker.
            $uninstallArgs = @{
                ServiceName = $ServiceName
                InstallDir  = $InstallDir
                LogDir      = $LogDir
            }
            if (-not [string]::IsNullOrWhiteSpace($MaintenanceToken)) {
                $uninstallArgs['MaintenanceToken'] = $MaintenanceToken
            }
            & $uninstallScript @uninstallArgs
        } else {
            Remove-ServiceBestEffort -Name $ServiceName -ExePath $targetBinary -Token $MaintenanceToken -TokenHash $resolvedMaintenanceTokenHash
        }
    }

    Write-Step "creating install directory: $InstallDir"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    if (-not $DisableTamperProtection) {
        Protect-AgentDirectories -InstallPath $InstallDir -LogPath $LogDir
    }

    Write-Step "copying endpoint-agent.exe"
    Copy-Item -LiteralPath $sourceBinary -Destination $targetBinary -Force
    Unblock-File -LiteralPath $targetBinary -ErrorAction SilentlyContinue
    $copiedBinary = $true

    # AG-026C / ADR-0029: install agent config to the SERVICE-SPECIFIC env regkey
    # (HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName\Environment)
    # instead of the Machine env. Bypasses the SCM env block caching
    # quirk that delayed SCM from picking up Machine env changes on
    # high-uptime hosts (live evidence: SRB-AIDENETIMPC 3-hour debug
    # session, 2026-05-29; Codex 019e7314). The service spawn ALWAYS
    # reads this regkey, so an install->reboot dance is no longer
    # required and a service restart inherits the new config
    # immediately.
    #
    # The ENROLLMENT_TOKEN is included here only for the single
    # bootstrap window between install completion and the
    # AG-026D-emitted "hmac credential confirmed" sentinel. Once the
    # sentinel proves DPAPI persistence + signed heartbeat acceptance,
    # the post-install gate below removes ONLY the token entry,
    # leaving non-secret config in place.
    #
    # AG-026D credential persistence makes the token's continued
    # presence in env unnecessary across restarts: the agent loads
    # DPAPI credential at cold start and bypasses the env-token path
    # entirely.
    # Codex 019e7314 iter-1 P1.2: ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256
    # stays in Machine env. It is a hash (not a secret) - the
    # uninstall script needs to read it without first having access
    # to the service-specific regkey (which is per-service and would
    # need to be looked up by service name AT uninstall time, but the
    # uninstall path runs BEFORE service registry teardown anyway).
    # The standalone agent CLI service stop/uninstall paths also
    # currently consult process env for this hash; moving it to a
    # service-only regkey would break those out-of-band recovery
    # operations. Keeping the maintenance hash in Machine env is the
    # narrow exception to the AG-026C "Machine env NEVER" rule.
    Set-MachineEnvIfPresent -OriginalValues $originalValues -Name "ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256" -Value $resolvedMaintenanceTokenHash

    if ($AutoEnroll) {
        $autoEnrollRegistrySnapshot = Get-AgentRegistrySnapshot -Names @("Mode", "ApiUrl", "EnrollmentJitterSeconds")
        Write-Step "configuring auto-enroll registry mode"
        Set-AgentAutoEnrollRegistry -ApiUrl $AutoEnrollApiUrl -JitterSeconds $AutoEnrollJitterSeconds
        $autoEnrollRegistryTouched = $true

        $serviceEnv = @{
            "ENDPOINT_AGENT_LOG_DIR" = $LogDir
            "ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256" = $resolvedMaintenanceTokenHash
            "ENDPOINT_AGENT_AUTO_ENROLL_API_URL" = $AutoEnrollApiUrl
            "ENDPOINT_AGENT_AUTO_ENROLL_CERT_SUBJECT_SUFFIX" = $AutoEnrollCertSubjectSuffix
            "ENDPOINT_AGENT_AUTO_ENROLL_CERT_SAN_URI_PREFIX" = $AutoEnrollCertSANURIPrefix
        }
    } else {
        # #108: an earlier AutoEnroll install may have left
        # HKLM:\SOFTWARE\EndpointAgent\Mode=auto-enroll. HMAC reinstall
        # must explicitly clear that registry override before first
        # service start, otherwise the runner ignores the HMAC service
        # env and boots in auto-enroll mode.
        $autoEnrollRegistrySnapshot = Get-AgentRegistrySnapshot -Names @("Mode", "ApiUrl", "EnrollmentJitterSeconds")
        Write-Step "clearing auto-enroll registry mode for HMAC install"
        Clear-AgentAutoEnrollRegistry
        $autoEnrollRegistryTouched = $true

        $serviceEnv = @{
            "ENDPOINT_AGENT_API_URL" = $ApiUrl
            "ENDPOINT_AGENT_ENROLLMENT_TOKEN" = $EnrollmentToken
            "ENDPOINT_AGENT_ID" = $AgentId
            "ENDPOINT_AGENT_SECRET" = $AgentSecret
            "ENDPOINT_AGENT_INSTALL_ID" = $InstallId
            "ENDPOINT_AGENT_LOG_DIR" = $LogDir
            "ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256" = $resolvedMaintenanceTokenHash
        }
    }

    Write-Step "installing service: $ServiceName"
    Invoke-AgentServiceCommand -ExePath $targetBinary -Arguments @(
        "service", "install",
        "--name", $ServiceName,
        "--display-name", $DisplayName,
        "--description", $Description
    )
    $installedService = $true

    # AG-026C: write the service-specific env regkey AFTER service
    # install (the service registry key must exist first) but BEFORE
    # service start (so the first spawn sees the new config). Stale
    # entries from a previous install/upgrade are overwritten by
    # New-ItemProperty -Force; this also defuses the regkey override
    # mechanism that masked Machine env updates in the SRB live debug.
    Write-Step "writing service env regkey: $ServiceName\\Environment"
    Set-ServiceEnvironmentRegkey -Name $ServiceName -Values $serviceEnv

    if (-not $DisableTamperProtection) {
        Set-AgentServiceHardening -Name $ServiceName -Sddl $ServiceSddl
    }

    # Codex 019e7314 iter-1 P1.1: snapshot the agent log byte length
    # BEFORE service start. The append-only logger may already have a
    # "hmac credential confirmed" line from a previous install; the
    # gate below only honours sentinels written at offset >
    # $logBaselineLength.
    $agentLog = Join-Path $LogDir "endpoint-agent.log"
    $logBaselineLength = if (Test-Path -LiteralPath $agentLog) {
        (Get-Item -LiteralPath $agentLog).Length
    } else {
        0
    }

    if ($Start) {
        Write-Step "starting service: $ServiceName"
        Invoke-AgentServiceCommand -ExePath $targetBinary -Arguments @("service", "start", "--name", $ServiceName)
    }

    Write-Step "status"
    Invoke-AgentServiceCommand -ExePath $targetBinary -Arguments @("service", "status", "--name", $ServiceName)

    # AG-026C: post-install enroll validation gate. Codex 019e7314
    # iter-1 must_fix #1 keyed the AG-026D-emitted "hmac credential
    # confirmed" sentinel on (a) DPAPI store write success in this
    # process AND (b) signed heartbeat 2xx accepted + deviceId match.
    # When the sentinel appears, the credential is durably persisted
    # and the env token is no longer needed; we strip it from the
    # service env regkey so a subsequent OS administrator inspecting
    # `Get-ItemProperty HKLM:\...\Services\EndpointAgent` does not
    # see the consumed token. The degraded sentinel ("hmac credential
    # accepted (not persisted)") is deliberately ignored by the gate
    # - without DPAPI confirmation we leave the token in place so the
    # next service restart can retry the same enroll.
    if ($Start -and -not $AutoEnroll -and -not [string]::IsNullOrWhiteSpace($EnrollmentToken)) {
        Write-Step "waiting for AG-026D credential-confirmed sentinel (up to 60s, log baseline=$logBaselineLength bytes)"
        if (Wait-ForCredentialConfirmed -LogPath $agentLog -TimeoutSeconds 60 -BaselineLength $logBaselineLength) {
            Write-Step "AG-026C: enroll confirmed - removing token from service env regkey"
            Remove-ServiceEnvironmentEntry -Name $ServiceName -Key "ENDPOINT_AGENT_ENROLLMENT_TOKEN"
        } else {
            Write-Warning "AG-026C: 'hmac credential confirmed' sentinel not seen within 60s; token left in service env regkey for next restart retry"
        }
    }

    Write-Step "install completed"
} catch {
    Write-Error $_
    Write-Step "rollback started"
    if ($installedService -and (Test-Path -LiteralPath $targetBinary)) {
        try {
            Remove-ServiceBestEffort -Name $ServiceName -ExePath $targetBinary -Token $MaintenanceToken -TokenHash $resolvedMaintenanceTokenHash
        } catch {
            Write-Warning "service rollback failed: $($_.Exception.Message)"
        }
    }
    if ($copiedBinary -and (Test-Path -LiteralPath $targetBinary)) {
        try {
            Remove-Item -LiteralPath $targetBinary -Force
        } catch {
            Write-Warning "binary rollback failed: $($_.Exception.Message)"
        }
    }
    if ($autoEnrollRegistryTouched -and $null -ne $autoEnrollRegistrySnapshot) {
        try {
            Restore-AgentRegistrySnapshot -Snapshot $autoEnrollRegistrySnapshot
        } catch {
            Write-Warning "auto-enroll registry rollback failed: $($_.Exception.Message)"
        }
    }
    Restore-MachineEnv -OriginalValues $originalValues
    throw
}
