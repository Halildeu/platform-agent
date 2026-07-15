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
    # Default resolved in the body (see $EaScriptDir): $PSScriptRoot can be empty
    # during param-default binding on some hosts, which made the old
    # `Join-Path $PSScriptRoot ...` default THROW "empty Path" before the body ran.
    [string]$BinaryPath = "",
    [string]$InstallDir = (Join-Path $env:ProgramFiles "EndpointAgent"),
    [string]$ServiceName = "EndpointAgent",
    [string]$DisplayName = "Endpoint Agent",
    [string]$Description = "Endpoint management platform agent",
    [string]$ApiUrl = "",
    [string]$EnrollmentToken = "",
    # #120: minimum plausible length for an HMAC enrollment token. Real signed
    # tokens are ~600+ chars; this floor catches an impossibly-short truncated
    # paste (the MKR-A1 live pilot captured a single char over AnyDesk) without
    # false-rejecting a real token. NOTE: it does NOT catch a partial (e.g.
    # 100-char) paste -- it is a truncation floor, not a token validator.
    # ValidateRange keeps an operator from weakening the guard below 32.
    [ValidateRange(32, [int]::MaxValue)]
    [int]$MinEnrollmentTokenLength = 32,
    [string]$AgentId = "",
    [string]$AgentSecret = "",
    [string]$InstallId = "",
    [string]$LogDir = (Join-Path $env:ProgramData "EndpointAgent\logs"),
    [string]$MaintenanceToken = "",
    [string]$MaintenanceTokenHash = "",
    [string]$ServiceSddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)",
    [switch]$AutoEnroll,
    [string]$AutoEnrollApiUrl = "https://mtls.testai.acik.com/api/v1/endpoint-agent",
    [string]$AutoEnrollCertSubjectSuffix = "",
    [string]$AutoEnrollCertSANURIPrefix = "adcomputer:",
    [int]$AutoEnrollJitterSeconds = 0,
    [switch]$RemoteBridgeEnabled,
    [string]$RemoteBridgeBrokerAddr = "",
    [switch]$RemoteBridgeInsecurePlaintext,
    [string]$RemoteBridgeMTLSCertSubjectSuffix = "",
    [string]$RemoteBridgeMTLSCertSANURIPrefix = "",
    [string]$RemoteBridgeAttestationEvidenceB64 = "",
    [switch]$RemoteBridgeOperationsEnabled,
    [string]$RemoteBridgePermitBrokerPublicKeyB64 = "",
    [string]$RemoteBridgePermitKeyID = "",
    [switch]$RemoteBridgePilotAutoConsent,
    [switch]$RemoteBridgeDeviceKeySessionEnabled,
    [switch]$RemoteBridgeViewOnlyEnabled,
    [switch]$RemoteBridgeViewOnlyAttendedConsent,
    [string]$RemoteBridgeViewOnlyMaskRectBPS = "",
    [string]$RemoteBridgeTLSServerName = "",
    [switch]$SelfUpdateEnabled,
    [string]$SelfUpdateAllowedHosts = "",
    [string]$SelfUpdateSignerThumbprints = "",
    [string]$SelfUpdateHardMaxBytes = "52428800",
    [ValidateRange(0, 100)]
    [int]$SelfUpdateMaxRedirects = 5,
    [switch]$SelfUpdateAutoActivate,
    [string]$SelfUpdateActivationTimeout = "2m",
    [string]$SelfUpdateServiceName = "",
    [string]$SelfUpdateCommandTimeout = "30m",
    [ValidateRange(1, 600)]
    [int]$ServiceStartTimeoutSeconds = 30,
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
    [switch]$AllowLabOnDomainJoined,
    # ------------------------------------------------------------------
    # AG-018 internal-CA root trust (TOFU for the domain-less fleet).
    # SigningTier=trusted-internal-ca releases chain to an internal
    # OpenSSL root that public Windows trust does NOT know. The agent
    # installer imports that root (LocalMachine\Root + TrustedPublisher)
    # so the binary signature validates AND future signed updates verify
    #  -  domain-joined AND workgroup machines alike (GPO can't reach the
    # latter). The root .cer ships in the payload next to this script;
    # before import its SHA256 must equal $ExpectedRootCertSha256 (the
    # release-patched pin)  -  a mismatch ABORTS (never import an
    # unexpected root). -SkipRootTrust opts out (audited): the install
    # logs ROOT_TRUST_SKIPPED and the signature check then requires the
    # root to be pre-trusted by other means (GPO). (Codex 019eb0dd:
    # default-ON managed deployment + pin-match-before-import.)
    # Real value (the internal root is public + stable, NOT release-specific  - 
    # unlike the binary URL/hash/thumbprint which ARE release-patched). Pinned
    # here so both the URL-download and MSI-payload paths self-verify the embedded
    # root before importing it. If the CA rotates, regenerate this + $script:CodesignRootCertB64.
    [string]$ExpectedRootCertSha256 = "078494D03E2FB51EA35DB71FFC04B5C5230EE9F52E0D5A057B6F35B8F7E0B59E",
    [switch]$SkipRootTrust
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Robust script-directory resolution. $PSScriptRoot is normally the script's
# folder, but it was observed EMPTY during param-default binding on a real domain
# device 2026-06-09 (install.ps1:13/564 threw "Join-Path: empty Path"). Resolve
# once here with fallbacks so the installer works on any host; param defaults that
# need the script dir stay empty above and are filled from this value.
$EaScriptDir = if ($PSScriptRoot) { $PSScriptRoot }
    elseif ($PSCommandPath) { Split-Path -Parent $PSCommandPath }
    else { (Get-Location).Path }
if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $BinaryPath = Join-Path $EaScriptDir "endpoint-agent.exe"
}

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
    "ENDPOINT_AGENT_AUTO_ENROLL_CERT_SAN_URI_PREFIX",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_ENABLED",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_BROKER_ADDR",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_INSECURE_PLAINTEXT",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_MTLS_CERT_SUBJECT_SUFFIX",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_MTLS_CERT_SAN_URI_PREFIX",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_ATTESTATION_EVIDENCE_B64",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_OPERATIONS_ENABLED",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_PERMIT_BROKER_PUBLIC_KEY_B64",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_PERMIT_KEY_ID",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_PILOT_AUTO_CONSENT",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_DEVICE_KEY_SESSION_ENABLED",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ENABLED",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ATTENDED_CONSENT_ENABLED",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_MASK_RECT_BPS",
    "ENDPOINT_AGENT_REMOTE_BRIDGE_TLS_SERVER_NAME"
)

function Write-Step {
    param([string]$Message)
    Write-Host "[endpoint-agent] $Message"
}

# ---------------------------------------------------------------------------
# AG-018 internal-CA root trust (TOFU). The internal OpenSSL root that signs
# trusted-internal-ca releases is embedded here (public cert, DER base64) so
# both the URL-download and MSI-payload install paths can self-verify + import
# it WITHOUT relying on a sidecar file that the URL path may not fetch. Importing
# it makes the agent's Authenticode signature validate (Valid) on domain-joined
# AND workgroup machines alike (GPO can't reach the latter). Codex 019eb0dd.
$script:CodesignRootCertB64 = "MIIFdTCCA12gAwIBAgIUa+TQkGyCIVU0wGWGlmsb+8RNwj0wDQYJKoZIhvcNAQELBQAwUTErMCkGA1UEAwwiQUNJSyBJbnRlcm5hbCBDb2RlIFNpZ25pbmcgUm9vdCBDQTENMAsGA1UECgwEQUNJSzETMBEGA1UECwwKQUNJSyBCdWlsZDAeFw0yNjA2MTAwOTM3MTBaFw0zNjA2MDcwOTM3MTBaMFExKzApBgNVBAMMIkFDSUsgSW50ZXJuYWwgQ29kZSBTaWduaW5nIFJvb3QgQ0ExDTALBgNVBAoMBEFDSUsxEzARBgNVBAsMCkFDSUsgQnVpbGQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/b1e9q87a6ngOI0YponEHQxfyP1Fu13LMVmfBsCTaiqpWphpWig05PiChf7HFEGZe+PLXtCPOgyKlvWX4DL6fMGaLL0vLoFmMSC7mEkUvOBLhY6YiCw9U4ddjDDewNk3OcJkjgq9QmposA+FmhZbp1to6vXep8dNXmo/loCbNDuAusj/APmqPWpJ5k9buOZzTrSSdUB38HDv1QgtihPXSS5baGXT2Yu5z0euRcU+RHWkfV6WveD4CEYi2JXWr6WVYWGCpdkFkzvaaG1MOzXrIYBfejwZSdr3K2sCmEzwhnzM4Lipf/Ga6Pl5IDuwoj8WI0Sc6sXlt0wdt6t/YMF4AXIkLHchPKdPWqKGURHYImYfArayQL+LQs4Ye4R956F3unWpvBQ00c6sPNioRTC3Pc0T1hfg3Phd/kL45g+sDvAh2dBwvnNZ/bywBb9eWpkjD4f7eKv8uYwEO0o7gJacF0JozIuIbxFrdEPLn4GYjGrYI280cPe3uX9gmjZS0cc9eNLRnwVm/3BlouNiR3BML7/PiI5qqan7zynyT+pzUoCZ0AndygeFd1zU8k+2LnmJ45748STc2siVSBgVANu7SFH1uNiJsWn3zC00KDlyAu+9G3OObf4rHHZ92n/B9si1P2b6ppJm0bl9u4/Rxu2PEkxaQn2gSVMJ0+6v/JYxnowIDAQABo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUQIGX/iGYy0xN9c0z5kqVJ6BZeQkwDQYJKoZIhvcNAQELBQADggIBAHfzeNVzWnu9YJsI3i4sPJxeOhJYw3efUtH2Hp+vDSB2Pgz2Rbr6xsFypjsaTv6kNWkiXG39lvew0jH3S0J2mflc0rAR9vVMWBHF71FPLyrKoFqQmbgjq+yb6IZAFAuoNQSSRD3KGeo5BkHl2K/diNxEX/dpqByz5U5/FqUwBnTLqjS56kuDfiYcv9UzgMijXgknR0OdEUnQSQijMQhICVNSoYOo3ORHyU089REop1vbEMrMIrNjROCOe0Uf/46s6Fm8raW2QEnzrM2WK/S6ppznQZ8rq3ZSsWxDma3mn+QII5iOczpWXU5o3GxZd+EKJCZOHcfZj0oL3VnUF0NMO7W8I73l+mrV4m0+aBq1mPx189SqmsDSTWxtKz9sEuXy7uaLT/2oMtYoahrWq9SZRVSmZ7E7iyksdYkBZesQvrQKmEZqyZGZyvordsoIYlrxBjGfTXeORiBnvvxR+keTImc8Asuvypno+49s1DItvuhcxD/C8JG39tmlJ9K9PAVgC5F6oeQnRI2hSOOwXGx5LbEmS3uIM7HSJcwlOtV81Qsypu71f9erYbvMqU51VIJFdsfJgX/PVbpNdj8AdGOBSIZ6hCz+ND1cLlZgaQLQni0+juXrh/SqydQUEhragT2Jp9N5QpD9VVbsxwychrLT971d6wD+g4BF1BNGfnJct4CT"

function Import-CodesignRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Tier,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [switch]$Skip
    )
    if ($Tier -ne "trusted-internal-ca") { return }   # tier-gated; other tiers untouched

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        [Convert]::FromBase64String($script:CodesignRootCertB64))
    $actualSha = $cert.GetCertHashString("SHA256").ToUpperInvariant()
    $expectSha = ($ExpectedSha256 -replace '\s', '').ToUpperInvariant()

    # pin-match BEFORE any import  -  never import an unexpected root.
    if ([string]::IsNullOrWhiteSpace($expectSha) -or $expectSha -eq "__INJECTED_ROOT_CERT_SHA256__") {
        throw "trusted-internal-ca: -ExpectedRootCertSha256 is unset/sentinel; refusing to import an unpinned root"
    }
    if ($actualSha -ne $expectSha) {
        throw "trusted-internal-ca: embedded root SHA256 $actualSha != expected pin $expectSha (refusing import)"
    }
    if ($cert.NotAfter -lt (Get-Date)) {
        throw "trusted-internal-ca: embedded root expired $($cert.NotAfter.ToUniversalTime().ToString('o'))"
    }

    if ($Skip) {
        Write-Step "ROOT_TRUST_SKIPPED tier=$Tier thumbprint=$($cert.Thumbprint) sha256=$actualSha host=$env:COMPUTERNAME user=$env:USERNAME (operator opted out; root must be pre-trusted via GPO; signature still required Valid below)"
        return
    }

    foreach ($store in @("Root", "TrustedPublisher")) {
        $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($store, "LocalMachine")
        $s.Open("ReadWrite")
        try {
            if (-not $s.Certificates.Find("FindByThumbprint", $cert.Thumbprint, $false).Count) {
                $s.Add($cert)   # idempotent: only add when absent
            }
        } finally { $s.Close() }
    }
    Write-Step "ROOT_TRUSTED tier=$Tier thumbprint=$($cert.Thumbprint) sha256=$actualSha notAfter=$($cert.NotAfter.ToUniversalTime().ToString('o')) (imported LocalMachine Root+TrustedPublisher)"
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

function Wait-ForServiceAbsent {
    param(
        [string]$Name,
        [int]$TimeoutSeconds = 30
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-ServiceExists -Name $Name)) {
            return $true
        }
        Start-Sleep -Milliseconds 250
    }
    return (-not (Test-ServiceExists -Name $Name))
}

function Get-ServiceEnvironmentSnapshot {
    param(
        [string]$Name,
        [string]$ServicePath = ""
    )

    if ([string]::IsNullOrWhiteSpace($ServicePath)) {
        $ServicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    }
    $exists = $false
    $entries = @()
    if (Test-Path -LiteralPath $ServicePath) {
        $key = $null
        try {
            $key = Get-Item -LiteralPath $ServicePath -ErrorAction Stop
            $exists = @($key.GetValueNames()) -contains "Environment"
            if ($exists) {
                $raw = $key.GetValue("Environment", $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($null -ne $raw) {
                    $entries = @($raw)
                }
            }
        } finally {
            if ($key) { $key.Dispose() }
        }
    }
    return [pscustomobject]@{
        Exists = $exists
        Entries = $entries
    }
}

function Restore-ServiceEnvironmentSnapshot {
    param(
        [string]$Name,
        [Parameter(Mandatory)] $Snapshot,
        [string]$ServicePath = ""
    )

    if ([string]::IsNullOrWhiteSpace($ServicePath)) {
        $ServicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    }
    if (-not (Test-Path -LiteralPath $ServicePath)) {
        throw "Service registry key not found while restoring environment: $ServicePath"
    }
    if ($Snapshot.Exists) {
        New-ItemProperty -Path $ServicePath -Name "Environment" -Value @($Snapshot.Entries) -PropertyType MultiString -Force | Out-Null
    } else {
        Remove-ItemProperty -Path $ServicePath -Name "Environment" -ErrorAction SilentlyContinue
    }
}

function Assert-ServiceEnvironmentSnapshot {
    param(
        [string]$Name,
        [Parameter(Mandatory)] $Expected,
        [string]$ServicePath = ""
    )

    $actual = Get-ServiceEnvironmentSnapshot -Name $Name -ServicePath $ServicePath
    if ([bool]$actual.Exists -ne [bool]$Expected.Exists) {
        throw "restored service environment presence mismatch for $Name"
    }
    $actualEntries = @($actual.Entries | Sort-Object)
    $expectedEntries = @($Expected.Entries | Sort-Object)
    if (($actualEntries -join "`0") -cne ($expectedEntries -join "`0")) {
        throw "restored service environment content mismatch for $Name"
    }
}

function Get-ServiceSddlFromOutput {
    param(
        [object[]]$Output,
        [string]$Name
    )
    $sddl = @($output | ForEach-Object { ([string]$_).Trim() } | Where-Object {
        $_ -match '^[DOGS]:'
    } | Select-Object -First 1)
    if ($sddl.Count -ne 1 -or [string]::IsNullOrWhiteSpace($sddl[0])) {
        throw "service SDDL could not be captured for $Name"
    }
    return [string]$sddl[0]
}

function Get-ServiceSddl {
    param([string]$Name)

    $output = @(& sc.exe sdshow $Name 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe sdshow $Name failed with exit code $LASTEXITCODE"
    }
    return Get-ServiceSddlFromOutput -Output $output -Name $Name
}

function Initialize-ServiceFailurePolicyNative {
    if ($null -ne ("EndpointAgentInstaller.ServiceFailurePolicyNative" -as [type])) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace EndpointAgentInstaller
{
    public sealed class ServiceFailureAction
    {
        public int Type;
        public uint Delay;
    }

    public sealed class ServiceFailurePolicy
    {
        public uint ResetPeriod;
        public string RebootMessage;
        public string Command;
        public ServiceFailureAction[] Actions;
        public bool NonCrashFailures;
    }

    public static class ServiceFailurePolicyNative
    {
        private const uint SC_MANAGER_CONNECT = 0x0001;
        private const uint SERVICE_QUERY_CONFIG = 0x0001;
        private const uint SERVICE_CHANGE_CONFIG = 0x0002;
        private const int SERVICE_CONFIG_FAILURE_ACTIONS = 2;
        private const int SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SERVICE_FAILURE_ACTIONS
        {
            public uint dwResetPeriod;
            public IntPtr lpRebootMsg;
            public IntPtr lpCommand;
            public uint cActions;
            public IntPtr lpsaActions;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SC_ACTION
        {
            public int Type;
            public uint Delay;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_FAILURE_ACTIONS_FLAG
        {
            public int Enabled;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(
            string machineName,
            string databaseName,
            uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(
            IntPtr scm,
            string serviceName,
            uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceConfig2(
            IntPtr service,
            int infoLevel,
            IntPtr buffer,
            int bufferSize,
            out int bytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ChangeServiceConfig2(
            IntPtr service,
            int infoLevel,
            IntPtr info);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr handle);

        private static IntPtr OpenScm()
        {
            IntPtr scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
            if (scm == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
            }
            return scm;
        }

        private static IntPtr OpenServiceHandle(IntPtr scm, string name, uint access)
        {
            IntPtr service = OpenService(scm, name, access);
            if (service == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenService failed for " + name);
            }
            return service;
        }

        private static IntPtr QueryBuffer(IntPtr service, int level)
        {
            int needed;
            QueryServiceConfig2(service, level, IntPtr.Zero, 0, out needed);
            int error = Marshal.GetLastWin32Error();
            if (needed <= 0 || error != ERROR_INSUFFICIENT_BUFFER)
            {
                throw new Win32Exception(error, "QueryServiceConfig2 size query failed at level " + level);
            }
            IntPtr buffer = Marshal.AllocHGlobal(needed);
            if (!QueryServiceConfig2(service, level, buffer, needed, out needed))
            {
                error = Marshal.GetLastWin32Error();
                Marshal.FreeHGlobal(buffer);
                throw new Win32Exception(error, "QueryServiceConfig2 failed at level " + level);
            }
            return buffer;
        }

        public static ServiceFailurePolicy Capture(string serviceName)
        {
            IntPtr scm = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            IntPtr actionsBuffer = IntPtr.Zero;
            IntPtr flagBuffer = IntPtr.Zero;
            try
            {
                scm = OpenScm();
                service = OpenServiceHandle(scm, serviceName, SERVICE_QUERY_CONFIG);
                actionsBuffer = QueryBuffer(service, SERVICE_CONFIG_FAILURE_ACTIONS);
                SERVICE_FAILURE_ACTIONS native = (SERVICE_FAILURE_ACTIONS)Marshal.PtrToStructure(
                    actionsBuffer,
                    typeof(SERVICE_FAILURE_ACTIONS));

                ServiceFailureAction[] actions = new ServiceFailureAction[native.cActions];
                int actionSize = Marshal.SizeOf(typeof(SC_ACTION));
                for (int i = 0; i < actions.Length; i++)
                {
                    IntPtr actionPtr = IntPtr.Add(native.lpsaActions, i * actionSize);
                    SC_ACTION action = (SC_ACTION)Marshal.PtrToStructure(actionPtr, typeof(SC_ACTION));
                    actions[i] = new ServiceFailureAction { Type = action.Type, Delay = action.Delay };
                }

                flagBuffer = QueryBuffer(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG);
                SERVICE_FAILURE_ACTIONS_FLAG flag = (SERVICE_FAILURE_ACTIONS_FLAG)Marshal.PtrToStructure(
                    flagBuffer,
                    typeof(SERVICE_FAILURE_ACTIONS_FLAG));

                return new ServiceFailurePolicy
                {
                    ResetPeriod = native.dwResetPeriod,
                    RebootMessage = native.lpRebootMsg == IntPtr.Zero ? "" : Marshal.PtrToStringUni(native.lpRebootMsg),
                    Command = native.lpCommand == IntPtr.Zero ? "" : Marshal.PtrToStringUni(native.lpCommand),
                    Actions = actions,
                    NonCrashFailures = flag.Enabled != 0
                };
            }
            finally
            {
                if (flagBuffer != IntPtr.Zero) Marshal.FreeHGlobal(flagBuffer);
                if (actionsBuffer != IntPtr.Zero) Marshal.FreeHGlobal(actionsBuffer);
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                if (scm != IntPtr.Zero) CloseServiceHandle(scm);
            }
        }

        public static void Restore(string serviceName, ServiceFailurePolicy policy)
        {
            if (policy == null) throw new ArgumentNullException("policy");
            IntPtr scm = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            IntPtr rebootMessage = IntPtr.Zero;
            IntPtr command = IntPtr.Zero;
            IntPtr actions = IntPtr.Zero;
            IntPtr policyBuffer = IntPtr.Zero;
            IntPtr flagBuffer = IntPtr.Zero;
            try
            {
                scm = OpenScm();
                service = OpenServiceHandle(scm, serviceName, SERVICE_CHANGE_CONFIG);
                rebootMessage = Marshal.StringToHGlobalUni(policy.RebootMessage ?? "");
                command = Marshal.StringToHGlobalUni(policy.Command ?? "");

                ServiceFailureAction[] managedActions = policy.Actions ?? new ServiceFailureAction[0];
                int actionSize = Marshal.SizeOf(typeof(SC_ACTION));
                if (managedActions.Length > 0)
                {
                    actions = Marshal.AllocHGlobal(actionSize * managedActions.Length);
                    for (int i = 0; i < managedActions.Length; i++)
                    {
                        SC_ACTION action = new SC_ACTION
                        {
                            Type = managedActions[i].Type,
                            Delay = managedActions[i].Delay
                        };
                        Marshal.StructureToPtr(action, IntPtr.Add(actions, i * actionSize), false);
                    }
                }

                SERVICE_FAILURE_ACTIONS native = new SERVICE_FAILURE_ACTIONS
                {
                    dwResetPeriod = policy.ResetPeriod,
                    lpRebootMsg = rebootMessage,
                    lpCommand = command,
                    cActions = (uint)managedActions.Length,
                    lpsaActions = actions
                };
                policyBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SERVICE_FAILURE_ACTIONS)));
                Marshal.StructureToPtr(native, policyBuffer, false);
                if (!ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, policyBuffer))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ChangeServiceConfig2 failure actions failed");
                }

                SERVICE_FAILURE_ACTIONS_FLAG flag = new SERVICE_FAILURE_ACTIONS_FLAG
                {
                    Enabled = policy.NonCrashFailures ? 1 : 0
                };
                flagBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SERVICE_FAILURE_ACTIONS_FLAG)));
                Marshal.StructureToPtr(flag, flagBuffer, false);
                if (!ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, flagBuffer))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ChangeServiceConfig2 failure-actions flag failed");
                }
            }
            finally
            {
                if (flagBuffer != IntPtr.Zero) Marshal.FreeHGlobal(flagBuffer);
                if (policyBuffer != IntPtr.Zero) Marshal.FreeHGlobal(policyBuffer);
                if (actions != IntPtr.Zero) Marshal.FreeHGlobal(actions);
                if (command != IntPtr.Zero) Marshal.FreeHGlobal(command);
                if (rebootMessage != IntPtr.Zero) Marshal.FreeHGlobal(rebootMessage);
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                if (scm != IntPtr.Zero) CloseServiceHandle(scm);
            }
        }

        public static string Canonical(ServiceFailurePolicy policy)
        {
            StringBuilder value = new StringBuilder();
            value.Append(policy.ResetPeriod).Append('|');
            value.Append((policy.RebootMessage ?? "").Length).Append(':').Append(policy.RebootMessage ?? "").Append('|');
            value.Append((policy.Command ?? "").Length).Append(':').Append(policy.Command ?? "").Append('|');
            value.Append(policy.NonCrashFailures ? "1" : "0");
            ServiceFailureAction[] actions = policy.Actions ?? new ServiceFailureAction[0];
            for (int i = 0; i < actions.Length; i++)
            {
                value.Append('|').Append(actions[i].Type).Append(':').Append(actions[i].Delay);
            }
            return value.ToString();
        }
    }
}
'@
}

function Get-ServiceFailurePolicy {
    param([string]$Name)
    Initialize-ServiceFailurePolicyNative
    return [EndpointAgentInstaller.ServiceFailurePolicyNative]::Capture($Name)
}

function Restore-ServiceFailurePolicy {
    param(
        [string]$Name,
        [Parameter(Mandatory)] $Policy
    )
    Initialize-ServiceFailurePolicyNative
    [EndpointAgentInstaller.ServiceFailurePolicyNative]::Restore($Name, $Policy)
}

function Assert-ServiceFailurePolicy {
    param(
        [string]$Name,
        [Parameter(Mandatory)] $Expected
    )
    Initialize-ServiceFailurePolicyNative
    $actual = [EndpointAgentInstaller.ServiceFailurePolicyNative]::Capture($Name)
    $actualCanonical = [EndpointAgentInstaller.ServiceFailurePolicyNative]::Canonical($actual)
    $expectedCanonical = [EndpointAgentInstaller.ServiceFailurePolicyNative]::Canonical($Expected)
    if ($actualCanonical -cne $expectedCanonical) {
        throw "restored SCM failure-action policy mismatch for $Name"
    }
}

function Get-ServiceStartMode {
    param(
        [int]$StartValue,
        [bool]$DelayedAutoStart
    )
    switch ($StartValue) {
        2 { return $(if ($DelayedAutoStart) { "delayed-auto" } else { "auto" }) }
        3 { return "demand" }
        4 { return "disabled" }
        default { throw "unsupported service start value in transaction snapshot: $StartValue" }
    }
}

function Get-InstallTreeAclSnapshot {
    param([string]$Path)

    $root = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath.TrimEnd('\')
    $items = @((Get-Item -LiteralPath $root -Force -ErrorAction Stop))
    $items += @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop)
    return @($items | ForEach-Object {
        $relativePath = if ($_.FullName -eq $root) {
            "."
        } else {
            $_.FullName.Substring($root.Length).TrimStart('\')
        }
        $acl = Get-Acl -LiteralPath $_.FullName -ErrorAction Stop
        [pscustomobject]@{
            RelativePath = $relativePath
            Acl = $acl
            Sddl = [string]$acl.Sddl
        }
    })
}

function Restore-InstallTreeAclSnapshot {
    param(
        [string]$Path,
        [object[]]$Snapshot
    )

    foreach ($entry in @($Snapshot | Sort-Object { $_.RelativePath.Length } -Descending)) {
        $target = if ($entry.RelativePath -eq ".") {
            $Path
        } else {
            Join-Path $Path $entry.RelativePath
        }
        if (-not (Test-Path -LiteralPath $target)) {
            throw "install-tree ACL restore target missing: $($entry.RelativePath)"
        }
        Set-Acl -LiteralPath $target -AclObject $entry.Acl -ErrorAction Stop
    }
}

function Assert-InstallTreeAclSnapshot {
    param(
        [string]$Path,
        [object[]]$Expected
    )

    foreach ($entry in $Expected) {
        $target = if ($entry.RelativePath -eq ".") {
            $Path
        } else {
            Join-Path $Path $entry.RelativePath
        }
        if (-not (Test-Path -LiteralPath $target)) {
            throw "restored install-tree ACL target missing: $($entry.RelativePath)"
        }
        $actual = Get-Acl -LiteralPath $target -ErrorAction Stop
        if ([string]$actual.Sddl -cne [string]$entry.Sddl) {
            throw "restored install-tree ACL mismatch: $($entry.RelativePath)"
        }
    }
}

function New-ServiceReplacementSnapshot {
    param(
        [string]$Name,
        [string]$InstallPath
    )

    if (-not (Test-ServiceExists -Name $Name)) {
        return $null
    }
    $binaryPath = Join-Path $InstallPath "endpoint-agent.exe"
    if (-not (Test-Path -LiteralPath $binaryPath)) {
        Write-Warning "existing service binary is missing; continuing Force repair without transactional binary rollback: $binaryPath"
        return $null
    }

    $service = Get-Service -Name $Name -ErrorAction Stop
    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $serviceProps = Get-ItemProperty -LiteralPath $servicePath -ErrorAction Stop
    $description = ""
    if ($null -ne $serviceProps.PSObject.Properties["Description"]) {
        $description = [string]$serviceProps.Description
    }
    $delayedAutoStart = $false
    if ($null -ne $serviceProps.PSObject.Properties["DelayedAutoStart"]) {
        $delayedAutoStart = [bool]$serviceProps.DelayedAutoStart
    }
    $startValue = [int]$serviceProps.Start
    $startMode = Get-ServiceStartMode `
        -StartValue $startValue `
        -DelayedAutoStart $delayedAutoStart
    $failurePolicy = Get-ServiceFailurePolicy -Name $Name
    $serviceSddl = Get-ServiceSddl -Name $Name
    $installTreeAcl = Get-InstallTreeAclSnapshot -Path $InstallPath
    $rollbackRoot = Join-Path $env:ProgramData "EndpointAgent\rollback\$Name-$([guid]::NewGuid().ToString('N'))"
    $rollbackInstallPath = Join-Path $rollbackRoot "install"
    try {
        New-Item -ItemType Directory -Force -Path $rollbackRoot | Out-Null
        Protect-DirectoryAcl -Path $rollbackRoot
        New-Item -ItemType Directory -Force -Path $rollbackInstallPath | Out-Null
        $binarySha256BeforeCopy = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Get-ChildItem -LiteralPath $InstallPath -Force -ErrorAction Stop |
            Copy-Item -Destination $rollbackInstallPath -Recurse -Force
        $binarySha256AfterCopy = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $rollbackBinarySha256 = (Get-FileHash -LiteralPath (Join-Path $rollbackInstallPath "endpoint-agent.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($binarySha256BeforeCopy -ne $binarySha256AfterCopy -or
            $binarySha256BeforeCopy -ne $rollbackBinarySha256) {
            throw "existing service binary changed while the transaction snapshot was being captured"
        }
        $binarySha256 = $binarySha256BeforeCopy
        $environment = Get-ServiceEnvironmentSnapshot -Name $Name
    } catch {
        if (Test-Path -LiteralPath $rollbackRoot) {
            Remove-Item -LiteralPath $rollbackRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        throw
    }

    return [pscustomobject]@{
        Name = $Name
        InstallPath = $InstallPath
        RollbackRoot = $rollbackRoot
        RollbackInstallPath = $rollbackInstallPath
        BinarySha256 = $binarySha256
        Environment = $environment
        DisplayName = $service.DisplayName
        Description = $description
        StartValue = $startValue
        StartMode = $startMode
        DelayedAutoStart = $delayedAutoStart
        WasRunning = ($service.Status -eq "Running")
        FailurePolicy = $failurePolicy
        ServiceSddl = $serviceSddl
        InstallTreeAcl = $installTreeAcl
    }
}

function Remove-ServiceReplacementSnapshot {
    param($Snapshot)
    if ($null -ne $Snapshot -and (Test-Path -LiteralPath $Snapshot.RollbackRoot)) {
        Remove-Item -LiteralPath $Snapshot.RollbackRoot -Recurse -Force
    }
}

function Restore-ServiceReplacementSnapshot {
    param(
        [Parameter(Mandatory)] $Snapshot,
        [int]$StartTimeoutSeconds = 30,
        [string]$MaintenanceToken = "",
        [string]$MaintenanceTokenHash = ""
    )

    if (-not (Test-Path -LiteralPath $Snapshot.RollbackInstallPath)) {
        throw "transaction rollback payload missing: $($Snapshot.RollbackInstallPath)"
    }
    if (Test-ServiceExists -Name $Snapshot.Name) {
        $currentBinary = Join-Path $Snapshot.InstallPath "endpoint-agent.exe"
        Remove-ServiceBestEffort `
            -Name $Snapshot.Name `
            -ExePath $currentBinary `
            -Token $MaintenanceToken `
            -TokenHash $MaintenanceTokenHash
        if (-not (Wait-ForServiceAbsent -Name $Snapshot.Name -TimeoutSeconds 30)) {
            throw "existing service entry could not be removed before transaction rollback restore: $($Snapshot.Name)"
        }
    }
    if (Test-Path -LiteralPath $Snapshot.InstallPath) {
        Remove-Item -LiteralPath $Snapshot.InstallPath -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $Snapshot.InstallPath | Out-Null
    Get-ChildItem -LiteralPath $Snapshot.RollbackInstallPath -Force -ErrorAction Stop |
        Copy-Item -Destination $Snapshot.InstallPath -Recurse -Force
    Restore-InstallTreeAclSnapshot `
        -Path $Snapshot.InstallPath `
        -Snapshot $Snapshot.InstallTreeAcl

    $restoredBinary = Join-Path $Snapshot.InstallPath "endpoint-agent.exe"
    $restoredSha = (Get-FileHash -LiteralPath $restoredBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($restoredSha -ne $Snapshot.BinarySha256) {
        throw "transaction rollback binary hash mismatch for $restoredBinary"
    }

    Invoke-AgentServiceCommand -ExePath $restoredBinary -Arguments @(
        "service", "install",
        "--name", $Snapshot.Name,
        "--display-name", $Snapshot.DisplayName,
        "--description", $Snapshot.Description
    )
    Restore-ServiceEnvironmentSnapshot -Name $Snapshot.Name -Snapshot $Snapshot.Environment
    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Snapshot.Name)"
    Restore-ServiceFailurePolicy `
        -Name $Snapshot.Name `
        -Policy $Snapshot.FailurePolicy
    Invoke-NativeCommand -FilePath "sc.exe" -Arguments @("sdset", $Snapshot.Name, $Snapshot.ServiceSddl)
    Invoke-NativeCommand -FilePath "sc.exe" -Arguments @("config", $Snapshot.Name, "start=", $Snapshot.StartMode)

    Assert-ServiceEnvironmentSnapshot -Name $Snapshot.Name -Expected $Snapshot.Environment
    Assert-ServiceFailurePolicy `
        -Name $Snapshot.Name `
        -Expected $Snapshot.FailurePolicy
    $restoredServiceSddl = Get-ServiceSddl -Name $Snapshot.Name
    if ($restoredServiceSddl -cne [string]$Snapshot.ServiceSddl) {
        throw "restored service SDDL mismatch for $($Snapshot.Name)"
    }
    Assert-InstallTreeAclSnapshot `
        -Path $Snapshot.InstallPath `
        -Expected $Snapshot.InstallTreeAcl
    $restoredServiceProps = Get-ItemProperty `
        -LiteralPath $servicePath `
        -ErrorAction Stop
    if ([int]$restoredServiceProps.Start -ne [int]$Snapshot.StartValue) {
        throw "restored service start mode mismatch for $($Snapshot.Name)"
    }
    $actualDelayedAutoStart = $false
    if (@($restoredServiceProps.PSObject.Properties.Name) -contains "DelayedAutoStart") {
        $actualDelayedAutoStart = [bool]$restoredServiceProps.DelayedAutoStart
    }
    if ($actualDelayedAutoStart -ne [bool]$Snapshot.DelayedAutoStart) {
        throw "restored service delayed-auto-start mismatch for $($Snapshot.Name)"
    }
    $actualDescription = ""
    if ($null -ne $restoredServiceProps.PSObject.Properties["Description"]) {
        $actualDescription = [string]$restoredServiceProps.Description
    }
    if ($actualDescription -cne [string]$Snapshot.Description) {
        throw "restored service description mismatch for $($Snapshot.Name)"
    }
    $restoredService = Get-Service -Name $Snapshot.Name -ErrorAction Stop
    if ([string]$restoredService.DisplayName -cne [string]$Snapshot.DisplayName) {
        throw "restored service display-name mismatch for $($Snapshot.Name)"
    }
    if ($Snapshot.WasRunning) {
        Invoke-AgentServiceCommand -ExePath $restoredBinary -Arguments @("service", "start", "--name", $Snapshot.Name)
        if (-not (Wait-ForServiceRunning -Name $Snapshot.Name -TimeoutSeconds $StartTimeoutSeconds)) {
            throw "restored service '$($Snapshot.Name)' did not reach Running"
        }
    }
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

function Assert-AgentBinaryRunnable {
    param([string]$Path)

    $versionOutput = @(& $Path --version 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "endpoint-agent binary readiness check failed with exit code $LASTEXITCODE"
    }
    if ($versionOutput.Count -eq 0 -or [string]::IsNullOrWhiteSpace(([string]$versionOutput[0]))) {
        throw "endpoint-agent binary readiness check returned no version"
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

function Assert-ViewOnlyMaskRectBPS {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return
    }
    if ($Value -notmatch '^[0-9]{1,5},[0-9]{1,5},[0-9]{1,5},[0-9]{1,5}$') {
        throw "-RemoteBridgeViewOnlyMaskRectBPS must be canonical x,y,width,height basis points."
    }
    $parts = @($Value.Split(',') | ForEach-Object { [int]$_ })
    if (@($parts | Where-Object { $_ -lt 0 -or $_ -gt 10000 }).Count -gt 0) {
        throw "-RemoteBridgeViewOnlyMaskRectBPS fields must be between 0 and 10000."
    }
    if ($parts[2] -le 0 -or $parts[3] -le 0) {
        throw "-RemoteBridgeViewOnlyMaskRectBPS width and height must be positive."
    }
    if (($parts[0] + $parts[2]) -gt 10000 -or ($parts[1] + $parts[3]) -gt 10000) {
        throw "-RemoteBridgeViewOnlyMaskRectBPS must fit inside the primary monitor."
    }
}

function Assert-RemoteBridgeInstallConfig {
    param(
        [bool]$Enabled,
        [string]$BrokerAddr,
        [bool]$InsecurePlaintext,
        [string]$CertSubjectSuffix = "",
        [string]$CertSANURIPrefix = "",
        [string]$AttestationEvidenceB64 = "",
        [bool]$OperationsEnabled = $false,
        [string]$PermitBrokerPublicKeyB64 = "",
        [string]$PermitKeyID = "",
        [bool]$PilotAutoConsent = $false,
        [bool]$DeviceKeySessionEnabled = $false,
        [bool]$ViewOnlyEnabled = $false,
        [bool]$ViewOnlyAttendedConsent = $false,
        [string]$ViewOnlyMaskRectBPS = "",
        [string]$TLSServerName = ""
    )
    if ($Enabled) {
        if ([string]::IsNullOrWhiteSpace($BrokerAddr)) {
            throw "-RemoteBridgeEnabled requires -RemoteBridgeBrokerAddr."
        }
        $operationCapable = $OperationsEnabled -or $ViewOnlyEnabled
        if ($operationCapable) {
            if ([string]::IsNullOrWhiteSpace($PermitBrokerPublicKeyB64) -or [string]::IsNullOrWhiteSpace($PermitKeyID)) {
                throw "remote-bridge operation-capable policy requires -RemoteBridgePermitBrokerPublicKeyB64 and -RemoteBridgePermitKeyID."
            }
        }
        if ($PilotAutoConsent -and -not $OperationsEnabled) {
            throw "-RemoteBridgePilotAutoConsent requires -RemoteBridgeOperationsEnabled."
        }
        if ($DeviceKeySessionEnabled -and -not $OperationsEnabled) {
            throw "-RemoteBridgeDeviceKeySessionEnabled requires -RemoteBridgeOperationsEnabled."
        }
        if ($ViewOnlyAttendedConsent -and -not $ViewOnlyEnabled) {
            throw "-RemoteBridgeViewOnlyAttendedConsent requires -RemoteBridgeViewOnlyEnabled."
        }
        if (-not [string]::IsNullOrWhiteSpace($ViewOnlyMaskRectBPS) -and -not $ViewOnlyEnabled) {
            throw "-RemoteBridgeViewOnlyMaskRectBPS requires -RemoteBridgeViewOnlyEnabled."
        }
        Assert-ViewOnlyMaskRectBPS -Value $ViewOnlyMaskRectBPS
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($BrokerAddr)) {
        throw "-RemoteBridgeBrokerAddr requires -RemoteBridgeEnabled."
    }
    if ($InsecurePlaintext) {
        throw "-RemoteBridgeInsecurePlaintext requires -RemoteBridgeEnabled."
    }
    if (-not [string]::IsNullOrWhiteSpace($CertSubjectSuffix)) {
        throw "-RemoteBridgeMTLSCertSubjectSuffix requires -RemoteBridgeEnabled."
    }
    if (-not [string]::IsNullOrWhiteSpace($CertSANURIPrefix)) {
        throw "-RemoteBridgeMTLSCertSANURIPrefix requires -RemoteBridgeEnabled."
    }
    if (-not [string]::IsNullOrWhiteSpace($AttestationEvidenceB64)) {
        throw "-RemoteBridgeAttestationEvidenceB64 requires -RemoteBridgeEnabled."
    }
    if ($OperationsEnabled) {
        throw "-RemoteBridgeOperationsEnabled requires -RemoteBridgeEnabled."
    }
    if (-not [string]::IsNullOrWhiteSpace($PermitBrokerPublicKeyB64)) {
        throw "-RemoteBridgePermitBrokerPublicKeyB64 requires -RemoteBridgeEnabled."
    }
    if (-not [string]::IsNullOrWhiteSpace($PermitKeyID)) {
        throw "-RemoteBridgePermitKeyID requires -RemoteBridgeEnabled."
    }
    if ($PilotAutoConsent) {
        throw "-RemoteBridgePilotAutoConsent requires -RemoteBridgeEnabled."
    }
    if ($DeviceKeySessionEnabled) {
        throw "-RemoteBridgeDeviceKeySessionEnabled requires -RemoteBridgeEnabled."
    }
    if ($ViewOnlyEnabled) {
        throw "-RemoteBridgeViewOnlyEnabled requires -RemoteBridgeEnabled."
    }
    if ($ViewOnlyAttendedConsent) {
        throw "-RemoteBridgeViewOnlyAttendedConsent requires -RemoteBridgeEnabled."
    }
    if (-not [string]::IsNullOrWhiteSpace($ViewOnlyMaskRectBPS)) {
        throw "-RemoteBridgeViewOnlyMaskRectBPS requires -RemoteBridgeEnabled."
    }
    if (-not [string]::IsNullOrWhiteSpace($TLSServerName)) {
        throw "-RemoteBridgeTLSServerName requires -RemoteBridgeEnabled."
    }
}

function Add-RemoteBridgeServiceEnvironment {
    param(
        [hashtable]$Values,
        [bool]$Enabled,
        [string]$BrokerAddr,
        [bool]$InsecurePlaintext,
        [string]$CertSubjectSuffix = "",
        [string]$CertSANURIPrefix = "",
        [string]$AttestationEvidenceB64 = "",
        [bool]$OperationsEnabled = $false,
        [string]$PermitBrokerPublicKeyB64 = "",
        [string]$PermitKeyID = "",
        [bool]$PilotAutoConsent = $false,
        [bool]$DeviceKeySessionEnabled = $false,
        [bool]$ViewOnlyEnabled = $false,
        [bool]$ViewOnlyAttendedConsent = $false,
        [string]$ViewOnlyMaskRectBPS = "",
        [string]$TLSServerName = ""
    )
    if (-not $Enabled) {
        return
    }

    $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_ENABLED"] = "true"
    $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_BROKER_ADDR"] = $BrokerAddr
    if ($InsecurePlaintext) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_INSECURE_PLAINTEXT"] = "true"
    }
    if (-not [string]::IsNullOrWhiteSpace($CertSubjectSuffix)) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_MTLS_CERT_SUBJECT_SUFFIX"] = $CertSubjectSuffix
    }
    if (-not [string]::IsNullOrWhiteSpace($CertSANURIPrefix)) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_MTLS_CERT_SAN_URI_PREFIX"] = $CertSANURIPrefix
    }
    if (-not [string]::IsNullOrWhiteSpace($AttestationEvidenceB64)) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_ATTESTATION_EVIDENCE_B64"] = $AttestationEvidenceB64
    }
    if ($OperationsEnabled) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_OPERATIONS_ENABLED"] = "true"
    }
    if (-not [string]::IsNullOrWhiteSpace($PermitBrokerPublicKeyB64)) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_PERMIT_BROKER_PUBLIC_KEY_B64"] = $PermitBrokerPublicKeyB64
    }
    if (-not [string]::IsNullOrWhiteSpace($PermitKeyID)) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_PERMIT_KEY_ID"] = $PermitKeyID
    }
    if ($PilotAutoConsent) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_PILOT_AUTO_CONSENT"] = "true"
    }
    if ($DeviceKeySessionEnabled) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_DEVICE_KEY_SESSION_ENABLED"] = "true"
    }
    if ($ViewOnlyEnabled) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ENABLED"] = "true"
    }
    if ($ViewOnlyAttendedConsent) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_ATTENDED_CONSENT_ENABLED"] = "true"
    }
    if (-not [string]::IsNullOrWhiteSpace($ViewOnlyMaskRectBPS)) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_VIEW_ONLY_MASK_RECT_BPS"] = $ViewOnlyMaskRectBPS
    }
    if (-not [string]::IsNullOrWhiteSpace($TLSServerName)) {
        $Values["ENDPOINT_AGENT_REMOTE_BRIDGE_TLS_SERVER_NAME"] = $TLSServerName
    }
}

function Resolve-SelfUpdateSignerThumbprints {
    param(
        [string]$ExplicitThumbprints,
        [string]$VerifiedSignerSha256Thumbprint
    )
    if (-not [string]::IsNullOrWhiteSpace($ExplicitThumbprints)) {
        return (Normalize-SelfUpdateSignerSha256Thumbprints -Thumbprints $ExplicitThumbprints)
    }
    if (-not [string]::IsNullOrWhiteSpace($VerifiedSignerSha256Thumbprint)) {
        return $VerifiedSignerSha256Thumbprint
    }
    return ""
}

function Normalize-SelfUpdateSignerSha256Thumbprints {
    param(
        [string]$Thumbprints
    )

    if ([string]::IsNullOrWhiteSpace($Thumbprints)) {
        return ""
    }

    $normalized = @()
    foreach ($entry in ($Thumbprints -split ",")) {
        $value = (($entry.Trim().ToUpperInvariant() -replace ":", "") -replace " ", "")
        if ($value -notmatch "^[0-9A-F]{64}$") {
            throw "-SelfUpdateSignerThumbprints entries must be SHA256 certificate fingerprints (64 hex chars)."
        }
        $normalized += $value
    }

    return ($normalized -join ",")
}

function Get-CertificateRawSha256Thumbprint {
    param(
        [Parameter(Mandatory)] $Certificate
    )

    if ($null -eq $Certificate.RawData -or $Certificate.RawData.Length -eq 0) {
        throw "certificate raw data missing; cannot derive self-update signer fingerprint"
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([byte[]]$Certificate.RawData)
        return (($hash | ForEach-Object { $_.ToString("X2") }) -join "")
    } finally {
        if ($null -ne $sha) {
            $sha.Dispose()
        }
    }
}

function Get-SelfUpdateSignerSha256ThumbprintFromBinary {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [string]$ExpectedThumbprint
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedThumbprint) -or $ExpectedThumbprint -eq "__INJECTED_EXPECTED_THUMBPRINT__") {
        throw "-SelfUpdateEnabled requires explicit -SelfUpdateSignerThumbprints or release-patched -ExpectedSignerThumbprint."
    }

    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if (-not $sig.SignerCertificate) {
        throw "binary is unsigned; cannot derive self-update signer fingerprint"
    }

    $actualThumb = $sig.SignerCertificate.Thumbprint
    if ($actualThumb -ne $ExpectedThumbprint.ToUpperInvariant()) {
        throw "signer thumbprint mismatch: expected $ExpectedThumbprint, got $actualThumb"
    }

    return Get-CertificateRawSha256Thumbprint -Certificate $sig.SignerCertificate
}

function Assert-SelfUpdateInstallConfig {
    param(
        [bool]$Enabled,
        [string]$AllowedHosts,
        [string]$SignerThumbprints,
        [string]$HardMaxBytes,
        [int]$MaxRedirects,
        [bool]$AutoActivate,
        [string]$ActivationTimeout,
        [string]$CommandTimeout
    )
    if ($Enabled) {
        if ([string]::IsNullOrWhiteSpace($AllowedHosts)) {
            throw "-SelfUpdateEnabled requires -SelfUpdateAllowedHosts."
        }
        if ([string]::IsNullOrWhiteSpace($SignerThumbprints)) {
            throw "-SelfUpdateEnabled requires -SelfUpdateSignerThumbprints or a release-patched -ExpectedSignerThumbprint."
        }
        [int64]$maxBytes = 0
        if (-not [int64]::TryParse($HardMaxBytes, [ref]$maxBytes) -or $maxBytes -le 0) {
            throw "-SelfUpdateHardMaxBytes must be a positive integer."
        }
        if ($MaxRedirects -lt 0) {
            throw "-SelfUpdateMaxRedirects must be zero or greater."
        }
        if ($AutoActivate -and [string]::IsNullOrWhiteSpace($ActivationTimeout)) {
            throw "-SelfUpdateAutoActivate requires -SelfUpdateActivationTimeout."
        }
        if ([string]::IsNullOrWhiteSpace($CommandTimeout)) {
            throw "-SelfUpdateCommandTimeout must not be empty when -SelfUpdateEnabled is set."
        }
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($AllowedHosts)) {
        throw "-SelfUpdateAllowedHosts requires -SelfUpdateEnabled."
    }
    if (-not [string]::IsNullOrWhiteSpace($SignerThumbprints)) {
        throw "-SelfUpdateSignerThumbprints requires -SelfUpdateEnabled."
    }
    if ($AutoActivate) {
        throw "-SelfUpdateAutoActivate requires -SelfUpdateEnabled."
    }
}

function Add-SelfUpdateServiceEnvironment {
    param(
        [hashtable]$Values,
        [bool]$Enabled,
        [string]$AllowedHosts,
        [string]$SignerThumbprints,
        [string]$HardMaxBytes,
        [int]$MaxRedirects,
        [bool]$AutoActivate,
        [string]$ActivationTimeout,
        [string]$ServiceName,
        [string]$CommandTimeout
    )
    if (-not $Enabled) {
        return
    }

    $Values["ENDPOINT_AGENT_SELF_UPDATE_ENABLED"] = "true"
    $Values["ENDPOINT_AGENT_SELF_UPDATE_ALLOWED_HOSTS"] = $AllowedHosts
    $Values["ENDPOINT_AGENT_SELF_UPDATE_SIGNER_THUMBPRINTS"] = $SignerThumbprints
    $Values["ENDPOINT_AGENT_SELF_UPDATE_HARD_MAX_BYTES"] = $HardMaxBytes
    $Values["ENDPOINT_AGENT_SELF_UPDATE_MAX_REDIRECTS"] = [string]$MaxRedirects
    if ($AutoActivate) {
        $Values["ENDPOINT_AGENT_SELF_UPDATE_AUTO_ACTIVATE"] = "true"
    }
    if (-not [string]::IsNullOrWhiteSpace($ActivationTimeout)) {
        $Values["ENDPOINT_AGENT_SELF_UPDATE_ACTIVATION_TIMEOUT"] = $ActivationTimeout
    }
    if (-not [string]::IsNullOrWhiteSpace($ServiceName)) {
        $Values["ENDPOINT_AGENT_SELF_UPDATE_SERVICE_NAME"] = $ServiceName
    }
    if (-not [string]::IsNullOrWhiteSpace($CommandTimeout)) {
        $Values["ENDPOINT_AGENT_SELF_UPDATE_COMMAND_TIMEOUT"] = $CommandTimeout
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
        $entry = [pscustomobject]@{
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
    foreach ($registryName in @("Mode", "ApiUrl", "EnrollmentJitterSeconds")) {
        $entry = $Snapshot[$registryName]
        if ($null -eq $entry) {
            continue
        }
        $exists = [bool]$entry.Exists
        if ($exists) {
            if (-not (Test-Path -LiteralPath $Path)) {
                New-Item -Path $Path -Force | Out-Null
            }
            $propertyType = [string]$entry.Kind
            $propertyValue = $entry.Value
            switch ($propertyType) {
                "DWord" {
                    New-ItemProperty -Path $Path -Name $registryName -Value ([int]$propertyValue) -PropertyType DWord -Force | Out-Null
                }
                default {
                    New-ItemProperty -Path $Path -Name $registryName -Value ([string]$propertyValue) -PropertyType String -Force | Out-Null
                }
            }
        } elseif (Test-Path -LiteralPath $Path) {
            Remove-ItemProperty -Path $Path -Name $registryName -ErrorAction SilentlyContinue
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

function Wait-ForServiceRunning {
    param(
        [string]$Name,
        [int]$TimeoutSeconds = 30
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -eq "Running") {
            return $true
        }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Get-AgentLogTailForError {
    param(
        [string]$LogPath,
        [int]$LineCount = 40
    )
    if (-not (Test-Path -LiteralPath $LogPath)) {
        return "agent log not found: $LogPath"
    }
    try {
        $lines = Get-Content -LiteralPath $LogPath -Tail $LineCount -ErrorAction Stop
        $joined = ($lines -join " | ")
        if ([string]::IsNullOrWhiteSpace($joined)) {
            return "agent log exists but has no recent lines: $LogPath"
        }
        if ($joined.Length -gt 4096) {
            return $joined.Substring($joined.Length - 4096)
        }
        return $joined
    } catch {
        return "agent log tail read failed: $($_.Exception.Message)"
    }
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

function Restore-HmacCredentialStoreBackup {
    param(
        [string]$CredentialStorePath,
        [string]$BackupPath
    )
    if ([string]::IsNullOrWhiteSpace($BackupPath)) {
        return
    }
    if (-not (Test-Path -LiteralPath $BackupPath)) {
        throw "HMAC credential-store rollback backup not found: $BackupPath"
    }
    if (Test-Path -LiteralPath $CredentialStorePath) {
        Remove-Item -LiteralPath $CredentialStorePath -Force
    }
    Move-Item -LiteralPath $BackupPath -Destination $CredentialStorePath -Force
    Write-Step "restored previous HMAC credential store after failed fresh enrollment"
}

function Assert-HmacCredentialResetConfirmed {
    param(
        [string]$BackupPath,
        [bool]$Confirmed
    )
    if (-not [string]::IsNullOrWhiteSpace($BackupPath) -and -not $Confirmed) {
        throw "fresh HMAC enrollment was not confirmed; refusing to commit over the previous credential store"
    }
}

# #120: fail-loud on a truncated-paste enrollment token. A blank/absent token is
# a no-op (the AgentId/AgentSecret HMAC variant + the -AutoEnroll path carry no
# token). Throws BEFORE any service/config mutation so a 1-char paste never
# silently installs a bad-token agent that then fails auth.
function Assert-EnrollmentTokenLength {
    param(
        [string]$Token,
        [int]$MinLength
    )
    if ([string]::IsNullOrWhiteSpace($Token)) {
        return
    }
    $trimmed = $Token.Trim()
    if ($trimmed.Length -lt $MinLength) {
        throw ("-EnrollmentToken is only $($trimmed.Length) character(s); a valid signed enrollment token is " +
            "far longer (likely a truncated paste). Refusing to install a bad-token agent. Re-run with the full " +
            "token, e.g. -EnrollmentToken (Get-Clipboard).")
    }
}

Assert-Administrator

# AG-018: import the internal-CA root BEFORE any binary signature check, so a
# trusted-internal-ca release validates as Valid on this machine (domain-joined
# or workgroup). Tier-gated + pin-matched + audited; no-op for other tiers.
Import-CodesignRoot -Tier $SigningTier -ExpectedSha256 $ExpectedRootCertSha256 -Skip:$SkipRootTrust

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
} else {
    # #120: HMAC enrollment-token path. Fail-loud on a truncated-paste token
    # BEFORE any service/config mutation (the MKR-A1 live pilot captured a single
    # char over AnyDesk and silently installed a bad-token agent that then failed
    # auth). No-op when no token is supplied (the AgentId/AgentSecret variant).
    Assert-EnrollmentTokenLength -Token $EnrollmentToken -MinLength $MinEnrollmentTokenLength
}

Assert-RemoteBridgeInstallConfig `
    -Enabled ([bool]$RemoteBridgeEnabled) `
    -BrokerAddr $RemoteBridgeBrokerAddr `
    -InsecurePlaintext ([bool]$RemoteBridgeInsecurePlaintext) `
    -CertSubjectSuffix $RemoteBridgeMTLSCertSubjectSuffix `
    -CertSANURIPrefix $RemoteBridgeMTLSCertSANURIPrefix `
    -AttestationEvidenceB64 $RemoteBridgeAttestationEvidenceB64 `
    -OperationsEnabled ([bool]$RemoteBridgeOperationsEnabled) `
    -PermitBrokerPublicKeyB64 $RemoteBridgePermitBrokerPublicKeyB64 `
    -PermitKeyID $RemoteBridgePermitKeyID `
    -PilotAutoConsent ([bool]$RemoteBridgePilotAutoConsent) `
    -DeviceKeySessionEnabled ([bool]$RemoteBridgeDeviceKeySessionEnabled) `
    -ViewOnlyEnabled ([bool]$RemoteBridgeViewOnlyEnabled) `
    -ViewOnlyAttendedConsent ([bool]$RemoteBridgeViewOnlyAttendedConsent) `
    -ViewOnlyMaskRectBPS $RemoteBridgeViewOnlyMaskRectBPS `
    -TLSServerName $RemoteBridgeTLSServerName

$resolvedSelfUpdateSignerThumbprints = Resolve-SelfUpdateSignerThumbprints `
    -ExplicitThumbprints $SelfUpdateSignerThumbprints `
    -VerifiedSignerSha256Thumbprint ""
$resolvedSelfUpdateServiceName = if ([string]::IsNullOrWhiteSpace($SelfUpdateServiceName)) { $ServiceName } else { $SelfUpdateServiceName }

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
                # Legacy trusted tier MUST chain to a trusted root on the
                # endpoint at install time. Anything but Valid is rejected.
                if ($sig.Status -ne "Valid") {
                    throw "trusted-signing tier requires Authenticode Status=Valid (got $($sig.Status): $($sig.StatusMessage))"
                }
            }
            "trusted-internal-ca" {
                # AG-018 internal-CA tier: the internal root was imported by
                # Import-CodesignRoot before this check (unless -SkipRootTrust,
                # which requires the root pre-trusted via GPO). Either way the
                # signature MUST be Valid here  -  the internal CA is a real trust
                # anchor on this machine, so NotTrusted is a genuine failure.
                if ($sig.Status -ne "Valid") {
                    throw "trusted-internal-ca tier requires Authenticode Status=Valid (got $($sig.Status): $($sig.StatusMessage)). The internal root must be trusted (Import-CodesignRoot, or GPO when -SkipRootTrust)."
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
Assert-AgentBinaryRunnable -Path $sourceBinary.ProviderPath
if ($SelfUpdateEnabled -and [string]::IsNullOrWhiteSpace($resolvedSelfUpdateSignerThumbprints)) {
    $verifiedSelfUpdateSignerThumbprint = Get-SelfUpdateSignerSha256ThumbprintFromBinary `
        -Path $sourceBinary.ProviderPath `
        -ExpectedThumbprint $ExpectedSignerThumbprint
    $resolvedSelfUpdateSignerThumbprints = Resolve-SelfUpdateSignerThumbprints `
        -ExplicitThumbprints $SelfUpdateSignerThumbprints `
        -VerifiedSignerSha256Thumbprint $verifiedSelfUpdateSignerThumbprint
}
Assert-SelfUpdateInstallConfig `
    -Enabled ([bool]$SelfUpdateEnabled) `
    -AllowedHosts $SelfUpdateAllowedHosts `
    -SignerThumbprints $resolvedSelfUpdateSignerThumbprints `
    -HardMaxBytes $SelfUpdateHardMaxBytes `
    -MaxRedirects $SelfUpdateMaxRedirects `
    -AutoActivate ([bool]$SelfUpdateAutoActivate) `
    -ActivationTimeout $SelfUpdateActivationTimeout `
    -CommandTimeout $SelfUpdateCommandTimeout

$targetBinary = Join-Path $InstallDir "endpoint-agent.exe"
$originalValues = @{}
$autoEnrollRegistrySnapshot = $null
$autoEnrollRegistryTouched = $false
$copiedBinary = $false
$installedService = $false
$resolvedMaintenanceTokenHash = Resolve-MaintenanceTokenHash -Token $MaintenanceToken -Hash $MaintenanceTokenHash
$hmacCredentialStorePath = Get-HmacCredentialStorePath
$hmacCredentialStoreBackup = ""
$freshHmacCredentialConfirmed = $false
$replacementSnapshot = $null

try {
    # Codex 019e7314 iter-2 P1: non-destructive existence check FIRST.
    # An accidental install run without -Force on an existing service
    # MUST NOT touch the service-specific Environment regkey, because
    # the running service is consuming that config and any silent
    # cleanup would leave it credential-less on the next restart.
    $serviceExists = Test-ServiceExists -Name $ServiceName
    if ($serviceExists -and -not $Force) {
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
            if ((Test-Path -LiteralPath $hmacCredentialStorePath) -and -not $Start) {
                throw "-ResetCredentialStore over an existing credential requires -Start so fresh enrollment can be confirmed or rolled back."
            }
            $hmacCredentialStoreBackup = Backup-HmacCredentialStoreForFreshEnroll `
                -CredentialStorePath $hmacCredentialStorePath
        }
    }

    if ($serviceExists -and $Force) {
        Write-Step "snapshotting existing service for transactional replacement"
        $replacementSnapshot = New-ServiceReplacementSnapshot `
            -Name $ServiceName `
            -InstallPath $InstallDir
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
    if ($serviceExists -and $Force) {
        Write-Step "clearing stale service env regkey: $ServiceName\\Environment"
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name 'Environment' -ErrorAction SilentlyContinue
        Write-Step "existing service found; uninstalling $ServiceName"
        $uninstallScript = Join-Path $EaScriptDir "uninstall.ps1"
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
        if (-not (Wait-ForServiceAbsent -Name $ServiceName -TimeoutSeconds 30)) {
            throw "existing service entry remained marked for deletion after Force uninstall: $ServiceName"
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

    Add-RemoteBridgeServiceEnvironment `
        -Values $serviceEnv `
        -Enabled ([bool]$RemoteBridgeEnabled) `
        -BrokerAddr $RemoteBridgeBrokerAddr `
        -InsecurePlaintext ([bool]$RemoteBridgeInsecurePlaintext) `
        -CertSubjectSuffix $RemoteBridgeMTLSCertSubjectSuffix `
        -CertSANURIPrefix $RemoteBridgeMTLSCertSANURIPrefix `
        -AttestationEvidenceB64 $RemoteBridgeAttestationEvidenceB64 `
        -OperationsEnabled ([bool]$RemoteBridgeOperationsEnabled) `
        -PermitBrokerPublicKeyB64 $RemoteBridgePermitBrokerPublicKeyB64 `
        -PermitKeyID $RemoteBridgePermitKeyID `
        -PilotAutoConsent ([bool]$RemoteBridgePilotAutoConsent) `
        -DeviceKeySessionEnabled ([bool]$RemoteBridgeDeviceKeySessionEnabled) `
        -ViewOnlyEnabled ([bool]$RemoteBridgeViewOnlyEnabled) `
        -ViewOnlyAttendedConsent ([bool]$RemoteBridgeViewOnlyAttendedConsent) `
        -ViewOnlyMaskRectBPS $RemoteBridgeViewOnlyMaskRectBPS `
        -TLSServerName $RemoteBridgeTLSServerName

    Add-SelfUpdateServiceEnvironment `
        -Values $serviceEnv `
        -Enabled ([bool]$SelfUpdateEnabled) `
        -AllowedHosts $SelfUpdateAllowedHosts `
        -SignerThumbprints $resolvedSelfUpdateSignerThumbprints `
        -HardMaxBytes $SelfUpdateHardMaxBytes `
        -MaxRedirects $SelfUpdateMaxRedirects `
        -AutoActivate ([bool]$SelfUpdateAutoActivate) `
        -ActivationTimeout $SelfUpdateActivationTimeout `
        -ServiceName $resolvedSelfUpdateServiceName `
        -CommandTimeout $SelfUpdateCommandTimeout

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
        if (-not (Wait-ForServiceRunning -Name $ServiceName -TimeoutSeconds $ServiceStartTimeoutSeconds)) {
            $recentLog = Get-AgentLogTailForError -LogPath $agentLog -LineCount 40
            throw "Service '$ServiceName' did not reach Running within ${ServiceStartTimeoutSeconds}s after start. Recent agent log: $recentLog"
        }
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
            $freshHmacCredentialConfirmed = $true
            Write-Step "AG-026C: enroll confirmed - removing token from service env regkey"
            Remove-ServiceEnvironmentEntry -Name $ServiceName -Key "ENDPOINT_AGENT_ENROLLMENT_TOKEN"
        } else {
            Write-Warning "AG-026C: 'hmac credential confirmed' sentinel not seen within 60s; token left in service env regkey for next restart retry"
        }
    }

    Assert-HmacCredentialResetConfirmed `
        -BackupPath $hmacCredentialStoreBackup `
        -Confirmed $freshHmacCredentialConfirmed

    if (-not [string]::IsNullOrWhiteSpace($hmacCredentialStoreBackup)) {
        if ($freshHmacCredentialConfirmed) {
            try {
                Remove-Item -LiteralPath $hmacCredentialStoreBackup -Force -ErrorAction Stop
                $hmacCredentialStoreBackup = ""
                Write-Step "removed superseded HMAC credential-store backup after confirmed fresh enrollment"
            } catch {
                Write-Warning "fresh enrollment is confirmed, but superseded HMAC credential-store backup cleanup failed: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "fresh enrollment was not confirmed in this install window; previous HMAC credential-store backup retained for recovery"
        }
    }

    if ($null -ne $replacementSnapshot) {
        try {
            Remove-ServiceReplacementSnapshot -Snapshot $replacementSnapshot
        } catch {
            Write-Warning "installed service is healthy, but rollback payload cleanup failed at $($replacementSnapshot.RollbackRoot): $($_.Exception.Message)"
        }
        $replacementSnapshot = $null
    }
    Write-Step "install completed"
} catch {
    $installError = $_
    $cleanupRollbackFailures = @()
    $stateRollbackFailures = @()
    $restoredPreviousService = $false
    Write-Warning "install failed: $($installError.Exception.Message)"
    Write-Step "rollback started"
    if ($installedService -and (Test-Path -LiteralPath $targetBinary)) {
        try {
            Remove-ServiceBestEffort -Name $ServiceName -ExePath $targetBinary -Token $MaintenanceToken -TokenHash $resolvedMaintenanceTokenHash
        } catch {
            Write-Warning "service rollback failed: $($_.Exception.Message)"
            $cleanupRollbackFailures += "service cleanup: $($_.Exception.Message)"
        }
    }
    if ($copiedBinary -and (Test-Path -LiteralPath $targetBinary)) {
        try {
            Remove-Item -LiteralPath $targetBinary -Force
        } catch {
            Write-Warning "binary rollback failed: $($_.Exception.Message)"
            $cleanupRollbackFailures += "binary cleanup: $($_.Exception.Message)"
        }
    }
    if ($autoEnrollRegistryTouched -and $null -ne $autoEnrollRegistrySnapshot) {
        try {
            Restore-AgentRegistrySnapshot -Snapshot $autoEnrollRegistrySnapshot
        } catch {
            Write-Warning "auto-enroll registry rollback failed: $($_.Exception.Message)"
            $stateRollbackFailures += "auto-enroll registry: $($_.Exception.Message)"
        }
    }
    try {
        Restore-MachineEnv -OriginalValues $originalValues
    } catch {
        Write-Warning "machine environment rollback failed: $($_.Exception.Message)"
        $stateRollbackFailures += "machine environment: $($_.Exception.Message)"
    }
    if (-not [string]::IsNullOrWhiteSpace($hmacCredentialStoreBackup)) {
        try {
            Restore-HmacCredentialStoreBackup `
                -CredentialStorePath $hmacCredentialStorePath `
                -BackupPath $hmacCredentialStoreBackup
            $hmacCredentialStoreBackup = ""
        } catch {
            Write-Warning "HMAC credential-store rollback failed: $($_.Exception.Message)"
            $stateRollbackFailures += "HMAC credential store: $($_.Exception.Message)"
        }
    }
    if ($null -ne $replacementSnapshot) {
        try {
            Write-Step "restoring previous service transaction snapshot"
            Restore-ServiceReplacementSnapshot `
                -Snapshot $replacementSnapshot `
                -MaintenanceToken $MaintenanceToken `
                -MaintenanceTokenHash $resolvedMaintenanceTokenHash
            Write-Step "previous service transaction snapshot restored"
        } catch {
            $rollbackError = $_
            $failureDetails = @($cleanupRollbackFailures + $stateRollbackFailures + @(
                "previous service restore: $($rollbackError.Exception.Message)"
            )) -join "; "
            throw "EndpointAgent replacement failed: $($installError.Exception.Message). Rollback incomplete: $failureDetails. Protected rollback payload retained at $($replacementSnapshot.RollbackRoot)."
        }
        $restoredPreviousService = $true
        try {
            Remove-ServiceReplacementSnapshot -Snapshot $replacementSnapshot
        } catch {
            Write-Warning "previous service was restored, but rollback payload cleanup failed at $($replacementSnapshot.RollbackRoot): $($_.Exception.Message)"
        }
        $replacementSnapshot = $null
    }
    $incompleteRollback = @($stateRollbackFailures)
    if (-not $restoredPreviousService) {
        $incompleteRollback += $cleanupRollbackFailures
    }
    if ($incompleteRollback.Count -gt 0) {
        throw "EndpointAgent install failed: $($installError.Exception.Message). Rollback incomplete: $($incompleteRollback -join '; ')."
    }
    throw $installError
}
