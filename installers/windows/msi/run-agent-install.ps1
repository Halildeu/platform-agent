<#
.SYNOPSIS
  MSI deferred-custom-action wrapper around install.ps1 / uninstall.ps1.

.DESCRIPTION
  Faz 22.5 M4 — the WiX MSI (EndpointAgent.wxs) is the payload/ARP/upgrade owner;
  install.ps1 stays the installer single-source-of-truth (service create, AG-026C
  Environment regkey, SDDL/tamper hardening, credential preservation, auto-enroll).

  This wrapper is invoked by the deferred custom action (Execute=deferred,
  Impersonate=no -> runs as SYSTEM). It receives:
    -Mode        install | uninstall
    -ConfigData  the MSI CustomActionData blob (key=value pairs, ';'-separated),
                 carrying ONLY non-secret config (API_URL, AUTO_ENROLL, ...).
    -ResponseFile (optional) path to a SYSTEM/Admins-only temp file holding the
                 lab-fallback HMAC ENROLLMENT_TOKEN (Codex 019ead14 cond.2 — keep
                 secrets out of the process command line / MSI verbose log). The
                 file is shredded in a finally{} regardless of outcome.

  Secret hygiene (Codex 019ead14 cond.1/2):
    - never echoes a secret value to stdout / the agent log,
    - reads the token from the response file (not a visible -EnrollmentToken arg
      on a command line that process-creation auditing could capture),
    - deletes the response file even on failure.

  Residual risk (documented): for the lab HMAC fallback only, the token transits
  CustomActionData -> response file. This path is lab-only / non-prod. The prod
  GPO path is TOKENLESS (-AutoEnroll machine-cert/mTLS); see installers/windows/msi/README.md.
#>
[CmdletBinding()]
param(
    [ValidateSet("install", "uninstall")]
    [string]$Mode = "install",

    # MSI CustomActionData: "KEY=value;KEY2=value2;..." (non-secret only).
    [string]$ConfigData = "",

    # Optional SYSTEM/Admins-only temp file holding the lab ENROLLMENT_TOKEN.
    [string]$ResponseFile = "",

    # Staged payload dir (default: the dir this wrapper lives in).
    [string]$PayloadDir = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($PayloadDir)) {
    $PayloadDir = if ($PSScriptRoot) { $PSScriptRoot }
        elseif ($PSCommandPath) { Split-Path -Parent $PSCommandPath }
        else { (Get-Location).Path }
}

# Deterministic, redaction-tested MSI log (Codex 019ead14 gotcha).
$logDir = Join-Path $env:ProgramData "EndpointAgent\logs"
if (-not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
}
$ts = (Get-Date).ToString("yyyyMMdd-HHmmss")
$msiLog = Join-Path $logDir "install-msi-$ts.log"

function Write-MsiLog {
    param([string]$Message)
    # NOTE: callers MUST NOT pass secret values here.
    $line = "[{0}] {1}" -f (Get-Date).ToString("o"), $Message
    Add-Content -LiteralPath $msiLog -Value $line
    Write-Host $line
}

# Parse "KEY=value;KEY2=value2" -> ordered hashtable (last-wins).
function ConvertFrom-ConfigData {
    param([string]$Data)
    $map = @{}
    if ([string]::IsNullOrWhiteSpace($Data)) { return $map }
    foreach ($pair in $Data -split ';') {
        if ([string]::IsNullOrWhiteSpace($pair)) { continue }
        $i = $pair.IndexOf('=')
        if ($i -lt 1) { continue }
        $k = $pair.Substring(0, $i).Trim()
        $v = $pair.Substring($i + 1)
        if (-not [string]::IsNullOrWhiteSpace($k)) { $map[$k] = $v }
    }
    return $map
}

# Map the MSI public-property keys -> install.ps1 parameter names. Only keys
# present (and non-empty) are forwarded, so unset MSI props use install.ps1's
# own defaults. Switches map to [switch] = $true when the value is 1/true/yes.
$keyMap = @{
    'API_URL'                        = @{ Param = 'ApiUrl';                     Kind = 'value'  }
    'SERVICE_NAME'                   = @{ Param = 'ServiceName';                Kind = 'value'  }
    'LOG_DIR'                        = @{ Param = 'LogDir';                     Kind = 'value'  }
    'INSTALL_ID'                     = @{ Param = 'InstallId';                  Kind = 'value'  }
    'MAINTENANCE_TOKEN_HASH'         = @{ Param = 'MaintenanceTokenHash';       Kind = 'value'  }
    'SERVICE_SDDL'                   = @{ Param = 'ServiceSddl';                Kind = 'value'  }
    'AUTO_ENROLL'                    = @{ Param = 'AutoEnroll';                 Kind = 'switch' }
    'AUTO_ENROLL_API_URL'            = @{ Param = 'AutoEnrollApiUrl';           Kind = 'value'  }
    'AUTO_ENROLL_CERT_SUBJECT_SUFFIX'= @{ Param = 'AutoEnrollCertSubjectSuffix';Kind = 'value'  }
    'AUTO_ENROLL_CERT_SAN_URI_PREFIX'= @{ Param = 'AutoEnrollCertSANURIPrefix'; Kind = 'value'  }
    'AUTO_ENROLL_JITTER_SECONDS'     = @{ Param = 'AutoEnrollJitterSeconds';    Kind = 'int'    }
}

function Test-TruthyFlag {
    param([string]$Value)
    return @('1', 'true', 'yes', 'on') -contains ($Value).Trim().ToLowerInvariant()
}

$responseFileToShred = $ResponseFile
try {
    Write-MsiLog "M4 MSI wrapper start mode=$Mode payload=$PayloadDir log=$msiLog"

    $installScript   = Join-Path $PayloadDir "install.ps1"
    $uninstallScript = Join-Path $PayloadDir "uninstall.ps1"
    $agentBinary     = Join-Path $PayloadDir "endpoint-agent.exe"

    if ($Mode -eq "uninstall") {
        if (-not (Test-Path -LiteralPath $uninstallScript)) {
            throw "uninstall.ps1 not found in staged payload: $uninstallScript"
        }
        $uArgs = @{}
        $cfg = ConvertFrom-ConfigData -Data $ConfigData
        # Default uninstall PRESERVES the DPAPI credential store + config
        # (Codex 019ead14 cond.6). Only an explicit PURGE_CONFIG=1 purges.
        if ($cfg.ContainsKey('PURGE_CONFIG') -and (Test-TruthyFlag $cfg['PURGE_CONFIG'])) {
            $uArgs['RemoveConfig'] = $true
            Write-MsiLog "uninstall: PURGE_CONFIG=1 -> credential/config purge requested"
        } else {
            Write-MsiLog "uninstall: default -> credential/config PRESERVED"
        }
        if ($cfg.ContainsKey('SERVICE_NAME')) { $uArgs['ServiceName'] = $cfg['SERVICE_NAME'] }
        & $uninstallScript @uArgs
        Write-MsiLog "uninstall.ps1 exit=$LASTEXITCODE"
        if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) { exit $LASTEXITCODE }
        exit 0
    }

    # ---- install / upgrade ----
    if (-not (Test-Path -LiteralPath $installScript)) {
        throw "install.ps1 not found in staged payload: $installScript"
    }
    if (-not (Test-Path -LiteralPath $agentBinary)) {
        throw "endpoint-agent.exe not found in staged payload: $agentBinary"
    }

    $cfg = ConvertFrom-ConfigData -Data $ConfigData

    # Build the install.ps1 splat. The MSI is the payload owner; the runtime
    # install dir stays script-managed C:\Program Files\EndpointAgent (MF1).
    $splat = @{
        BinaryPath = $agentBinary
        InstallDir = (Join-Path $env:ProgramFiles "EndpointAgent")
        Force      = $true
        Start      = $true
    }

    foreach ($key in $keyMap.Keys) {
        if (-not $cfg.ContainsKey($key)) { continue }
        $raw = $cfg[$key]
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $m = $keyMap[$key]
        switch ($m.Kind) {
            'switch' { if (Test-TruthyFlag $raw) { $splat[$m.Param] = $true } }
            'int'    { [int]$n = 0; if ([int]::TryParse($raw, [ref]$n)) { $splat[$m.Param] = $n } }
            default  { $splat[$m.Param] = $raw }
        }
    }

    # Lab-only HMAC fallback: the token comes from the SYSTEM/Admins-only
    # response file, NEVER a visible command-line arg (Codex 019ead14 cond.2).
    # On UPGRADE (an existing credential store) the token is deliberately NOT
    # forwarded — install.ps1 fail-fasts on a new -EnrollmentToken without
    # -ResetCredentialStore, and we never pass -ResetCredentialStore on upgrade
    # (MF4 credential preservation).
    if (-not [string]::IsNullOrWhiteSpace($ResponseFile) -and (Test-Path -LiteralPath $ResponseFile)) {
        $token = (Get-Content -LiteralPath $ResponseFile -Raw)
        if ($null -ne $token) { $token = $token.Trim() }
        $credDir = Join-Path $env:ProgramData "EndpointAgent"
        $hasCredStore = Test-Path -LiteralPath (Join-Path $credDir "credential.dat")
        if ([string]::IsNullOrWhiteSpace($token)) {
            Write-MsiLog "enrollment token response file empty -> ignored"
        } elseif ($hasCredStore) {
            Write-MsiLog "existing credential store -> enrollment token NOT forwarded (upgrade-preserve)"
        } elseif ($splat.ContainsKey('AutoEnroll')) {
            Write-MsiLog "AutoEnroll set -> lab HMAC token NOT forwarded (tokenless path wins)"
        } else {
            $splat['EnrollmentToken'] = $token   # value redacted by install.ps1's own logging
            Write-MsiLog "lab HMAC enrollment token forwarded from response file (value redacted)"
        }
        $token = $null
    }

    # Redaction-friendly log line: keys only, never values.
    Write-MsiLog ("install.ps1 params: " + (($splat.Keys | Sort-Object) -join ', '))

    & $installScript @splat
    $code = $LASTEXITCODE
    Write-MsiLog "install.ps1 exit=$code"
    if ($null -ne $code -and $code -ne 0) { exit $code }
    exit 0
}
catch {
    Write-MsiLog ("ERROR: " + $_.Exception.Message)
    exit 1603   # ERROR_INSTALL_FAILURE
}
finally {
    # Shred the lab token response file regardless of outcome (Codex cond.2).
    if (-not [string]::IsNullOrWhiteSpace($responseFileToShred) -and (Test-Path -LiteralPath $responseFileToShred)) {
        try {
            $len = (Get-Item -LiteralPath $responseFileToShred).Length
            if ($len -gt 0) {
                $zeros = New-Object byte[] $len
                [System.IO.File]::WriteAllBytes($responseFileToShred, $zeros)
            }
            Remove-Item -LiteralPath $responseFileToShred -Force -ErrorAction SilentlyContinue
            Write-MsiLog "response file shredded"
        } catch {
            Write-MsiLog "WARN: response file shred failed: $($_.Exception.Message)"
        }
    }
}
