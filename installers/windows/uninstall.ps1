<#
.SYNOPSIS
Uninstalls Endpoint Agent Windows service.

.DESCRIPTION
Stops and removes the service, removes the installed binary, and optionally
removes machine-level configuration and logs.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "EndpointAgent"),
    [string]$ServiceName = "EndpointAgent",
    [string]$LogDir = (Join-Path $env:ProgramData "EndpointAgent\logs"),
    [string]$MaintenanceToken = "",
    [string]$MaintenanceTokenHash = "",
    [switch]$RemoveConfig,
    [switch]$RemoveLogs
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
    "ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256"
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

function Get-MachineEnv {
    param([string]$Name)
    return [Environment]::GetEnvironmentVariable($Name, "Machine")
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

function Resolve-ExpectedMaintenanceTokenHash {
    param([string]$HashOverride)
    if (-not [string]::IsNullOrWhiteSpace($HashOverride)) {
        return $HashOverride.Trim().ToLowerInvariant()
    }
    $stored = Get-MachineEnv -Name "ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256"
    if ([string]::IsNullOrWhiteSpace($stored)) {
        return ""
    }
    return $stored.Trim().ToLowerInvariant()
}

function Assert-MaintenanceToken {
    param(
        [string]$Token,
        [string]$ExpectedHash
    )
    if ([string]::IsNullOrWhiteSpace($ExpectedHash)) {
        Write-Step "maintenance token not configured; admin uninstall allowed"
        return
    }
    if ([string]::IsNullOrWhiteSpace($Token)) {
        throw "Maintenance token is required for uninstall."
    }
    $actual = ConvertTo-Sha256Hex -Value $Token
    if ($actual -ne $ExpectedHash) {
        throw "Maintenance token validation failed."
    }
    Write-Step "maintenance token validated"
}

function Remove-PathWithRetry {
    param(
        [string]$Path,
        [int]$Attempts = 10
    )
    $lastError = $null
    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            if (-not (Test-Path -LiteralPath $Path)) {
                return
            }
            Remove-Item -LiteralPath $Path -Recurse -Force
            return
        } catch {
            $lastError = $_
            Start-Sleep -Milliseconds (250 * $i)
        }
    }
    if ($null -ne $lastError) {
        throw $lastError
    }
}

function Wait-AgentProcessExit {
    # After `service uninstall` the SCM can report the service removed while the
    # agent process is still terminating (or a watchdog child still holds the
    # binary), so the subsequent install-dir removal races a locked exe
    # ("Access to the path 'endpoint-agent.exe' is denied"). Wait for every
    # endpoint-agent process running from $InstallPath to exit, then force-kill
    # any stragglers as a last resort.
    param(
        [string]$InstallPath,
        [int]$TimeoutSeconds = 30
    )
    $isOurs = {
        param($p)
        try { $p.Path -and $p.Path.StartsWith($InstallPath, [System.StringComparison]::OrdinalIgnoreCase) }
        catch { $false }
    }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $procs = @(Get-Process -Name "endpoint-agent" -ErrorAction SilentlyContinue | Where-Object { & $isOurs $_ })
        if ($procs.Count -eq 0) { return }
        Start-Sleep -Milliseconds 500
    }
    $stragglers = @(Get-Process -Name "endpoint-agent" -ErrorAction SilentlyContinue | Where-Object { & $isOurs $_ })
    foreach ($p in $stragglers) {
        Write-Step "force-killing residual agent process pid=$($p.Id)"
        try { $p.Kill(); $p.WaitForExit(5000) | Out-Null } catch { }
    }
    Start-Sleep -Milliseconds 500
}

Assert-Administrator

$targetBinary = Join-Path $InstallDir "endpoint-agent.exe"
$expectedMaintenanceTokenHash = Resolve-ExpectedMaintenanceTokenHash -HashOverride $MaintenanceTokenHash

Assert-MaintenanceToken -Token $MaintenanceToken -ExpectedHash $expectedMaintenanceTokenHash

if (Test-ServiceExists -Name $ServiceName) {
    # AG-026C: nuke the service-specific Environment regkey BEFORE the
    # service uninstall so any residual token or non-secret config is
    # gone even if the service-delete path runs the best-effort
    # sc.exe fallback. This keeps the next install/upgrade from
    # inheriting stale state through `HKLM\...\Services\<name>\Environment`.
    Write-Step "clearing service env regkey: $ServiceName\\Environment"
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name 'Environment' -ErrorAction SilentlyContinue

    Write-Step "uninstalling service: $ServiceName"
    if (Test-Path -LiteralPath $targetBinary) {
        $arguments = @("service", "uninstall", "--name", $ServiceName)
        if (-not [string]::IsNullOrWhiteSpace($MaintenanceToken)) {
            $arguments += @("--maintenance-token", $MaintenanceToken)
        }
        if (-not [string]::IsNullOrWhiteSpace($expectedMaintenanceTokenHash)) {
            $arguments += @("--maintenance-token-sha256", $expectedMaintenanceTokenHash)
        }
        Invoke-AgentServiceCommand -ExePath $targetBinary -Arguments $arguments
    } else {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        }
        sc.exe delete $ServiceName | Out-Null
    }
} else {
    Write-Step "service not found: $ServiceName"
}

# Ensure the agent process has fully released the binary before removing the
# install dir (avoids "Access denied" on a still-terminating process / watchdog).
Wait-AgentProcessExit -InstallPath $InstallDir

if (Test-Path -LiteralPath $InstallDir) {
    Write-Step "removing install directory: $InstallDir"
    Remove-PathWithRetry -Path $InstallDir
}

if ($RemoveConfig) {
    foreach ($key in $configKeys) {
        [Environment]::SetEnvironmentVariable($key, $null, "Machine")
        Write-Step "removed $key"
    }
    # AG-026D: also remove the persisted HMAC credential so a future
    # install does not silently inherit a credential bound to a
    # different deployment / tenant. Maintenance-token gate above
    # already authorised the destructive action.
    $hmacCredPath = Join-Path $env:ProgramData "EndpointAgent\config\hmac-credential.dpapi"
    if (Test-Path -LiteralPath $hmacCredPath) {
        Write-Step "removing hmac credential blob: $hmacCredPath"
        Remove-Item -LiteralPath $hmacCredPath -Force -ErrorAction SilentlyContinue
    }
}

if ($RemoveLogs -and (Test-Path -LiteralPath $LogDir)) {
    Write-Step "removing logs: $LogDir"
    Remove-PathWithRetry -Path $LogDir
}

Write-Step "uninstall completed"
