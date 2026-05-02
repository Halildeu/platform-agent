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

Assert-Administrator

$targetBinary = Join-Path $InstallDir "endpoint-agent.exe"
$expectedMaintenanceTokenHash = Resolve-ExpectedMaintenanceTokenHash -HashOverride $MaintenanceTokenHash

Assert-MaintenanceToken -Token $MaintenanceToken -ExpectedHash $expectedMaintenanceTokenHash

if (Test-ServiceExists -Name $ServiceName) {
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

if (Test-Path -LiteralPath $InstallDir) {
    Write-Step "removing install directory: $InstallDir"
    Remove-PathWithRetry -Path $InstallDir
}

if ($RemoveConfig) {
    foreach ($key in $configKeys) {
        [Environment]::SetEnvironmentVariable($key, $null, "Machine")
        Write-Step "removed $key"
    }
}

if ($RemoveLogs -and (Test-Path -LiteralPath $LogDir)) {
    Write-Step "removing logs: $LogDir"
    Remove-PathWithRetry -Path $LogDir
}

Write-Step "uninstall completed"
