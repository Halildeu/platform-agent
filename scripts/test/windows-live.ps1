<#
.SYNOPSIS
Runs a live Windows service smoke test for Endpoint Agent.

.DESCRIPTION
Uses the packaged files under dist/windows/EndpointAgent, installs a temporary
service, starts it, validates status, runs the read-only local user diagnostic,
checks the log file, then uninstalls unless -KeepInstalled is supplied.
#>

[CmdletBinding()]
param(
    [string]$ServiceName = "EndpointAgentCodexTest",
    [string]$DisplayName = "Endpoint Agent Codex Test",
    [string]$InstallDir = "C:\Program Files\EndpointAgentCodexTest",
    [string]$LogDir = "C:\ProgramData\EndpointAgentCodexTest\logs",
    [switch]$KeepInstalled
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "[endpoint-agent-live] $Message"
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator PowerShell is required."
    }
}

function Invoke-AgentExpectFailure {
    param(
        [string]$ExePath,
        [string[]]$Arguments
    )
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $ExePath @Arguments 1>$null 2>$null
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
}

Assert-Administrator

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$packageDir = Join-Path $repoRoot "dist\windows\EndpointAgent"
$installScript = Join-Path $packageDir "install.ps1"
$uninstallScript = Join-Path $packageDir "uninstall.ps1"
$installedExe = Join-Path $InstallDir "endpoint-agent.exe"
$logPath = Join-Path $LogDir "endpoint-agent.log"
$maintenanceToken = "codex-maintenance-token"

if (-not (Test-Path -LiteralPath $installScript)) {
    throw "Package not found. Run ./scripts/build/windows-package.sh first."
}

Write-Step "pre-clean"
& $uninstallScript -ServiceName $ServiceName -InstallDir $InstallDir -LogDir $LogDir -MaintenanceToken $maintenanceToken -RemoveConfig -RemoveLogs

try {
    Write-Step "install and start"
    & $installScript `
        -ServiceName $ServiceName `
        -DisplayName $DisplayName `
        -InstallDir $InstallDir `
        -LogDir $LogDir `
        -MaintenanceToken $maintenanceToken `
        -Force `
        -Start

    Write-Step "status after start"
    & $installedExe service status --name $ServiceName

    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($service.Status -ne "Running") {
        throw "Service status is $($service.Status), expected Running."
    }

    $sourceExists = [System.Diagnostics.EventLog]::SourceExists($ServiceName)
    if (-not $sourceExists) {
        throw "Expected Windows Event Log source was not created: $ServiceName"
    }
    Write-Step "event log source exists: $ServiceName"

    Write-Step "tamper protection checks"
    $failurePolicy = (& sc.exe qfailure $ServiceName) -join "`n"
    if ($failurePolicy -notmatch "RESTART") {
        throw "Expected service failure action to include RESTART. Output: $failurePolicy"
    }
    $serviceSddl = (& sc.exe sdshow $ServiceName) -join "`n"
    if ($serviceSddl -notmatch "AU") {
        throw "Expected service SDDL to include Authenticated Users read-only ACE. Output: $serviceSddl"
    }
    if ($serviceSddl -match "\(A;;[^)]*WP[^)]*;;;AU\)") {
        throw "Authenticated Users must not have SERVICE_STOP in service SDDL. Output: $serviceSddl"
    }
    $serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $delayedAutoStart = (Get-ItemProperty -LiteralPath $serviceRegistryPath -Name DelayedAutoStart -ErrorAction Stop).DelayedAutoStart
    if ($delayedAutoStart -ne 1) {
        throw "Expected DelayedAutoStart=1, got $delayedAutoStart"
    }
    $maintenanceTokenHash = [Environment]::GetEnvironmentVariable("ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256", "Machine")
    if ([string]::IsNullOrWhiteSpace($maintenanceTokenHash)) {
        throw "Expected ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256 machine env to be configured."
    }
    $wrongTokenExitCode = Invoke-AgentExpectFailure -ExePath $installedExe -Arguments @(
        "service", "stop",
        "--name", $ServiceName,
        "--maintenance-token", "wrong-token",
        "--maintenance-token-sha256", $maintenanceTokenHash
    )
    if ($wrongTokenExitCode -eq 0) {
        throw "Expected wrong maintenance token to reject service stop."
    }
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($service.Status -ne "Running") {
        throw "Service should still be Running after rejected stop; got $($service.Status)."
    }

    Write-Step "read-only local users diagnostic"
    & $installedExe diagnose local-users

    Write-Step "stop service with maintenance token"
    & $installedExe service stop --name $ServiceName --maintenance-token $maintenanceToken --maintenance-token-sha256 $maintenanceTokenHash
    & $installedExe service status --name $ServiceName

    if (-not (Test-Path -LiteralPath $logPath)) {
        throw "Expected log file was not created: $logPath"
    }

    Write-Step "log file"
    Get-Item -LiteralPath $logPath | Select-Object FullName, Length
    Get-Content -LiteralPath $logPath -TotalCount 20

    Write-Step "event log sample"
    Get-WinEvent -FilterHashtable @{ LogName = "Application"; ProviderName = $ServiceName } -MaxEvents 5 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message

    Write-Step "live smoke completed"
} finally {
    if (-not $KeepInstalled) {
        Write-Step "cleanup"
        & $uninstallScript -ServiceName $ServiceName -InstallDir $InstallDir -LogDir $LogDir -MaintenanceToken $maintenanceToken -RemoveConfig -RemoveLogs
    }
}
