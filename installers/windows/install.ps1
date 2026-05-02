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
    [switch]$Start,
    [switch]$Force,
    [switch]$DisableTamperProtection
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

Assert-Administrator

$sourceBinary = Resolve-Path -LiteralPath $BinaryPath -ErrorAction Stop
$targetBinary = Join-Path $InstallDir "endpoint-agent.exe"
$originalValues = @{}
$copiedBinary = $false
$installedService = $false
$resolvedMaintenanceTokenHash = Resolve-MaintenanceTokenHash -Token $MaintenanceToken -Hash $MaintenanceTokenHash

try {
    if ((Test-ServiceExists -Name $ServiceName) -and -not $Force) {
        throw "Service '$ServiceName' already exists. Use -Force to replace it."
    }

    if ((Test-ServiceExists -Name $ServiceName) -and $Force) {
        Write-Step "existing service found; uninstalling $ServiceName"
        $uninstallScript = Join-Path $PSScriptRoot "uninstall.ps1"
        if (Test-Path -LiteralPath $uninstallScript) {
            $uninstallArgs = @(
                "-ServiceName", $ServiceName,
                "-InstallDir", $InstallDir,
                "-LogDir", $LogDir
            )
            if (-not [string]::IsNullOrWhiteSpace($MaintenanceToken)) {
                $uninstallArgs += @("-MaintenanceToken", $MaintenanceToken)
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

    Set-MachineEnvIfPresent -OriginalValues $originalValues -Name "ENDPOINT_AGENT_API_URL" -Value $ApiUrl
    Set-MachineEnvIfPresent -OriginalValues $originalValues -Name "ENDPOINT_AGENT_ENROLLMENT_TOKEN" -Value $EnrollmentToken
    Set-MachineEnvIfPresent -OriginalValues $originalValues -Name "ENDPOINT_AGENT_ID" -Value $AgentId
    Set-MachineEnvIfPresent -OriginalValues $originalValues -Name "ENDPOINT_AGENT_SECRET" -Value $AgentSecret
    Set-MachineEnvIfPresent -OriginalValues $originalValues -Name "ENDPOINT_AGENT_INSTALL_ID" -Value $InstallId
    Set-MachineEnvIfPresent -OriginalValues $originalValues -Name "ENDPOINT_AGENT_LOG_DIR" -Value $LogDir
    Set-MachineEnvIfPresent -OriginalValues $originalValues -Name "ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256" -Value $resolvedMaintenanceTokenHash

    Write-Step "installing service: $ServiceName"
    Invoke-AgentServiceCommand -ExePath $targetBinary -Arguments @(
        "service", "install",
        "--name", $ServiceName,
        "--display-name", $DisplayName,
        "--description", $Description
    )
    $installedService = $true
    if (-not $DisableTamperProtection) {
        Set-AgentServiceHardening -Name $ServiceName -Sddl $ServiceSddl
    }

    if ($Start) {
        Write-Step "starting service: $ServiceName"
        Invoke-AgentServiceCommand -ExePath $targetBinary -Arguments @("service", "start", "--name", $ServiceName)
    }

    Write-Step "status"
    Invoke-AgentServiceCommand -ExePath $targetBinary -Arguments @("service", "status", "--name", $ServiceName)
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
    Restore-MachineEnv -OriginalValues $originalValues
    throw
}
