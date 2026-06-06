param(
  # Parallels Desktop exposes the Mac home directory at \\Mac\Home. The default
  # is intentionally local-E2E specific; pass -SourceExe for any other runner.
  [string]$SourceExe = "\\Mac\Home\Documents\platform-agent-ag029-harness\dist\windows\EndpointAgent\endpoint-agent.exe",
  [string]$Root = "C:\Temp\EndpointAgentAg029E2E",
  [string]$ServiceName = "EndpointAgentCodexSmoke",
  [string]$StagingId = "a123456789abcdef0123456789abcdef",
  [string]$TargetVersion = "0.1.1-ag029-e2e",
  [int]$ServiceWaitSeconds = 30,
  [int]$HelperWaitSeconds = 120,
  [switch]$KeepService
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

function Stop-And-Delete-Service([string]$Name) {
  $svcObj = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $svcObj) {
    return
  }
  if ($svcObj.Status -ne "Stopped") {
    & sc.exe stop $Name | Out-Null
    $deadline = (Get-Date).AddSeconds(20)
    do {
      Start-Sleep -Milliseconds 500
      $svcObj = Get-Service -Name $Name -ErrorAction SilentlyContinue
      if ($null -eq $svcObj -or $svcObj.Status -eq "Stopped") {
        break
      }
    } while ((Get-Date) -lt $deadline)
  }
  & sc.exe delete $Name | Out-Null
  Start-Sleep -Milliseconds 500
}

function Wait-Service-State([string]$Name, [string]$Target, [int]$Seconds) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  do {
    $svcObj = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $svcObj -and $svcObj.Status.ToString() -eq $Target) {
      return $true
    }
    Start-Sleep -Milliseconds 500
  } while ((Get-Date) -lt $deadline)
  return $false
}

function Read-Text-Or-Empty([string]$Path) {
  if (Test-Path $Path) {
    return (Get-Content -Raw $Path)
  }
  return ""
}

function Trim-Text([object]$Value) {
  if ($null -eq $Value) {
    return ""
  }
  return ([string]$Value).Trim()
}

function Service-Snapshot([string]$Name) {
  return Get-CimInstance Win32_Service |
    Where-Object { $_.Name -eq $Name } |
    Select-Object Name, State, ProcessId, PathName
}

$serviceDir = Join-Path $Root "service"
$stagingRoot = Join-Path $Root "staging"
$current = Join-Path $serviceDir "endpoint-agent.exe"
$staged = Join-Path $stagingRoot "staged-$StagingId.bin"
$planPath = Join-Path $stagingRoot "activation-$StagingId.json"
$helper = Join-Path $stagingRoot "activation-helper-$StagingId.exe"
$outFile = Join-Path $stagingRoot "helper.stdout.json"
$errFile = Join-Path $stagingRoot "helper.stderr.txt"
$highWater = Join-Path $stagingRoot "max-activated-version.txt"
$outcomePath = Join-Path $stagingRoot "activation-outcome-$StagingId.json"
$proc = $null

try {
  Stop-And-Delete-Service $ServiceName
  if (Test-Path $Root) {
    Remove-Item -Recurse -Force $Root
  }
  New-Item -ItemType Directory -Force -Path $serviceDir, $stagingRoot | Out-Null

  Copy-Item -Force $SourceExe $current
  Copy-Item -Force $SourceExe $staged
  Add-Content -Path $staged -Value "`nAG029-E2E-MARKER-$StagingId" -Encoding ASCII
  Copy-Item -Force $current $helper

  $currentHashBefore = (Get-FileHash -Algorithm SHA256 $current).Hash.ToLowerInvariant()
  $stagedHash = (Get-FileHash -Algorithm SHA256 $staged).Hash.ToLowerInvariant()
  $helperHash = (Get-FileHash -Algorithm SHA256 $helper).Hash.ToLowerInvariant()

  $plan = [ordered]@{
    schemaVersion = 1
    stagingId = $StagingId
    activationPlanId = $StagingId
    serviceName = $ServiceName
    currentBinaryPath = $current
    stagedBinaryPath = $staged
    activationPlanPath = $planPath
    targetVersion = $TargetVersion
    actualSha256 = $stagedHash
    actualSignerThumbprint = "LOCAL-E2E"
    signingTier = "TRUSTED"
  }
  $plan | ConvertTo-Json -Depth 5 | Set-Content -Path $planPath -Encoding UTF8

  $binPath = '"' + $current + '" --service-run-name ' + $ServiceName
  $createOutput = (& sc.exe create $ServiceName binPath= $binPath start= demand 2>&1 | Out-String).Trim()
  $startOutput = (& sc.exe start $ServiceName 2>&1 | Out-String).Trim()
  $runningBefore = Wait-Service-State $ServiceName "Running" $ServiceWaitSeconds
  $serviceBefore = Service-Snapshot $ServiceName

  $helperArgs = @(
    "self-update", "activate",
    "--staging-root", $stagingRoot,
    "--staging-id", $StagingId,
    "--service-name", $ServiceName,
    "--high-water-path", $highWater,
    "--timeout", "90s"
  )
  $proc = Start-Process -FilePath $helper `
    -ArgumentList $helperArgs `
    -RedirectStandardOutput $outFile `
    -RedirectStandardError $errFile `
    -PassThru
  $finished = $proc.WaitForExit($HelperWaitSeconds * 1000)
  if ($finished) {
    $proc.Refresh()
  }
  if (-not $finished) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  }

  $runningAfter = Wait-Service-State $ServiceName "Running" $ServiceWaitSeconds
  $serviceAfter = Service-Snapshot $ServiceName
  $currentHashAfter = (Get-FileHash -Algorithm SHA256 $current).Hash.ToLowerInvariant()
  $stdout = Read-Text-Or-Empty $outFile
  $stderr = Read-Text-Or-Empty $errFile
  $outcome = $null
  if (Test-Path $outcomePath) {
    $outcome = Get-Content -Raw $outcomePath | ConvertFrom-Json
  }
  $highWaterValue = Read-Text-Or-Empty $highWater
  $helperExitCode = $null
  if ($null -ne $proc -and $finished) {
    $helperExitCode = $proc.ExitCode
  }

  [ordered]@{
    host = (& hostname)
    user = (& whoami)
    serviceName = $ServiceName
    stagingId = $StagingId
    sourceExists = (Test-Path $SourceExe)
    currentHashBefore = $currentHashBefore
    stagedHash = $stagedHash
    helperHash = $helperHash
    helperDistinct = ($helper -ne $current)
    createOutput = $createOutput
    startOutput = $startOutput
    runningBeforeActivation = $runningBefore
    serviceBefore = $serviceBefore
    helperFinished = $finished
    helperExitCode = $helperExitCode
    helperStdout = (Trim-Text $stdout)
    helperStderr = (Trim-Text $stderr)
    runningAfterActivation = $runningAfter
    serviceAfter = $serviceAfter
    currentHashAfter = $currentHashAfter
    currentEqualsStagedAfter = ($currentHashAfter -eq $stagedHash)
    currentChanged = ($currentHashAfter -ne $currentHashBefore)
    outcomePersisted = (Test-Path $outcomePath)
    outcome = $outcome
    highWater = (Trim-Text $highWaterValue)
    planPathExists = (Test-Path $planPath)
    helperPath = $helper
    currentPath = $current
    stagedPath = $staged
  } | ConvertTo-Json -Depth 8
} finally {
  if (-not $KeepService) {
    Stop-And-Delete-Service $ServiceName
  }
}
