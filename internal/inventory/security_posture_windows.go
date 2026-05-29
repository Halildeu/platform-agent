//go:build windows

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// AG-031 Windows endpoint security posture probe.
//
// One PowerShell process produces a single JSON document covering
// Defender + SecurityCenter2 third-party AV summary + per-profile
// firewall + BitLocker counts. The script ONLY emits allowlisted
// fields (no raw drive identifiers, no recovery material, no
// vendor product names, no exception dumps). All cmdlet calls run
// under -ErrorAction SilentlyContinue and the script tags each
// section with a sourcePresent bool so the agent can distinguish
// "control not installed" from "cmdlet failed".

const securityProbeTimeout = 30 * time.Second

// securityProbeScript is the fixed argv input. No payload-supplied
// substitution, no shell, no `Invoke-Expression`. The script is
// reviewed once and pinned by the build.
const securityProbeScript = `
$ErrorActionPreference = 'SilentlyContinue'
$result = [ordered]@{
  defender = $null
  securityCenter = $null
  firewall = @{ domain = $null; private = $null; public = $null }
  bitlocker = $null
  errors = @()
}

# ---- Defender (Get-MpComputerStatus) ----
try {
  $mp = Get-MpComputerStatus
  if ($null -ne $mp) {
    $sigAge = $null
    if ($mp.AntivirusSignatureLastUpdated) {
      try {
        $sigAge = [int][math]::Floor(((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays)
      } catch { $sigAge = $null }
    }
    $defenderObj = [ordered]@{
      present                   = $true
      antivirusEnabled          = if ($mp.PSObject.Properties.Name -contains 'AntivirusEnabled') { [bool]$mp.AntivirusEnabled } else { $null }
      realTimeProtectionEnabled = if ($mp.PSObject.Properties.Name -contains 'RealTimeProtectionEnabled') { [bool]$mp.RealTimeProtectionEnabled } else { $null }
      signatureAgeDays          = $sigAge
      engineVersionPresent      = -not [string]::IsNullOrWhiteSpace($mp.AMEngineVersion)
      tamperProtected           = if ($mp.PSObject.Properties.Name -contains 'IsTamperProtected') { [bool]$mp.IsTamperProtected } else { $null }
    }
    $result.defender = $defenderObj
  } else {
    $result.defender = [ordered]@{ present = $false; antivirusEnabled = $null; realTimeProtectionEnabled = $null; signatureAgeDays = $null; engineVersionPresent = $false; tamperProtected = $null }
    $result.errors += @{ source = 'defender'; code = 'CMDLET_UNAVAILABLE'; summary = 'Get-MpComputerStatus returned null' }
  }
} catch {
  $result.defender = [ordered]@{ present = $false; antivirusEnabled = $null; realTimeProtectionEnabled = $null; signatureAgeDays = $null; engineVersionPresent = $false; tamperProtected = $null }
  $result.errors += @{ source = 'defender'; code = 'POWERSHELL_FAILED'; summary = 'Get-MpComputerStatus threw' }
}

# ---- SecurityCenter2 third-party AV summary ----
try {
  $avProducts = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'AntiVirusProduct'
  if ($null -ne $avProducts) {
    $count = ($avProducts | Measure-Object).Count
    $nonMs = $false
    foreach ($p in $avProducts) {
      if ($p.displayName -and -not ($p.displayName -like 'Windows Defender*' -or $p.displayName -like 'Microsoft Defender*')) {
        $nonMs = $true
      }
    }
    $result.securityCenter = [ordered]@{
      nonMicrosoftAvPresent = $nonMs
      avProductCount        = $count
    }
  } else {
    $result.securityCenter = [ordered]@{ nonMicrosoftAvPresent = $null; avProductCount = $null }
  }
} catch {
  $result.securityCenter = [ordered]@{ nonMicrosoftAvPresent = $null; avProductCount = $null }
  $result.errors += @{ source = 'securityCenter'; code = 'POWERSHELL_FAILED'; summary = 'Get-CimInstance SecurityCenter2 threw' }
}

# ---- Firewall per-profile ----
try {
  $profiles = Get-NetFirewallProfile
  if ($profiles) {
    foreach ($p in $profiles) {
      $action = 'UNKNOWN'
      if ($p.DefaultInboundAction) {
        $action = switch ($p.DefaultInboundAction.ToString().ToUpperInvariant()) {
          'ALLOW' { 'ALLOW' }
          'BLOCK' { 'BLOCK' }
          'NOTCONFIGURED' { 'UNKNOWN' }
          default { 'UNKNOWN' }
        }
      }
      $profileObj = [ordered]@{ enabled = [bool]$p.Enabled; defaultInboundAction = $action }
      switch ($p.Name.ToString().ToLowerInvariant()) {
        'domain'  { $result.firewall.domain  = $profileObj }
        'private' { $result.firewall.private = $profileObj }
        'public'  { $result.firewall.public  = $profileObj }
      }
    }
  } else {
    $result.errors += @{ source = 'firewall'; code = 'CMDLET_UNAVAILABLE'; summary = 'Get-NetFirewallProfile returned null' }
  }
} catch {
  $result.errors += @{ source = 'firewall'; code = 'POWERSHELL_FAILED'; summary = 'Get-NetFirewallProfile threw' }
}

# ---- BitLocker by count ----
try {
  $bl = Get-BitLockerVolume
  if ($null -ne $bl) {
    $systemPresent = $false
    $systemEncrypted = $false
    $systemProtected = $false
    $systemActive = $false
    $dataCount = 0
    $encryptedDataCount = 0
    $protectedDataCount = 0
    $suspended = 0
    foreach ($v in $bl) {
      $isSystem = ($v.VolumeType.ToString() -eq 'OperatingSystem')
      $encrypted = ($v.EncryptionPercentage -ge 100)
      $protected = ($v.ProtectionStatus.ToString() -eq 'On')
      $active = ($v.EncryptionPercentage -gt 0 -and $v.EncryptionPercentage -lt 100) -or ($v.VolumeStatus.ToString() -eq 'EncryptionInProgress')
      $isSuspended = ($v.ProtectionStatus.ToString() -eq 'Off' -and $encrypted)
      if ($isSystem) {
        $systemPresent = $true
        $systemEncrypted = $encrypted
        $systemProtected = $protected
        $systemActive = $active
      } else {
        $dataCount++
        if ($encrypted) { $encryptedDataCount++ }
        if ($protected) { $protectedDataCount++ }
      }
      if ($isSuspended) { $suspended++ }
    }
    $result.bitlocker = [ordered]@{
      systemDrivePresent          = $systemPresent
      systemDriveEncrypted        = $systemEncrypted
      systemDriveProtected        = $systemProtected
      systemDriveEncryptionActive = $systemActive
      dataDriveCount              = $dataCount
      encryptedDataDriveCount     = $encryptedDataCount
      protectedDataDriveCount     = $protectedDataCount
      suspendedDriveCount         = $suspended
    }
  } else {
    $result.bitlocker = [ordered]@{ systemDrivePresent = $false; systemDriveEncrypted = $false; systemDriveProtected = $false; systemDriveEncryptionActive = $false; dataDriveCount = 0; encryptedDataDriveCount = 0; protectedDataDriveCount = 0; suspendedDriveCount = 0 }
    $result.errors += @{ source = 'bitlocker'; code = 'CMDLET_UNAVAILABLE'; summary = 'Get-BitLockerVolume returned null' }
  }
} catch {
  $result.bitlocker = [ordered]@{ systemDrivePresent = $false; systemDriveEncrypted = $false; systemDriveProtected = $false; systemDriveEncryptionActive = $false; dataDriveCount = 0; encryptedDataDriveCount = 0; protectedDataDriveCount = 0; suspendedDriveCount = 0 }
  $result.errors += @{ source = 'bitlocker'; code = 'POWERSHELL_FAILED'; summary = 'Get-BitLockerVolume threw' }
}

$result | ConvertTo-Json -Depth 6 -Compress
`

var runSecurityProbe = runSecurityProbeReal

func runSecurityProbeReal(ctx context.Context) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", securityProbeScript)
	return cmd.Output()
}

// rawSecurityProbeOutput mirrors the PowerShell JSON shape. Fields
// that are missing/null in PowerShell decode as pointer-nil or zero
// values; the Go-side mapper normalizes that to the typed wire shape.
type rawSecurityProbeOutput struct {
	Defender       *rawDefender       `json:"defender"`
	SecurityCenter *rawSecurityCenter `json:"securityCenter"`
	Firewall       struct {
		Domain  *rawFirewallProfile `json:"domain"`
		Private *rawFirewallProfile `json:"private"`
		Public  *rawFirewallProfile `json:"public"`
	} `json:"firewall"`
	BitLocker *rawBitLocker       `json:"bitlocker"`
	Errors    []rawSecurityError `json:"errors"`
}

type rawDefender struct {
	Present                   bool  `json:"present"`
	AntivirusEnabled          *bool `json:"antivirusEnabled"`
	RealTimeProtectionEnabled *bool `json:"realTimeProtectionEnabled"`
	SignatureAgeDays          *int  `json:"signatureAgeDays"`
	EngineVersionPresent      bool  `json:"engineVersionPresent"`
	TamperProtected           *bool `json:"tamperProtected"`
}

type rawSecurityCenter struct {
	NonMicrosoftAVPresent *bool `json:"nonMicrosoftAvPresent"`
	AVProductCount        *int  `json:"avProductCount"`
}

type rawFirewallProfile struct {
	Enabled              bool   `json:"enabled"`
	DefaultInboundAction string `json:"defaultInboundAction"`
}

type rawBitLocker struct {
	SystemDrivePresent          bool `json:"systemDrivePresent"`
	SystemDriveEncrypted        bool `json:"systemDriveEncrypted"`
	SystemDriveProtected        bool `json:"systemDriveProtected"`
	SystemDriveEncryptionActive bool `json:"systemDriveEncryptionActive"`
	DataDriveCount              int  `json:"dataDriveCount"`
	EncryptedDataDriveCount     int  `json:"encryptedDataDriveCount"`
	ProtectedDataDriveCount     int  `json:"protectedDataDriveCount"`
	SuspendedDriveCount         int  `json:"suspendedDriveCount"`
}

type rawSecurityError struct {
	Source  string `json:"source"`
	Code    string `json:"code"`
	Summary string `json:"summary"`
}

// ProbeSecurityPosture is the Windows live runner. Mirrors the
// AG-035 / AG-030 pattern: nil-context guard, monotonic clock, one
// PowerShell process, structured JSON decode, allowlist normalize.
func ProbeSecurityPosture(ctx context.Context, now func() time.Time) SecurityPostureResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if now == nil {
		now = time.Now
	}
	start := now()
	result := SecurityPostureResult{
		SchemaVersion: SecurityPostureSchemaVersion,
		Supported:     true,
		Firewall: FirewallStatus{
			Domain:  FirewallProfileStatus{DefaultInboundAction: "UNKNOWN"},
			Private: FirewallProfileStatus{DefaultInboundAction: "UNKNOWN"},
			Public:  FirewallProfileStatus{DefaultInboundAction: "UNKNOWN"},
		},
	}

	probeCtx, cancel := context.WithTimeout(ctx, securityProbeTimeout)
	defer cancel()

	raw, err := runSecurityProbe(probeCtx)
	if err != nil {
		code := SecurityProbeErrPowerShellFailed
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			code = SecurityProbeErrPowerShellTimeout
		}
		result.ProbeErrors = append(result.ProbeErrors, SecurityProbeError{
			Source: SecurityProbeSourcePowerShell,
			Code:   code,
			Summary: boundSummary(fmt.Sprintf(
				"security posture probe failed: %v", err)),
		})
		deriveSecurityPostureSummary(&result)
		result.ProbeDurationMs = securityPostureElapsedMs(start, now)
		return result
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		result.ProbeErrors = append(result.ProbeErrors, SecurityProbeError{
			Source:  SecurityProbeSourcePowerShell,
			Code:    SecurityProbeErrPowerShellEmptyOutput,
			Summary: "security posture probe returned no output",
		})
		deriveSecurityPostureSummary(&result)
		result.ProbeDurationMs = securityPostureElapsedMs(start, now)
		return result
	}

	var parsed rawSecurityProbeOutput
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		result.ProbeErrors = append(result.ProbeErrors, SecurityProbeError{
			Source: SecurityProbeSourcePowerShell,
			Code:   SecurityProbeErrPowerShellParseError,
			Summary: boundSummary(fmt.Sprintf(
				"security posture JSON parse failed: %v", err)),
		})
		deriveSecurityPostureSummary(&result)
		result.ProbeDurationMs = securityPostureElapsedMs(start, now)
		return result
	}

	if parsed.Defender != nil {
		result.Antivirus.MicrosoftDefender = DefenderStatus{
			Present:                   parsed.Defender.Present,
			AntivirusEnabled:          parsed.Defender.AntivirusEnabled,
			RealTimeProtectionEnabled: parsed.Defender.RealTimeProtectionEnabled,
			SignatureAgeDays:          parsed.Defender.SignatureAgeDays,
			EngineVersionPresent:      parsed.Defender.EngineVersionPresent,
			TamperProtected:           parsed.Defender.TamperProtected,
		}
	}
	if parsed.SecurityCenter != nil {
		result.Antivirus.NonMicrosoftAVPresent = parsed.SecurityCenter.NonMicrosoftAVPresent
		result.Antivirus.AVProductCount = parsed.SecurityCenter.AVProductCount
	}
	if parsed.Firewall.Domain != nil {
		result.Firewall.Domain = FirewallProfileStatus{
			Enabled:              parsed.Firewall.Domain.Enabled,
			DefaultInboundAction: normalizeFirewallAction(parsed.Firewall.Domain.DefaultInboundAction),
		}
	}
	if parsed.Firewall.Private != nil {
		result.Firewall.Private = FirewallProfileStatus{
			Enabled:              parsed.Firewall.Private.Enabled,
			DefaultInboundAction: normalizeFirewallAction(parsed.Firewall.Private.DefaultInboundAction),
		}
	}
	if parsed.Firewall.Public != nil {
		result.Firewall.Public = FirewallProfileStatus{
			Enabled:              parsed.Firewall.Public.Enabled,
			DefaultInboundAction: normalizeFirewallAction(parsed.Firewall.Public.DefaultInboundAction),
		}
	}
	if parsed.BitLocker != nil {
		result.BitLocker = BitLockerStatus(*parsed.BitLocker)
	}
	for _, e := range parsed.Errors {
		result.ProbeErrors = append(result.ProbeErrors, SecurityProbeError{
			Source:  SecurityProbeSource(strings.ToLower(strings.TrimSpace(e.Source))),
			Code:    strings.TrimSpace(e.Code),
			Summary: boundSummary(e.Summary),
		})
	}

	deriveSecurityPostureSummary(&result)
	result.ProbeDurationMs = securityPostureElapsedMs(start, now)
	return result
}

// boundSummary trims free-form text to a fixed cap. Operator-facing
// error summaries must never carry raw PowerShell exception dumps
// or registry value contents.
func boundSummary(s string) string {
	const max = 200
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// normalizeFirewallAction collapses unknown / blank inputs to the
// "UNKNOWN" sentinel so the wire never carries an empty string.
func normalizeFirewallAction(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "ALLOW":
		return "ALLOW"
	case "BLOCK":
		return "BLOCK"
	default:
		return "UNKNOWN"
	}
}
