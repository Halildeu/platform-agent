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
# Codex 019e74c3 iter-1 MF-3 absorb: use -ErrorAction Stop so that
# CIM/namespace/access failures throw to the catch block and emit a
# structured error, instead of being silently swallowed by
# $ErrorActionPreference='SilentlyContinue' and producing
# nullable=null + probeComplete=true.
try {
  $avProducts = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop
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
    # Cmdlet succeeded but no AV products registered. Definitive
    # readout: zero products, no third-party AV. Distinct from
    # cmdlet failure (caught below).
    $result.securityCenter = [ordered]@{
      nonMicrosoftAvPresent = $false
      avProductCount        = 0
    }
  }
} catch {
  # Namespace missing, access denied, or CIM failure. Surface a
  # typed probe error so probeComplete=false; keep both nullable
  # fields at null so the wire cannot be confused with a real
  # zero-products readout.
  $result.securityCenter = [ordered]@{ nonMicrosoftAvPresent = $null; avProductCount = $null }
  $errCode = 'POWERSHELL_FAILED'
  if ($_.Exception -and $_.Exception.GetType().Name -like '*UnauthorizedAccess*') { $errCode = 'ACCESS_DENIED' }
  elseif ($_.Exception -and $_.Exception.GetType().Name -like '*ManagementException*') { $errCode = 'CMDLET_UNAVAILABLE' }
  $result.errors += @{ source = 'securityCenter'; code = $errCode; summary = 'Get-CimInstance SecurityCenter2 threw' }
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
			// Codex 019e74c3 iter-1 MF-1 absorb: don't lower-case the
			// source — the SecurityProbeSource enum is mixed-case
			// (`securityCenter`). Use an explicit allowlist that
			// preserves canonical source names and collapses
			// unrecognized values to the powershell catch-all so the
			// typed enum contract stays intact.
			Source:  normalizeSecuritySource(e.Source),
			Code:    strings.TrimSpace(e.Code),
			Summary: boundSummary(e.Summary),
		})
	}

	// Codex 019e74c3 iter-1 MF-2 absorb: a successful JSON parse
	// against a `null` or `{}` PowerShell output decodes into a
	// zero-value rawSecurityProbeOutput with no sub-objects
	// populated. Without this guard, the result would be reported as
	// probeComplete=true with no evidence — backend can't tell "the
	// host has no AV / no firewall / no encryption" from "the script
	// silently produced nothing". Fail-closed: at least one source
	// object OR one source-level error must be present.
	if !hasAnySecurityEvidence(&parsed) && len(parsed.Errors) == 0 {
		result.ProbeErrors = append(result.ProbeErrors, SecurityProbeError{
			Source:  SecurityProbeSourcePowerShell,
			Code:    SecurityProbeErrNoEvidence,
			Summary: "security posture script returned no evidence (no sources populated, no errors emitted)",
		})
	}

	deriveSecurityPostureSummary(&result)
	result.ProbeDurationMs = securityPostureElapsedMs(start, now)
	return result
}

// hasAnySecurityEvidence reports whether at least one sub-source
// object was populated by the PowerShell script. Used by the
// MF-2 fail-closed guard above to distinguish "ran but emitted
// nothing" (treated as a NO_EVIDENCE probe error) from "ran and
// returned at least one source readout" (treated as a real
// measurement).
func hasAnySecurityEvidence(p *rawSecurityProbeOutput) bool {
	if p == nil {
		return false
	}
	if p.Defender != nil || p.SecurityCenter != nil || p.BitLocker != nil {
		return true
	}
	if p.Firewall.Domain != nil || p.Firewall.Private != nil || p.Firewall.Public != nil {
		return true
	}
	return false
}

// normalizeSecuritySource maps a raw PowerShell error-source string
// into the canonical SecurityProbeSource enum. Unknown values fall
// back to SecurityProbeSourcePowerShell so the typed enum surface
// is never violated. Codex 019e74c3 iter-1 MF-1 absorb.
func normalizeSecuritySource(raw string) SecurityProbeSource {
	switch strings.TrimSpace(raw) {
	case "defender":
		return SecurityProbeSourceDefender
	case "securityCenter":
		return SecurityProbeSourceSecurityCenter
	case "firewall":
		return SecurityProbeSourceFirewall
	case "bitlocker":
		return SecurityProbeSourceBitLocker
	case "powershell":
		return SecurityProbeSourcePowerShell
	default:
		return SecurityProbeSourcePowerShell
	}
}

// boundSummary trims free-form text to a fixed cap and normalizes
// control characters. Operator-facing error summaries must never
// carry raw PowerShell exception dumps or registry value contents,
// and downstream consumers (audit log, UI, alerting) must not have
// to defend against stray NUL / TAB / CR / LF / DEL bytes that a
// buggy script could emit inside a summary string. Codex 019e74c3
// iter-1 nice-to-have absorb.
func boundSummary(s string) string {
	const max = 200
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
	}
	// Replace control characters (including NUL, BEL, BS, VT, FF,
	// SO/SI, ESC, DEL) with single spaces; keep TAB/CR/LF since they
	// are common in legitimate cmdlet messages.
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t', r == '\n', r == '\r':
			b.WriteRune(' ')
		case r < 0x20, r == 0x7f:
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
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
