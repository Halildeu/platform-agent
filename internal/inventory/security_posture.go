package inventory

import "time"

// AG-031 — Endpoint Security Posture (Faz 22.5.2 posture quartet).
//
// Read-only posture inventory covering the three canonical Windows
// endpoint security signals: antivirus, host-based firewall, drive
// encryption. The probe never enables or disables a control, never
// runs a sample scan, never decrypts a volume, never exports a
// recovery key. It answers a posture question: "what state are the
// security controls in right now?".
//
// Codex 019e74b5 iter-0 REVISE absorbed. See must-fix history:
//
//   - Tri-state nullables (*bool / *int) so "false" can mean "the
//     control is off" without colliding with "we could not measure
//     this control on this host".
//   - Defender split into AntivirusEnabled + RealTimeProtectionEnabled
//     (Get-MpComputerStatus exposes both; they are not interchangeable).
//   - SecurityCenter2 query for third-party AV summary — operators
//     need to distinguish "Defender disabled, no protection" from
//     "Defender disabled because CrowdStrike is active".
//   - Per-profile defaultInboundAction for firewall — "enabled
//     profile with allow-all inbound default" is weaker than absent.
//   - BitLocker by count (not "any" booleans) so 1-of-4 vs 4-of-4
//     encrypted is distinguishable without leaking drive identifiers
//     / GUIDs / mountpoints / recovery material.
//   - Typed enum codes for SecurityProbeSource and SecurityProbeError.

// SecurityPostureSchemaVersion bumps on non-additive schema changes.
const SecurityPostureSchemaVersion = 1

// SecurityProbeSource enumerates the contributing probes. Adding a
// new source is additive and does not bump SchemaVersion; removing
// or renaming one does.
type SecurityProbeSource string

const (
	SecurityProbeSourceDefender       SecurityProbeSource = "defender"
	SecurityProbeSourceSecurityCenter SecurityProbeSource = "securityCenter"
	SecurityProbeSourceFirewall       SecurityProbeSource = "firewall"
	SecurityProbeSourceBitLocker      SecurityProbeSource = "bitlocker"
	SecurityProbeSourcePowerShell     SecurityProbeSource = "powershell"
)

// SecurityProbeError codes. Stable enum; expansion is additive.
const (
	SecurityProbeErrUnsupportedPlatform   = "UNSUPPORTED_PLATFORM"
	SecurityProbeErrPowerShellTimeout     = "POWERSHELL_TIMEOUT"
	SecurityProbeErrPowerShellFailed      = "POWERSHELL_FAILED"
	SecurityProbeErrPowerShellEmptyOutput = "POWERSHELL_EMPTY_OUTPUT"
	SecurityProbeErrPowerShellParseError  = "POWERSHELL_PARSE_ERROR"
	SecurityProbeErrCmdletUnavailable     = "CMDLET_UNAVAILABLE"
	SecurityProbeErrAccessDenied          = "ACCESS_DENIED"
	SecurityProbeErrNoEvidence            = "NO_EVIDENCE"
)

// SecurityProbeError is the per-source structured failure carrier.
// Summary is bounded operator-facing text — never a raw exception
// dump, never a registry value, never a vendor product name.
type SecurityProbeError struct {
	Source  SecurityProbeSource `json:"source,omitempty"`
	Code    string              `json:"code"`
	Summary string              `json:"summary,omitempty"`
}

// DefenderStatus carries the Microsoft Defender (Windows Defender
// Antivirus / Microsoft Defender for Endpoint) posture. All boolean
// fields are tri-state nullable so a host without Defender installed,
// or a host where the cmdlet failed, can be distinguished from a host
// where Defender is explicitly disabled.
type DefenderStatus struct {
	Present                   bool  `json:"present"`
	AntivirusEnabled          *bool `json:"antivirusEnabled"`
	RealTimeProtectionEnabled *bool `json:"realTimeProtectionEnabled"`
	SignatureAgeDays          *int  `json:"signatureAgeDays"`
	EngineVersionPresent      bool  `json:"engineVersionPresent"`
	TamperProtected           *bool `json:"tamperProtected"`
}

// AntivirusStatus is the AV roll-up. Includes Microsoft Defender
// posture plus a bounded third-party summary (count + presence
// boolean) from the SecurityCenter2 WMI namespace. Never carries
// vendor product names or installation paths.
type AntivirusStatus struct {
	MicrosoftDefender     DefenderStatus `json:"microsoftDefender"`
	NonMicrosoftAVPresent *bool          `json:"nonMicrosoftAvPresent"`
	AVProductCount        *int           `json:"avProductCount"`
}

// FirewallProfileStatus carries the per-profile posture. Enabled is
// the headline; DefaultInboundAction distinguishes "profile enabled
// with allow-all default" (effectively no protection) from a real
// block-by-default policy.
type FirewallProfileStatus struct {
	Enabled              bool   `json:"enabled"`
	DefaultInboundAction string `json:"defaultInboundAction"` // "ALLOW" | "BLOCK" | "UNKNOWN"
}

// FirewallStatus is the per-profile roll-up.
type FirewallStatus struct {
	Domain  FirewallProfileStatus `json:"domain"`
	Private FirewallProfileStatus `json:"private"`
	Public  FirewallProfileStatus `json:"public"`
}

// BitLockerStatus carries drive-encryption posture with counts only.
// Drive letters, mountpoints, GUIDs, volume IDs, key protectors and
// recovery passwords are NEVER surfaced to the wire (HARD BOUNDARY).
// SystemDrive booleans cover the OS volume separately because it is
// the canonical "primary attack surface" drive; data drive counts
// aggregate the rest so the operator can tell "1 of 4 data drives
// encrypted" from "all 4 data drives encrypted" without exposing
// drive identifiers.
type BitLockerStatus struct {
	SystemDrivePresent          bool `json:"systemDrivePresent"`
	SystemDriveEncrypted        bool `json:"systemDriveEncrypted"`
	SystemDriveProtected        bool `json:"systemDriveProtected"`
	SystemDriveEncryptionActive bool `json:"systemDriveEncryptionActive"`
	DataDriveCount              int  `json:"dataDriveCount"`
	EncryptedDataDriveCount     int  `json:"encryptedDataDriveCount"`
	ProtectedDataDriveCount     int  `json:"protectedDataDriveCount"`
	SuspendedDriveCount         int  `json:"suspendedDriveCount"`
}

// SecurityPostureResult is the wire-safe outcome. Snapshot includes
// it via *SecurityPostureResult json:"securityPosture,omitempty";
// pointer is nil when the caller did not opt in.
//
// Boolean precedence:
//
//   - ProbeComplete is true if and only if ProbeErrors is empty.
//     Any source-level read failure flips it to false.
//   - Supported is true on Windows and false on every other GOOS.
//   - Caller MUST treat ProbeComplete=false as "evidence incomplete"
//     and never infer "no AV / no firewall / no encryption" from a
//     non-empty ProbeErrors list. The per-control sub-status fields
//     reflect what could be measured; nullable fields stay nil on
//     read failure.
type SecurityPostureResult struct {
	SchemaVersion   int                  `json:"schemaVersion"`
	Supported       bool                 `json:"supported"`
	ProbeComplete   bool                 `json:"probeComplete"`
	Antivirus       AntivirusStatus      `json:"antivirus"`
	Firewall        FirewallStatus       `json:"firewall"`
	BitLocker       BitLockerStatus      `json:"bitlocker"`
	ProbeErrors     []SecurityProbeError `json:"probeErrors,omitempty"`
	ProbeDurationMs int                  `json:"probeDurationMs"`
}

// deriveSecurityPostureSummary fills ProbeComplete from the
// ProbeErrors slice. Sub-status fields are populated by the live
// runner.
func deriveSecurityPostureSummary(result *SecurityPostureResult) {
	result.ProbeComplete = len(result.ProbeErrors) == 0
}

// securityPostureElapsedMs is the monotonic-duration helper.
func securityPostureElapsedMs(start time.Time, now func() time.Time) int {
	if now == nil {
		now = time.Now
	}
	return int(now().Sub(start) / time.Millisecond)
}
