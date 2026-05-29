package inventory

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

// AG-031 — cross-platform tests for the security posture probe.
// The Windows live path (Get-MpComputerStatus + SecurityCenter2 +
// Get-NetFirewallProfile + Get-BitLockerVolume) is exercised by the
// Parallels W11 (HALILKOOLUB735) lab smoke; these tests lock the
// wire-shape contract (nullable fields, count-only BitLocker,
// per-profile firewall, source enums, unsupported semantics) so a
// future schema-touching PR breaks loudly.

// ────────────────────────────────────────────────────────────────
// deriveSecurityPostureSummary

func TestDeriveSecurityPostureSummary_EmptyErrors(t *testing.T) {
	result := SecurityPostureResult{}
	deriveSecurityPostureSummary(&result)
	if !result.ProbeComplete {
		t.Fatalf("expected ProbeComplete=true when no errors present")
	}
}

func TestDeriveSecurityPostureSummary_AnyError(t *testing.T) {
	result := SecurityPostureResult{
		ProbeErrors: []SecurityProbeError{
			{Source: SecurityProbeSourceDefender, Code: SecurityProbeErrPowerShellFailed},
		},
	}
	deriveSecurityPostureSummary(&result)
	if result.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false when probe errors present")
	}
}

// ────────────────────────────────────────────────────────────────
// JSON contract — nullable presence + count-only BitLocker

// TestSecurityPostureResult_JSONContract_NullableFieldsArePresent locks
// the wire contract Codex 019e74b5 iter-0 must-fix #1+#2 introduced:
// the nullable bools/ints must appear in JSON as `null` (not omitted)
// when unmeasured, so the backend can distinguish unknown from false.
func TestSecurityPostureResult_JSONContract_NullableFieldsArePresent(t *testing.T) {
	result := SecurityPostureResult{
		SchemaVersion: SecurityPostureSchemaVersion,
		Supported:     true,
		ProbeComplete: true,
	}
	// Force the zero-value firewall actions to the explicit UNKNOWN
	// sentinel so the wire never carries an empty string.
	result.Firewall.Domain.DefaultInboundAction = "UNKNOWN"
	result.Firewall.Private.DefaultInboundAction = "UNKNOWN"
	result.Firewall.Public.DefaultInboundAction = "UNKNOWN"

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	s := string(raw)

	// Defender nullable fields MUST appear as literal `null`.
	mustContain := []string{
		`"antivirusEnabled":null`,
		`"realTimeProtectionEnabled":null`,
		`"signatureAgeDays":null`,
		`"tamperProtected":null`,
		`"nonMicrosoftAvPresent":null`,
		`"avProductCount":null`,
	}
	for _, frag := range mustContain {
		if !strings.Contains(s, frag) {
			t.Errorf("expected JSON to contain %q; got: %s", frag, s)
		}
	}

	// BitLocker counts default to int 0 — must be present.
	for _, frag := range []string{
		`"dataDriveCount":0`,
		`"encryptedDataDriveCount":0`,
		`"protectedDataDriveCount":0`,
		`"suspendedDriveCount":0`,
	} {
		if !strings.Contains(s, frag) {
			t.Errorf("expected JSON to contain %q; got: %s", frag, s)
		}
	}

	// Firewall per-profile inbound action must be present and
	// non-empty.
	for _, frag := range []string{
		`"defaultInboundAction":"UNKNOWN"`,
	} {
		if !strings.Contains(s, frag) {
			t.Errorf("expected JSON to contain %q; got: %s", frag, s)
		}
	}
}

// TestSecurityPostureResult_JSONContract_NonNilPointersSerialize asserts
// the *bool / *int pointer fields round-trip non-nil values correctly.
func TestSecurityPostureResult_JSONContract_NonNilPointersSerialize(t *testing.T) {
	trueP := true
	falseP := false
	age := 3
	count := 2
	result := SecurityPostureResult{
		SchemaVersion: SecurityPostureSchemaVersion,
		Supported:     true,
		ProbeComplete: true,
		Antivirus: AntivirusStatus{
			MicrosoftDefender: DefenderStatus{
				Present:                   true,
				AntivirusEnabled:          &trueP,
				RealTimeProtectionEnabled: &falseP,
				SignatureAgeDays:          &age,
				EngineVersionPresent:      true,
				TamperProtected:           &trueP,
			},
			NonMicrosoftAVPresent: &falseP,
			AVProductCount:        &count,
		},
		Firewall: FirewallStatus{
			Domain:  FirewallProfileStatus{Enabled: true, DefaultInboundAction: "BLOCK"},
			Private: FirewallProfileStatus{Enabled: true, DefaultInboundAction: "BLOCK"},
			Public:  FirewallProfileStatus{Enabled: false, DefaultInboundAction: "ALLOW"},
		},
		BitLocker: BitLockerStatus{
			SystemDrivePresent:          true,
			SystemDriveEncrypted:        true,
			SystemDriveProtected:        true,
			SystemDriveEncryptionActive: false,
			DataDriveCount:              4,
			EncryptedDataDriveCount:     1,
			ProtectedDataDriveCount:     1,
			SuspendedDriveCount:         0,
		},
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	s := string(raw)
	for _, frag := range []string{
		`"antivirusEnabled":true`,
		`"realTimeProtectionEnabled":false`,
		`"signatureAgeDays":3`,
		`"tamperProtected":true`,
		`"nonMicrosoftAvPresent":false`,
		`"avProductCount":2`,
		`"defaultInboundAction":"BLOCK"`,
		`"defaultInboundAction":"ALLOW"`,
		`"systemDriveEncrypted":true`,
		`"dataDriveCount":4`,
		`"encryptedDataDriveCount":1`,
	} {
		if !strings.Contains(s, frag) {
			t.Errorf("expected JSON to contain %q; got: %s", frag, s)
		}
	}
}

// ────────────────────────────────────────────────────────────────
// Source / Error enum stability

func TestSecurityProbeSource_Values(t *testing.T) {
	cases := map[SecurityProbeSource]string{
		SecurityProbeSourceDefender:       "defender",
		SecurityProbeSourceSecurityCenter: "securityCenter",
		SecurityProbeSourceFirewall:       "firewall",
		SecurityProbeSourceBitLocker:      "bitlocker",
		SecurityProbeSourcePowerShell:     "powershell",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("SecurityProbeSource %q != %q", string(got), want)
		}
	}
}

func TestSecurityProbeError_Codes(t *testing.T) {
	wanted := map[string]string{
		"UNSUPPORTED_PLATFORM":    SecurityProbeErrUnsupportedPlatform,
		"POWERSHELL_TIMEOUT":      SecurityProbeErrPowerShellTimeout,
		"POWERSHELL_FAILED":       SecurityProbeErrPowerShellFailed,
		"POWERSHELL_EMPTY_OUTPUT": SecurityProbeErrPowerShellEmptyOutput,
		"POWERSHELL_PARSE_ERROR":  SecurityProbeErrPowerShellParseError,
		"CMDLET_UNAVAILABLE":      SecurityProbeErrCmdletUnavailable,
		"ACCESS_DENIED":           SecurityProbeErrAccessDenied,
		"NO_EVIDENCE":             SecurityProbeErrNoEvidence,
	}
	for want, got := range wanted {
		if got != want {
			t.Errorf("expected error code %q, got %q", want, got)
		}
	}
}

// ────────────────────────────────────────────────────────────────
// Non-Windows stub semantics

func TestProbeSecurityPosture_NonWindowsStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses the live implementation")
	}
	t0 := time.Unix(1700000000, 0)
	calls := 0
	clock := func() time.Time {
		calls++
		// Make duration measurement deterministic: start=t0,
		// finish=t0+2ms.
		return t0.Add(time.Duration(calls-1) * 2 * time.Millisecond)
	}
	got := ProbeSecurityPosture(nil, clock)
	if got.Supported {
		t.Fatalf("expected Supported=false on %s", runtime.GOOS)
	}
	if got.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false on stub")
	}
	if got.SchemaVersion != SecurityPostureSchemaVersion {
		t.Fatalf("schemaVersion = %d, want %d", got.SchemaVersion, SecurityPostureSchemaVersion)
	}
	if len(got.ProbeErrors) != 1 {
		t.Fatalf("expected exactly one probe error, got %d", len(got.ProbeErrors))
	}
	if got.ProbeErrors[0].Code != SecurityProbeErrUnsupportedPlatform {
		t.Fatalf("expected code %q, got %q",
			SecurityProbeErrUnsupportedPlatform, got.ProbeErrors[0].Code)
	}
	if !strings.Contains(got.ProbeErrors[0].Summary, runtime.GOOS) {
		t.Fatalf("expected summary to mention runtime %q, got %q",
			runtime.GOOS, got.ProbeErrors[0].Summary)
	}
}

// ────────────────────────────────────────────────────────────────
// CollectWithOptions opt-in / opt-out

// TestCollectWithOptions_SecurityPostureOptOut asserts the AG-025H
// lightweight default never invokes the probe (no PowerShell, no
// CIM call, no allocation in Snapshot.SecurityPosture).
func TestCollectWithOptions_SecurityPostureOptOut(t *testing.T) {
	invoked := false
	restore := withCollectSecurityPostureForSnapshot(func(_ time.Time) SecurityPostureResult {
		invoked = true
		return SecurityPostureResult{}
	})
	defer restore()

	snap := CollectWithOptions("test", time.Unix(1700000000, 0), CollectOptions{})
	if invoked {
		t.Fatalf("security posture probe must not run when opt-out")
	}
	if snap.SecurityPosture != nil {
		t.Fatalf("snapshot.SecurityPosture must be nil when opt-out")
	}
}

// TestCollectWithOptions_SecurityPostureOptIn asserts the opt-in
// payload bit routes through the test-seam variable and wires the
// result onto Snapshot.SecurityPosture.
func TestCollectWithOptions_SecurityPostureOptIn(t *testing.T) {
	sentinel := SecurityPostureResult{
		SchemaVersion: SecurityPostureSchemaVersion,
		Supported:     true,
		ProbeComplete: true,
	}
	calls := 0
	restore := withCollectSecurityPostureForSnapshot(func(_ time.Time) SecurityPostureResult {
		calls++
		return sentinel
	})
	defer restore()

	snap := CollectWithOptions("test", time.Unix(1700000000, 0),
		CollectOptions{IncludeSecurityPosture: true})
	if calls != 1 {
		t.Fatalf("expected probe invocation count = 1, got %d", calls)
	}
	if snap.SecurityPosture == nil {
		t.Fatalf("snapshot.SecurityPosture must be set when opt-in")
	}
	if snap.SecurityPosture.SchemaVersion != SecurityPostureSchemaVersion {
		t.Fatalf("schemaVersion = %d, want %d",
			snap.SecurityPosture.SchemaVersion, SecurityPostureSchemaVersion)
	}
}

// ────────────────────────────────────────────────────────────────
// helpers

// withCollectSecurityPostureForSnapshot temporarily replaces the
// package-level test seam and returns a restore function.
func withCollectSecurityPostureForSnapshot(stub func(time.Time) SecurityPostureResult) func() {
	prev := collectSecurityPostureForSnapshot
	collectSecurityPostureForSnapshot = stub
	return func() { collectSecurityPostureForSnapshot = prev }
}
