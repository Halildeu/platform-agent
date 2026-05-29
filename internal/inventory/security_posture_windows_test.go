//go:build windows

package inventory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// AG-031 Windows-only parser + classifier unit tests. Codex
// 019e74c3 iter-1 nice-to-have absorb (factor Windows parser into
// testable unit). The full PowerShell live path is exercised by
// the HALILKOOLUB735 lab smoke; these tests lock the new MF-1
// (source enum normalize), MF-2 (no-evidence fail-closed guard),
// MF-3 (SecurityCenter2 explicit failure) and the boundSummary
// control-char defensive normalization without spawning a real
// powershell process.

// stubSecurityProbe installs a temporary script runner that returns
// the supplied stdout / error and restores the original on cleanup.
func stubSecurityProbe(t *testing.T, raw []byte, runErr error) {
	t.Helper()
	prev := runSecurityProbe
	runSecurityProbe = func(_ context.Context) ([]byte, error) {
		return raw, runErr
	}
	t.Cleanup(func() { runSecurityProbe = prev })
}

func TestProbeSecurityPosture_RunnerFailure_FailsProbeComplete(t *testing.T) {
	stubSecurityProbe(t, nil, errors.New("powershell crashed"))
	got := ProbeSecurityPosture(context.Background(), time.Now)
	if got.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false on runner failure")
	}
	if len(got.ProbeErrors) != 1 {
		t.Fatalf("expected exactly 1 probe error, got %d", len(got.ProbeErrors))
	}
	if got.ProbeErrors[0].Code != SecurityProbeErrPowerShellFailed {
		t.Fatalf("expected POWERSHELL_FAILED, got %q", got.ProbeErrors[0].Code)
	}
}

func TestProbeSecurityPosture_EmptyOutput_FailsProbeComplete(t *testing.T) {
	stubSecurityProbe(t, []byte("   \n  "), nil)
	got := ProbeSecurityPosture(context.Background(), time.Now)
	if got.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false on empty output")
	}
	if got.ProbeErrors[0].Code != SecurityProbeErrPowerShellEmptyOutput {
		t.Fatalf("expected POWERSHELL_EMPTY_OUTPUT, got %q", got.ProbeErrors[0].Code)
	}
}

func TestProbeSecurityPosture_MalformedJSON_FailsProbeComplete(t *testing.T) {
	stubSecurityProbe(t, []byte("not json"), nil)
	got := ProbeSecurityPosture(context.Background(), time.Now)
	if got.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false on malformed JSON")
	}
	if got.ProbeErrors[0].Code != SecurityProbeErrPowerShellParseError {
		t.Fatalf("expected POWERSHELL_PARSE_ERROR, got %q", got.ProbeErrors[0].Code)
	}
}

// MF-2: PowerShell emits literal `null` or `{}`. The Go-side
// unmarshal succeeds with a zero-value rawSecurityProbeOutput. The
// fail-closed guard must emit NO_EVIDENCE so probeComplete=false.
func TestProbeSecurityPosture_NullJSON_NoEvidenceGuard(t *testing.T) {
	stubSecurityProbe(t, []byte("null"), nil)
	got := ProbeSecurityPosture(context.Background(), time.Now)
	if got.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false on null JSON output (MF-2)")
	}
	found := false
	for _, e := range got.ProbeErrors {
		if e.Code == SecurityProbeErrNoEvidence {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected NO_EVIDENCE error in ProbeErrors, got %+v", got.ProbeErrors)
	}
}

func TestProbeSecurityPosture_EmptyObject_NoEvidenceGuard(t *testing.T) {
	stubSecurityProbe(t, []byte("{}"), nil)
	got := ProbeSecurityPosture(context.Background(), time.Now)
	if got.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false on {} JSON output (MF-2)")
	}
	found := false
	for _, e := range got.ProbeErrors {
		if e.Code == SecurityProbeErrNoEvidence {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected NO_EVIDENCE error in ProbeErrors, got %+v", got.ProbeErrors)
	}
}

// Counterexample: a valid payload with at least one sub-source
// populated does NOT trigger the NO_EVIDENCE guard.
func TestProbeSecurityPosture_HasEvidence_NoGuardTrigger(t *testing.T) {
	stubSecurityProbe(t, []byte(`{
        "defender": {"present": false, "antivirusEnabled": null, "realTimeProtectionEnabled": null, "signatureAgeDays": null, "engineVersionPresent": false, "tamperProtected": null}
    }`), nil)
	got := ProbeSecurityPosture(context.Background(), time.Now)
	for _, e := range got.ProbeErrors {
		if e.Code == SecurityProbeErrNoEvidence {
			t.Fatalf("did not expect NO_EVIDENCE when defender source is populated, got %+v", got.ProbeErrors)
		}
	}
	if !got.ProbeComplete {
		t.Fatalf("expected ProbeComplete=true when evidence is present and no errors, got false")
	}
}

// MF-1: source enum normalize. PowerShell emits canonical mixed-case
// "securityCenter"; the Go-side mapper must preserve it (NOT lower
// case). Unknown values must collapse to powershell catch-all.
func TestNormalizeSecuritySource_AllowlistMixedCase(t *testing.T) {
	cases := []struct {
		in   string
		want SecurityProbeSource
	}{
		{"defender", SecurityProbeSourceDefender},
		{"securityCenter", SecurityProbeSourceSecurityCenter},
		{"firewall", SecurityProbeSourceFirewall},
		{"bitlocker", SecurityProbeSourceBitLocker},
		{"powershell", SecurityProbeSourcePowerShell},
		// MF-1 explicit regression: lower-cased "securitycenter"
		// MUST NOT match — the enum literal is mixed-case.
		{"securitycenter", SecurityProbeSourcePowerShell},
		// Unknown / blank → powershell catch-all so the enum stays
		// closed.
		{"", SecurityProbeSourcePowerShell},
		{"random", SecurityProbeSourcePowerShell},
		// Trim-tolerant for whitespace.
		{"  defender  ", SecurityProbeSourceDefender},
	}
	for _, tc := range cases {
		got := normalizeSecuritySource(tc.in)
		if got != tc.want {
			t.Errorf("normalizeSecuritySource(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// MF-1 integration: an error embedded in the PowerShell output as
// `securityCenter` must reach the wire as exactly that enum value
// (no lower-case drift).
func TestProbeSecurityPosture_SourceEnumPreserved(t *testing.T) {
	stubSecurityProbe(t, []byte(`{
        "defender": {"present": true, "antivirusEnabled": true, "realTimeProtectionEnabled": true, "signatureAgeDays": 0, "engineVersionPresent": true, "tamperProtected": true},
        "errors": [{"source": "securityCenter", "code": "ACCESS_DENIED", "summary": "namespace blocked"}]
    }`), nil)
	got := ProbeSecurityPosture(context.Background(), time.Now)
	if len(got.ProbeErrors) != 1 {
		t.Fatalf("expected 1 probe error, got %d", len(got.ProbeErrors))
	}
	if got.ProbeErrors[0].Source != SecurityProbeSourceSecurityCenter {
		t.Fatalf("expected source %q, got %q",
			SecurityProbeSourceSecurityCenter, got.ProbeErrors[0].Source)
	}
}

// MF-1 boundary: PowerShell could (incorrectly) emit "securitycenter"
// lowercase. Mapper must collapse it to the powershell catch-all so
// the enum is never violated — even at the cost of losing source
// fidelity for malformed input.
func TestProbeSecurityPosture_UnknownSourceFallsBack(t *testing.T) {
	stubSecurityProbe(t, []byte(`{
        "defender": {"present": true, "antivirusEnabled": true, "realTimeProtectionEnabled": true, "signatureAgeDays": 0, "engineVersionPresent": true, "tamperProtected": true},
        "errors": [{"source": "totally-unknown", "code": "POWERSHELL_FAILED", "summary": "test"}]
    }`), nil)
	got := ProbeSecurityPosture(context.Background(), time.Now)
	if got.ProbeErrors[0].Source != SecurityProbeSourcePowerShell {
		t.Fatalf("expected fallback to powershell enum, got %q",
			got.ProbeErrors[0].Source)
	}
}

// boundSummary control-char normalization (Codex iter-1
// nice-to-have absorb): NUL, BEL, ESC, etc. must be replaced with
// spaces; CR/LF/TAB folded to spaces. Length cap and trim still
// applied.
func TestBoundSummary_ControlCharNormalization(t *testing.T) {
	in := "line1\nline2\rline3\ttab\x00nul\x07bel\x1bescend"
	got := boundSummary(in)
	if strings.ContainsAny(got, "\x00\x07\x1b\r\n\t") {
		t.Fatalf("expected control chars stripped, got %q", got)
	}
}

func TestBoundSummary_LengthCap(t *testing.T) {
	in := strings.Repeat("a", 500)
	got := boundSummary(in)
	if len(got) > 200 {
		t.Fatalf("expected length <= 200, got %d", len(got))
	}
}

func TestBoundSummary_EmptyAfterTrim(t *testing.T) {
	if got := boundSummary("   "); got != "" {
		t.Fatalf("expected empty string for whitespace-only input, got %q", got)
	}
}

// normalizeFirewallAction explicit allowlist test (defense in
// depth against PowerShell sending unexpected values).
func TestNormalizeFirewallAction(t *testing.T) {
	cases := map[string]string{
		"ALLOW":          "ALLOW",
		"BLOCK":          "BLOCK",
		"allow":          "ALLOW",
		"block":          "BLOCK",
		"  allow  ":      "ALLOW",
		"UNKNOWN":        "UNKNOWN",
		"NotConfigured":  "UNKNOWN",
		"":               "UNKNOWN",
		"random-garbage": "UNKNOWN",
	}
	for in, want := range cases {
		if got := normalizeFirewallAction(in); got != want {
			t.Errorf("normalizeFirewallAction(%q) = %q; want %q", in, got, want)
		}
	}
}

// hasAnySecurityEvidence sub-source presence test.
func TestHasAnySecurityEvidence(t *testing.T) {
	if hasAnySecurityEvidence(nil) {
		t.Fatalf("nil input must return false")
	}
	if hasAnySecurityEvidence(&rawSecurityProbeOutput{}) {
		t.Fatalf("zero-value input must return false")
	}
	with := &rawSecurityProbeOutput{Defender: &rawDefender{Present: true}}
	if !hasAnySecurityEvidence(with) {
		t.Fatalf("defender populated must return true")
	}
	with = &rawSecurityProbeOutput{}
	with.Firewall.Domain = &rawFirewallProfile{Enabled: true}
	if !hasAnySecurityEvidence(with) {
		t.Fatalf("firewall.domain populated must return true")
	}
}
