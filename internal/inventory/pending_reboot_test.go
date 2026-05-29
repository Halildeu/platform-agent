package inventory

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

// AG-030 — cross-platform tests for the pending-reboot probe summary
// helpers + non-Windows stub. The Windows registry path is exercised
// by the integration harness (Parallels W11 lab smoke); these tests
// lock the wire-shape contract (signal struct, derived bools, sources
// slice, unsupported semantics) so a future schema-touching PR breaks
// loudly.

// ────────────────────────────────────────────────────────────────
// derivePendingRebootSummary

func TestDerivePendingRebootSummary_AllFalse(t *testing.T) {
	result := PendingRebootResult{}
	derivePendingRebootSummary(&result)
	if result.PendingReboot {
		t.Fatalf("expected PendingReboot=false, got true")
	}
	if !result.ProbeComplete {
		t.Fatalf("expected ProbeComplete=true when no errors present")
	}
	if len(result.Sources) != 0 {
		t.Fatalf("expected empty Sources, got %v", result.Sources)
	}
}

func TestDerivePendingRebootSummary_SingleSourceTrue(t *testing.T) {
	cases := []struct {
		name   string
		setter func(*PendingRebootSignals)
		want   PendingRebootSource
	}{
		{"CBS", func(s *PendingRebootSignals) { s.CBSRebootPending = true }, PendingRebootSourceCBS},
		{"WU", func(s *PendingRebootSignals) { s.WindowsUpdateRebootRequired = true }, PendingRebootSourceWindowsUpdate},
		{"PFRO", func(s *PendingRebootSignals) { s.PendingFileRenameOperations = true }, PendingRebootSourcePendingFileRenameOperations},
		{"CompName", func(s *PendingRebootSignals) { s.ComputerNameChangePending = true }, PendingRebootSourceComputerNameChange},
		{"UEV", func(s *PendingRebootSignals) { s.UpdateExeVolatile = true }, PendingRebootSourceUpdateExeVolatile},
		{"Netlogon", func(s *PendingRebootSignals) { s.NetlogonJoinPending = true }, PendingRebootSourceNetlogonJoinPending},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var signals PendingRebootSignals
			tc.setter(&signals)
			result := PendingRebootResult{Signals: signals}
			derivePendingRebootSummary(&result)
			if !result.PendingReboot {
				t.Fatalf("expected PendingReboot=true when %s fires", tc.name)
			}
			if len(result.Sources) != 1 || result.Sources[0] != tc.want {
				t.Fatalf("Sources mismatch: got %v want [%s]", result.Sources, tc.want)
			}
			if !result.ProbeComplete {
				t.Fatalf("expected ProbeComplete=true when no errors present")
			}
		})
	}
}

func TestDerivePendingRebootSummary_AllSourcesTrue(t *testing.T) {
	result := PendingRebootResult{
		Signals: PendingRebootSignals{
			CBSRebootPending:            true,
			WindowsUpdateRebootRequired: true,
			PendingFileRenameOperations: true,
			ComputerNameChangePending:   true,
			UpdateExeVolatile:           true,
			NetlogonJoinPending:         true,
		},
	}
	derivePendingRebootSummary(&result)
	if !result.PendingReboot {
		t.Fatalf("expected PendingReboot=true")
	}
	if len(result.Sources) != 6 {
		t.Fatalf("expected 6 sources, got %d (%v)", len(result.Sources), result.Sources)
	}
}

func TestDerivePendingRebootSummary_ProbeErrorFlipsProbeComplete(t *testing.T) {
	result := PendingRebootResult{
		Signals: PendingRebootSignals{CBSRebootPending: true},
		ProbeErrors: []PendingRebootProbeError{
			{
				Source:  PendingRebootSourceWindowsUpdate,
				Code:    PendingRebootErrAccessDenied,
				Summary: "WU key probe failed",
			},
		},
	}
	derivePendingRebootSummary(&result)
	if !result.PendingReboot {
		t.Fatalf("expected PendingReboot=true (CBS fired)")
	}
	if result.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false when any probe error present")
	}
	if len(result.Sources) != 1 {
		t.Fatalf("expected only CBS source, got %v", result.Sources)
	}
}

// ────────────────────────────────────────────────────────────────
// Non-Windows stub (always runs cross-platform; the build tag in
// pending_reboot_windows.go means the Windows path is excluded on
// macOS/Linux test runs and the stub from pending_reboot_other.go
// is linked instead).

// nonWindowsBuild reports true when the unsupported-platform stub
// is the linked implementation. Codex 019e749c post-impl P0#1: use
// runtime.GOOS for the cross-build platform tag instead of probing
// at package init (the package-init probe panicked on Windows
// builds because ProbePendingReboot dereferenced a nil ctx).
var nonWindowsBuild = runtime.GOOS != "windows"

func TestProbePendingReboot_NonWindowsStubShape(t *testing.T) {
	if !nonWindowsBuild {
		t.Skip("Windows build — stub shape test does not apply")
	}
	r := ProbePendingReboot(nil, func() time.Time { return time.Unix(0, 0) })

	if r.SchemaVersion != PendingRebootSchemaVersion {
		t.Errorf("SchemaVersion: got %d want %d",
			r.SchemaVersion, PendingRebootSchemaVersion)
	}
	if r.Supported {
		t.Errorf("Supported: got true, want false on non-Windows stub")
	}
	if r.PendingReboot {
		t.Errorf("PendingReboot: got true, want false (no positive evidence)")
	}
	if r.ProbeComplete {
		t.Errorf("ProbeComplete: got true, want false (evidence incomplete)")
	}
	if len(r.ProbeErrors) != 1 {
		t.Fatalf("ProbeErrors: got %d entries, want 1", len(r.ProbeErrors))
	}
	if r.ProbeErrors[0].Code != PendingRebootErrUnsupportedPlatform {
		t.Errorf("ProbeErrors[0].Code: got %q want %q",
			r.ProbeErrors[0].Code, PendingRebootErrUnsupportedPlatform)
	}
	if !strings.Contains(r.ProbeErrors[0].Summary, "not implemented") {
		t.Errorf("ProbeErrors[0].Summary: got %q, expected to contain 'not implemented'",
			r.ProbeErrors[0].Summary)
	}
}

// ────────────────────────────────────────────────────────────────
// CollectWithOptions integration — default omit, opt-in call.

func TestCollectWithOptions_DefaultOmitsPendingReboot(t *testing.T) {
	called := false
	swap := collectPendingRebootForSnapshot
	collectPendingRebootForSnapshot = func(_ time.Time) PendingRebootResult {
		called = true
		return PendingRebootResult{}
	}
	t.Cleanup(func() { collectPendingRebootForSnapshot = swap })

	snapshot := CollectWithOptions("test-agent", time.Now(), CollectOptions{})

	if called {
		t.Fatalf("AG-025H lightweight default must not invoke pending-reboot probe")
	}
	if snapshot.PendingReboot != nil {
		t.Fatalf("Snapshot.PendingReboot must be nil when probe was not requested")
	}
}

func TestCollectWithOptions_OptInCallsProbeOnce(t *testing.T) {
	calls := 0
	swap := collectPendingRebootForSnapshot
	collectPendingRebootForSnapshot = func(_ time.Time) PendingRebootResult {
		calls++
		return PendingRebootResult{
			SchemaVersion: PendingRebootSchemaVersion,
			Supported:     true,
			Signals:       PendingRebootSignals{CBSRebootPending: true},
			PendingReboot: true,
			ProbeComplete: true,
			Sources:       []PendingRebootSource{PendingRebootSourceCBS},
		}
	}
	t.Cleanup(func() { collectPendingRebootForSnapshot = swap })

	snapshot := CollectWithOptions("test-agent", time.Now(),
		CollectOptions{IncludePendingReboot: true})

	if calls != 1 {
		t.Fatalf("expected probe to run exactly once, got %d", calls)
	}
	if snapshot.PendingReboot == nil {
		t.Fatalf("Snapshot.PendingReboot must be populated when probe was requested")
	}
	if !snapshot.PendingReboot.PendingReboot {
		t.Fatalf("Snapshot.PendingReboot.PendingReboot expected true")
	}
	if len(snapshot.PendingReboot.Sources) != 1 || snapshot.PendingReboot.Sources[0] != PendingRebootSourceCBS {
		t.Fatalf("Sources mismatch: got %v want [CBS]",
			snapshot.PendingReboot.Sources)
	}
}

// ────────────────────────────────────────────────────────────────
// Wire shape: all-false JSON contract (Codex 019e749c post-impl
// P0#2 absorb). Every PendingRebootSignals field must remain
// present in the wire payload even when its value is false; the
// `omitempty` JSON tag was removed from UpdateExeVolatile and
// NetlogonJoinPending so the contract is uniform across all six
// signals.

func TestPendingRebootSignals_AllFalseJSONKeepsAllKeys(t *testing.T) {
	raw, err := json.Marshal(PendingRebootSignals{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, key := range []string{
		`"cbsRebootPending"`,
		`"windowsUpdateRebootRequired"`,
		`"pendingFileRenameOperations"`,
		`"computerNameChangePending"`,
		`"updateExeVolatile"`,
		`"netlogonJoinPending"`,
	} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("AllFalse JSON must include %s, got %s",
				key, raw)
		}
	}
}

func TestPendingRebootSignals_AllFalseJSONValuesAreFalse(t *testing.T) {
	raw, err := json.Marshal(PendingRebootSignals{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Ensure each key is set to literal `false`, not the
	// zero-omitted form. We don't unmarshal into a struct because
	// that would erase the wire-presence question.
	for _, frag := range []string{
		`"cbsRebootPending":false`,
		`"windowsUpdateRebootRequired":false`,
		`"pendingFileRenameOperations":false`,
		`"computerNameChangePending":false`,
		`"updateExeVolatile":false`,
		`"netlogonJoinPending":false`,
	} {
		if !strings.Contains(string(raw), frag) {
			t.Errorf("AllFalse JSON must include %s, got %s",
				frag, raw)
		}
	}
}
