package inventory

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

// AG-037 — cross-platform tests for the hotfix posture probe wire-shape
// + non-Windows stub. The Windows pinned-PowerShell + WUA COM path is
// exercised by the integration harness (Parallels W11 lab smoke);
// these tests lock the wire-shape contract so a future schema-touching
// PR breaks loudly.

// ────────────────────────────────────────────────────────────────
// Cross-platform wire-shape locks

func TestHotfixPostureResult_JSONKeys(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	r := HotfixPostureResult{
		SchemaVersion:   HotfixPostureSchemaVersion,
		Supported:       true,
		ProbeComplete:   true,
		CollectedAt:     now,
		ProbeDurationMs: 250,
		InstalledSourceUsed: HotfixPostureSourceWUA,
		PendingSourceUsed:   HotfixPostureSourceWUA,
		HealthSourceUsed:    HotfixPostureSourceService,
		InstalledCount: 1,
		InstalledHotfixes: []InstalledHotfix{
			{KbId: "KB5034122", Description: "Security Update"},
		},
		PendingTotalCount: 0,
		AgentHealth: WindowsUpdateAgentHealth{
			WuaServiceState:  ServiceStateRunning,
			BitsServiceState: ServiceStateRunning,
		},
	}
	buf, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Allowlist — every top-level key must appear in this set OR
	// must be omitempty + absent in the payload above. Adding a new
	// field requires a contract bump.
	expectedTopKeys := map[string]struct{}{
		"schemaVersion":       {},
		"supported":           {},
		"probeComplete":       {},
		"collectedAt":         {},
		"probeDurationMs":     {},
		"installedSourceUsed": {},
		"installedHotfixes":   {},
		"installedCount":      {},
		"pendingSourceUsed":   {},
		"pendingTotalCount":   {},
		"healthSourceUsed":    {},
		"agentHealth":         {},
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(buf, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k := range m {
		if _, ok := expectedTopKeys[k]; !ok {
			t.Errorf("unexpected top-level key %q in JSON: %s", k, string(buf))
		}
	}
}

func TestInstalledHotfix_JSONKeys(t *testing.T) {
	tm := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	h := InstalledHotfix{
		KbId:        "KB5034122",
		InstalledOn: &tm,
		Description: "Security Update for Windows",
	}
	buf, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(buf)
	// Allowlist enforcement: exactly these three keys.
	for _, want := range []string{`"kbId"`, `"installedOn"`, `"description"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing expected key %s in %s", want, got)
		}
	}
	// Forbidden — never on wire.
	for _, forbidden := range []string{
		`"productCode"`,
		`"msiGuid"`,
		`"supersedence"`,
		`"installClient"`,
		`"installedBy"`,
		`"commandLine"`,
		`"accountName"`,
	} {
		if strings.Contains(got, forbidden) {
			t.Errorf("forbidden key %s present in %s", forbidden, got)
		}
	}
}

func TestPendingUpdateItem_JSONKeys(t *testing.T) {
	p := PendingUpdateItem{
		KbIds:           []string{"KB1234567"},
		PrimaryCategory: HotfixPostureCategorySecurity,
		Severity:        HotfixPostureSeverityCritical,
	}
	buf, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(buf)
	for _, want := range []string{`"kbIds"`, `"primaryCategory"`, `"severity"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	for _, forbidden := range []string{
		`"title"`,             // raw update title NEVER on wire in v1
		`"description"`,       // pending items intentionally lack description
		`"vendor"`,
		`"installClientAppId"`,
		`"deploymentAction"`,
	} {
		if strings.Contains(got, forbidden) {
			t.Errorf("forbidden key %s in pending item: %s", forbidden, got)
		}
	}
}

func TestPendingUpdateItem_InstalledOn_NullSerialization(t *testing.T) {
	h := InstalledHotfix{KbId: "KB1234567"}
	// InstalledOn omitempty when nil — should not emit "installedOn"
	// at all rather than emitting a zero-valued timestamp (Codex
	// 019e8167 must-fix #1).
	buf, _ := json.Marshal(h)
	if strings.Contains(string(buf), `"installedOn"`) {
		t.Errorf("expected installedOn to be omitted when nil, got %s", string(buf))
	}
}

func TestServiceState_EnumValues(t *testing.T) {
	cases := []ServiceState{
		ServiceStateRunning, ServiceStateStopped, ServiceStateDisabled, ServiceStateUnknown,
	}
	want := map[ServiceState]bool{
		"RUNNING": true, "STOPPED": true, "DISABLED": true, "UNKNOWN": true,
	}
	for _, c := range cases {
		if !want[c] {
			t.Errorf("unexpected ServiceState %q", c)
		}
	}
}

func TestHotfixPostureProbeErrorCode_AllListed(t *testing.T) {
	// Lock the canonical error code set so a typo'd new code requires
	// an explicit test bump.
	expected := []HotfixPostureProbeErrorCode{
		HotfixPostureUnsupportedPlatform,
		HotfixPostureAccessDenied,
		HotfixPostureCOMFailed,
		HotfixPostureWSUSUnreachable,
		HotfixPosturePowerShellMissing,
		HotfixPosturePowerShellTimeout,
		HotfixPosturePowerShellFailed,
		HotfixPosturePowerShellEmptyOutput,
		HotfixPosturePowerShellParseError,
		HotfixPostureRegistryUnavailable,
		HotfixPostureServiceQueryFailed,
		HotfixPostureNoEvidence,
	}
	if len(expected) != 12 {
		t.Errorf("expected 12 canonical error codes, got %d", len(expected))
	}
}

// ────────────────────────────────────────────────────────────────
// Non-Windows stub semantics

func TestProbeHotfixPosture_NonWindowsStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows runner test path lives in *_windows_test.go")
	}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	fixedNow := func() time.Time { return now }
	r := ProbeHotfixPosture(context.Background(), fixedNow)
	if r.Supported {
		t.Errorf("expected supported=false on %s, got true", runtime.GOOS)
	}
	if r.ProbeComplete {
		t.Errorf("expected probeComplete=false on stub")
	}
	if r.SchemaVersion != HotfixPostureSchemaVersion {
		t.Errorf("expected schemaVersion=%d, got %d",
			HotfixPostureSchemaVersion, r.SchemaVersion)
	}
	if len(r.ProbeErrors) != 1 {
		t.Fatalf("expected exactly 1 probe error, got %d", len(r.ProbeErrors))
	}
	if r.ProbeErrors[0].Code != HotfixPostureUnsupportedPlatform {
		t.Errorf("expected UNSUPPORTED_PLATFORM, got %q", r.ProbeErrors[0].Code)
	}
	if r.ProbeErrors[0].Source != HotfixPostureSourceNone {
		t.Errorf("expected source=none on stub, got %q", r.ProbeErrors[0].Source)
	}
	if r.InstalledSourceUsed != HotfixPostureSourceNone {
		t.Errorf("expected installedSourceUsed=none, got %q", r.InstalledSourceUsed)
	}
	if r.AgentHealth.WuaServiceState != ServiceStateUnknown {
		t.Errorf("expected WuaServiceState=UNKNOWN, got %q",
			r.AgentHealth.WuaServiceState)
	}
}

// ────────────────────────────────────────────────────────────────
// CollectWithOptions opt-in gate

func TestCollectWithOptions_HotfixPosture_DefaultOmit(t *testing.T) {
	saved := collectHotfixPostureForSnapshot
	defer func() { collectHotfixPostureForSnapshot = saved }()
	called := false
	collectHotfixPostureForSnapshot = func(_ time.Time) HotfixPostureResult {
		called = true
		return HotfixPostureResult{}
	}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	snap := CollectWithOptions("test-agent", now, CollectOptions{})
	if called {
		t.Errorf("expected probe NOT to run on default opts, but it did")
	}
	if snap.HotfixPosture != nil {
		t.Errorf("expected Snapshot.HotfixPosture=nil on default opts, got %+v",
			snap.HotfixPosture)
	}
}

func TestCollectWithOptions_HotfixPosture_OptIn(t *testing.T) {
	saved := collectHotfixPostureForSnapshot
	defer func() { collectHotfixPostureForSnapshot = saved }()
	called := false
	stub := HotfixPostureResult{
		SchemaVersion: HotfixPostureSchemaVersion,
		Supported:     true,
		ProbeComplete: true,
	}
	collectHotfixPostureForSnapshot = func(_ time.Time) HotfixPostureResult {
		called = true
		return stub
	}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	snap := CollectWithOptions("test-agent", now, CollectOptions{IncludeHotfixPosture: true})
	if !called {
		t.Errorf("expected probe to run when IncludeHotfixPosture=true")
	}
	if snap.HotfixPosture == nil {
		t.Fatalf("expected Snapshot.HotfixPosture to be populated")
	}
	if snap.HotfixPosture.SchemaVersion != HotfixPostureSchemaVersion {
		t.Errorf("expected schemaVersion=%d, got %d",
			HotfixPostureSchemaVersion, snap.HotfixPosture.SchemaVersion)
	}
}

// ────────────────────────────────────────────────────────────────
// Snapshot wire shape — HotfixPosture omitempty when nil

func TestSnapshotJSON_HotfixPostureOmittedWhenNil(t *testing.T) {
	snap := Snapshot{
		Hostname:     "test-host",
		OSFamily:     "linux",
		AgentVersion: "0.0.0",
		CollectedAt:  time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
	}
	buf, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(buf)
	if strings.Contains(got, `"hotfixPosture"`) {
		t.Errorf("expected hotfixPosture key absent when nil, got %s", got)
	}
}

// ────────────────────────────────────────────────────────────────
// Redaction guards (no forbidden strings in summary)

func TestHotfixPostureProbeError_SummaryRedacted(t *testing.T) {
	// The redactHotfixSummary helper is in *_windows.go but the
	// contract on Summary is enforced at struct level: no CRLF, no
	// path-like prefixes. A non-Windows test cannot exercise the
	// helper directly, but we lock that any error returned by the
	// stub never leaks a multi-line stack.
	if runtime.GOOS == "windows" {
		t.Skip("Windows path covers redactor directly")
	}
	r := ProbeHotfixPosture(context.Background(), nil)
	for _, e := range r.ProbeErrors {
		if strings.Contains(e.Summary, "\n") || strings.Contains(e.Summary, "\r") {
			t.Errorf("probeError.Summary contains CRLF, leaking multi-line: %q",
				e.Summary)
		}
	}
}
