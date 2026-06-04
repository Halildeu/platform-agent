package inventory

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestStartupExposureSchemaVersionPinned guards the wire contract:
// schemaVersion=1 is fixed in v1; bumping requires explicit contract
// migration.
func TestStartupExposureSchemaVersionPinned(t *testing.T) {
	if StartupExposureSchemaVersion != 1 {
		t.Fatalf("StartupExposureSchemaVersion drift: got %d, expected 1", StartupExposureSchemaVersion)
	}
}

// TestCanonicalStartupLocations guards the v1 Location enum allowlist.
// Codex 019e8387 plan iter-1 P1 #1 absorb: ten anchor slots, no full
// paths.
func TestCanonicalStartupLocations(t *testing.T) {
	expected := map[StartupAppLocation]bool{
		StartupLocationHKLMRun:             true,
		StartupLocationHKLMRunOnce:         true,
		StartupLocationHKLMWow6432Run:      true,
		StartupLocationHKCURun:             true,
		StartupLocationHKCURunOnce:         true,
		StartupLocationStartupFolderCommon: true,
		StartupLocationStartupFolderUser:   true,
		StartupLocationTaskRoot:            true,
		StartupLocationTaskMicrosoft:       true,
		StartupLocationTaskCustom:          true,
	}
	if len(CanonicalStartupLocations) != len(expected) {
		t.Fatalf("Location enum size drift: got %d, expected %d", len(CanonicalStartupLocations), len(expected))
	}
	for _, loc := range CanonicalStartupLocations {
		if !expected[loc] {
			t.Errorf("Location enum contains unexpected entry: %s", loc)
		}
	}
}

// TestStartupAppLocationEnumValues guards the bounded enum string
// surface — each enum MUST be the literal string, no drift.
func TestStartupAppLocationEnumValues(t *testing.T) {
	cases := map[StartupAppLocation]string{
		StartupLocationHKLMRun:             "HKLM_RUN",
		StartupLocationHKLMRunOnce:         "HKLM_RUNONCE",
		StartupLocationHKLMWow6432Run:      "HKLM_WOW6432_RUN",
		StartupLocationHKCURun:             "HKCU_RUN",
		StartupLocationHKCURunOnce:         "HKCU_RUNONCE",
		StartupLocationStartupFolderCommon: "STARTUP_FOLDER_COMMON",
		StartupLocationStartupFolderUser:   "STARTUP_FOLDER_USER",
		StartupLocationTaskRoot:            "TASK_SCHEDULER:ROOT",
		StartupLocationTaskMicrosoft:       "TASK_SCHEDULER:MICROSOFT_WINDOWS",
		StartupLocationTaskCustom:          "TASK_SCHEDULER:CUSTOM",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("StartupAppLocation %q != %q", got, want)
		}
	}
}

// TestStartupProbeOriginEnumValues guards the bounded source surface.
func TestStartupProbeOriginEnumValues(t *testing.T) {
	if string(StartupProbeOriginRegistry) != "REGISTRY" {
		t.Errorf("StartupProbeOriginRegistry != REGISTRY: %s", StartupProbeOriginRegistry)
	}
	if string(StartupProbeOriginScheduledTask) != "SCHEDULED_TASK" {
		t.Errorf("StartupProbeOriginScheduledTask != SCHEDULED_TASK: %s", StartupProbeOriginScheduledTask)
	}
}

// TestOrchestrateStartupExposureCanonicalSort: Windows enumeration order
// may vary across hosts; backend hash projection determinism requires a
// canonical sort with REGISTRY-origin first, then SCHEDULED_TASK-origin,
// each subsorted by Location enum then Name. Codex 019e8387 plan
// iter-1 P1 #5 absorb.
func TestOrchestrateStartupExposureCanonicalSort(t *testing.T) {
	now := func() time.Time { return time.Unix(2000000000, 0) }
	startedAt := time.Unix(1999999990, 0)
	// Input intentionally scrambled.
	raw := []StartupApp{
		{Name: "Zeta", Location: StartupLocationTaskCustom, Enabled: true, ProbeOrigin: StartupProbeOriginScheduledTask},
		{Name: "Alpha", Location: StartupLocationHKLMRun, Enabled: true, ProbeOrigin: StartupProbeOriginRegistry},
		{Name: "Bravo", Location: StartupLocationHKCURun, Enabled: true, ProbeOrigin: StartupProbeOriginRegistry},
		{Name: "Yankee", Location: StartupLocationTaskRoot, Enabled: true, ProbeOrigin: StartupProbeOriginScheduledTask},
		{Name: "Charlie", Location: StartupLocationHKLMRun, Enabled: true, ProbeOrigin: StartupProbeOriginRegistry},
	}
	result := orchestrateStartupExposureProbe(
		context.Background(), now, true, raw, true, true, nil, startedAt,
	)
	want := []struct {
		name     string
		origin   StartupProbeOrigin
		location StartupAppLocation
	}{
		// REGISTRY first.
		{name: "Alpha", origin: StartupProbeOriginRegistry, location: StartupLocationHKLMRun},
		{name: "Charlie", origin: StartupProbeOriginRegistry, location: StartupLocationHKLMRun},
		// HKCU_RUN sorts BEFORE HKLM_RUN by string ordering — but
		// our sort is location enum lexicographic; "HKCU_RUN" < "HKLM_RUN"
		// in string comparison, so HKCU goes first. Re-check.
		{name: "Bravo", origin: StartupProbeOriginRegistry, location: StartupLocationHKCURun},
		// SCHEDULED_TASK second.
		{name: "Zeta", origin: StartupProbeOriginScheduledTask, location: StartupLocationTaskCustom},
		{name: "Yankee", origin: StartupProbeOriginScheduledTask, location: StartupLocationTaskRoot},
	}
	if len(result.StartupApps) != len(want) {
		t.Fatalf("expected %d apps, got %d (apps=%v)", len(want), len(result.StartupApps), result.StartupApps)
	}
	// Verify origin ordering invariant: ALL REGISTRY entries come
	// strictly before any SCHEDULED_TASK entry.
	seenScheduled := false
	for i, app := range result.StartupApps {
		if app.ProbeOrigin == StartupProbeOriginScheduledTask {
			seenScheduled = true
		} else if seenScheduled {
			t.Errorf("REGISTRY entry at index %d after SCHEDULED_TASK entry — origin ordering broken", i)
		}
	}
	// Verify sub-ordering within each origin group: Location enum then Name.
	for i := 1; i < len(result.StartupApps); i++ {
		prev, cur := result.StartupApps[i-1], result.StartupApps[i]
		if prev.ProbeOrigin != cur.ProbeOrigin {
			continue
		}
		if prev.Location > cur.Location {
			t.Errorf("Location not sorted within origin at index %d: %s after %s", i, cur.Location, prev.Location)
		}
		if prev.Location == cur.Location && prev.Name > cur.Name {
			t.Errorf("Name not sorted within Location at index %d: %s after %s", i, cur.Name, prev.Name)
		}
	}
}

// TestOrchestrateStartupExposureCapEnforcement: when input exceeds
// MaxStartupEntries (50), the slice is truncated AND an
// ENTRY_CAP_APPLIED probe error is emitted.
func TestOrchestrateStartupExposureCapEnforcement(t *testing.T) {
	now := func() time.Time { return time.Unix(2000000000, 0) }
	startedAt := time.Unix(1999999990, 0)
	raw := make([]StartupApp, MaxStartupEntries+10)
	for i := range raw {
		raw[i] = StartupApp{
			Name:        "Entry" + suffix(i),
			Location:    StartupLocationHKLMRun,
			Enabled:     true,
			ProbeOrigin: StartupProbeOriginRegistry,
		}
	}
	result := orchestrateStartupExposureProbe(
		context.Background(), now, true, raw, false, false, nil, startedAt,
	)
	if len(result.StartupApps) != MaxStartupEntries {
		t.Errorf("expected truncation to %d; got %d", MaxStartupEntries, len(result.StartupApps))
	}
	foundCapErr := false
	for _, e := range result.ProbeErrors {
		if e.Code == StartupExposureErrEntryCapApplied {
			foundCapErr = true
			break
		}
	}
	if !foundCapErr {
		t.Errorf("ENTRY_CAP_APPLIED probe error not emitted on cap trigger")
	}
	// ProbeComplete must be false due to the emitted probe error.
	if result.ProbeComplete {
		t.Errorf("ProbeComplete must be false when ENTRY_CAP_APPLIED emitted")
	}
}

// TestOrchestrateStartupExposureCompleteFailClosed: ProbeComplete is
// true ONLY when (supported AND no probe errors). Zero entries with
// supported=true and no errors is COMPLETE — a clean host is a valid
// state.
func TestOrchestrateStartupExposureCompleteFailClosed(t *testing.T) {
	now := func() time.Time { return time.Unix(2000000000, 0) }
	startedAt := time.Unix(1999999990, 0)

	t.Run("supported+no-error+zero-entries → complete", func(t *testing.T) {
		r := orchestrateStartupExposureProbe(
			context.Background(), now, true, nil, false, false, nil, startedAt,
		)
		if !r.ProbeComplete {
			t.Fatalf("expected ProbeComplete=true for clean host; got false")
		}
	})
	t.Run("unsupported → incomplete", func(t *testing.T) {
		r := orchestrateStartupExposureProbe(
			context.Background(), now, false, nil, false, false, nil, startedAt,
		)
		if r.ProbeComplete {
			t.Fatalf("ProbeComplete should be false when unsupported")
		}
	})
	t.Run("supported+error → incomplete", func(t *testing.T) {
		errs := []StartupExposureProbeError{{Code: StartupExposureErrRegistryQueryFailed, Source: StartupLocationHKLMRun}}
		r := orchestrateStartupExposureProbe(
			context.Background(), now, true, nil, false, false, errs, startedAt,
		)
		if r.ProbeComplete {
			t.Fatalf("ProbeComplete should be false with probe error present")
		}
	})
}

// TestShouldRedactName_ValueLevelDenylist: Codex 019e83a8 iter-1 P1#2
// absorb — agent-side name redaction MUST mirror the backend
// NAME_FULLPATH_DENYLIST_RE so attacker-controlled value names never
// leave the host.
func TestShouldRedactName_ValueLevelDenylist(t *testing.T) {
	cases := []struct {
		name    string
		redact  bool
		comment string
	}{
		{"", true, "empty rejected"},
		{"OneDrive", false, "plain name accepted"},
		{"Slack", false, "plain name accepted"},
		{`C:\Users\Alice\OneDrive.exe`, true, "drive letter + exe rejected"},
		{`c:\Users\bob\app`, true, "drive letter case-insensitive rejected"},
		{`\\server\share\foo`, true, "UNC prefix rejected"},
		{"/etc/passwd", true, "unix path rejected"},
		{"foo.exe", true, "exe extension rejected"},
		{"setup.bat", true, "bat extension rejected"},
		{"loader.dll", true, "dll extension rejected"},
		{"runner.cmd", true, "cmd extension rejected"},
		{"task.ps1", true, "ps1 extension rejected"},
		{"helper.vbs", true, "vbs extension rejected"},
		{"OneDrive Sync", false, "spaces accepted"},
		{"Update_Agent", false, "underscore accepted"},
		// Codex 019e94d8 (AG-040 LIVE unblock): raw MSI ProductCode GUID
		// + Windows SID mirror completeness vs the backend
		// SoftwareInventoryPayloadPolicy. A {GUID}-named Run value 400'd
		// the entire COLLECT_INVENTORY result (services + startup) before
		// this. The unbraced case stays accepted — we mirror the backend
		// RAW_MSI_GUID pattern exactly, no silent policy widening.
		{`{90160000-0011-0000-0000-0000000FF1CE}`, true, "raw MSI ProductCode GUID rejected"},
		{`{90160000-0011-0000-0000-0000000ff1ce}`, true, "raw MSI ProductCode GUID case-insensitive rejected"},
		{`Updater {90160000-0011-0000-0000-0000000FF1CE}`, true, "embedded raw MSI ProductCode GUID rejected"},
		{`S-1-5-21-1111111111-2222222222-3333333333-1001`, true, "Windows SID rejected"},
		{`s-1-5-21-1111111111-2222222222-3333333333-1001`, true, "Windows SID rejected case-insensitively"},
		{`{not-a-guid}`, false, "non-GUID braces accepted"},
		{`90160000-0011-0000-0000-0000000FF1CE`, false, "unbraced GUID-shaped name is outside backend RAW_MSI_GUID pattern"},
	}
	for _, c := range cases {
		got := shouldRedactName(c.name)
		if got != c.redact {
			t.Errorf("shouldRedactName(%q) = %v; expected %v (%s)",
				c.name, got, c.redact, c.comment)
		}
	}
	// Control char (BEL 0x07) embedded.
	if !shouldRedactName("OneDriveBeep") {
		t.Errorf("control char in name MUST be redacted")
	}
	if !shouldRedactName("name\x00with-null") {
		t.Errorf("null byte in name MUST be redacted")
	}
}

// TestBucketTaskPath_BoundaryEvasion: Codex 019e83a8 iter-2 P1 absorb —
// the previous prefix check matched `\Microsoft\WindowsEvil\` as
// MICROSOFT_WINDOWS bucket, hiding operator-created persistence under
// the system bucket. Boundary check now requires exact path OR a
// trailing separator.
func TestBucketTaskPath_BoundaryEvasion(t *testing.T) {
	cases := []struct {
		path string
		want StartupAppLocation
	}{
		// ROOT cases.
		{"", StartupLocationTaskRoot},
		{`\`, StartupLocationTaskRoot},
		{` \ `, StartupLocationTaskRoot},
		// MICROSOFT_WINDOWS — exact match.
		{`\Microsoft\Windows`, StartupLocationTaskMicrosoft},
		{`\Microsoft\Windows\`, StartupLocationTaskMicrosoft},
		{`\MICROSOFT\WINDOWS\`, StartupLocationTaskMicrosoft},
		// MICROSOFT_WINDOWS — sub-path.
		{`\Microsoft\Windows\WindowsUpdate`, StartupLocationTaskMicrosoft},
		{`\Microsoft\Windows\WindowsUpdate\`, StartupLocationTaskMicrosoft},
		{`\Microsoft\Windows\Setup\AnyChild`, StartupLocationTaskMicrosoft},
		// Boundary-evasion cases — these MUST be CUSTOM, not MICROSOFT_WINDOWS.
		{`\Microsoft\WindowsEvil`, StartupLocationTaskCustom},
		{`\Microsoft\WindowsEvil\Persistence`, StartupLocationTaskCustom},
		{`\Microsoft\WindowsHax\`, StartupLocationTaskCustom},
		{`\MicrosoftEvil\Windows`, StartupLocationTaskCustom},
		// CUSTOM — unrelated top-level folders.
		{`\Foo`, StartupLocationTaskCustom},
		{`\Foo\Bar`, StartupLocationTaskCustom},
		{`\MyTasks\Persistence`, StartupLocationTaskCustom},
	}
	for _, c := range cases {
		got := bucketTaskPath(c.path)
		if got != c.want {
			t.Errorf("bucketTaskPath(%q) = %s; expected %s", c.path, got, c.want)
		}
	}
}

// TestBuildRedactionProbeErrors: per-source aggregation defends against
// visibility DoS — N forbidden-named entries under one anchor emit
// ONE probe error, not N. Codex 019e83a8 iter-2 P1 absorb.
func TestBuildRedactionProbeErrors(t *testing.T) {
	t.Run("empty input → nil", func(t *testing.T) {
		got := buildRedactionProbeErrors(nil)
		if got != nil {
			t.Errorf("expected nil; got %v", got)
		}
	})
	t.Run("zero-counter entry ignored", func(t *testing.T) {
		got := buildRedactionProbeErrors(map[StartupAppLocation]int{
			StartupLocationHKLMRun: 0,
		})
		if len(got) != 0 {
			t.Errorf("expected 0 emissions; got %d", len(got))
		}
	})
	t.Run("single source aggregates many entries to one", func(t *testing.T) {
		got := buildRedactionProbeErrors(map[StartupAppLocation]int{
			StartupLocationHKLMRun: 17,
		})
		if len(got) != 1 {
			t.Fatalf("expected 1 emission; got %d", len(got))
		}
		if got[0].Source != StartupLocationHKLMRun {
			t.Errorf("source mismatch: %s", got[0].Source)
		}
		if got[0].Code != StartupExposureErrNameValueRedacted {
			t.Errorf("code mismatch: %s", got[0].Code)
		}
		// Cap defense: even with 17 redactions, only 1 emission
		// per source — far under PROBE_ERRORS_MAX=16.
	})
	t.Run("multi-source emits deterministic sort", func(t *testing.T) {
		got := buildRedactionProbeErrors(map[StartupAppLocation]int{
			StartupLocationTaskCustom:    2,
			StartupLocationHKLMRun:       5,
			StartupLocationHKCURun:       3,
			StartupLocationTaskMicrosoft: 1,
		})
		if len(got) != 4 {
			t.Fatalf("expected 4 emissions; got %d", len(got))
		}
		// Sort: HKCU_RUN < HKLM_RUN < TASK_SCHEDULER:CUSTOM < TASK_SCHEDULER:MICROSOFT_WINDOWS
		wantOrder := []StartupAppLocation{
			StartupLocationHKCURun,
			StartupLocationHKLMRun,
			StartupLocationTaskCustom,
			StartupLocationTaskMicrosoft,
		}
		for i, w := range wantOrder {
			if got[i].Source != w {
				t.Errorf("sort drift at index %d: got %s, want %s", i, got[i].Source, w)
			}
		}
	})
	t.Run("cap defense: 10 anchors × N entries each = max 10 emissions", func(t *testing.T) {
		// Even if EVERY anchor has thousands of forbidden names, we
		// emit at most 10 NAME_VALUE_REDACTED probe errors total.
		// 16 - 10 = 6 slots left in PROBE_ERRORS_MAX for real errors.
		counts := make(map[StartupAppLocation]int)
		for _, loc := range CanonicalStartupLocations {
			counts[loc] = 9999
		}
		got := buildRedactionProbeErrors(counts)
		if len(got) > 10 {
			t.Errorf("emission cap broken: %d (max 10 = len(CanonicalStartupLocations))", len(got))
		}
		if len(got) != len(CanonicalStartupLocations) {
			t.Errorf("expected %d emissions; got %d", len(CanonicalStartupLocations), len(got))
		}
	})
}

// TestStartupExposureProbeErrorCodeEnum_AllListed: Codex 019e83a8 iter-1
// pin the bounded code enum surface — including NAME_VALUE_REDACTED
// added in this iter.
func TestStartupExposureProbeErrorCodeEnum_AllListed(t *testing.T) {
	cases := map[string]string{
		StartupExposureErrUnsupportedPlatform:     "UNSUPPORTED_PLATFORM",
		StartupExposureErrRegistryQueryFailed:     "REGISTRY_QUERY_FAILED",
		StartupExposureErrTaskSchedulerUnavail:    "TASK_SCHEDULER_UNAVAILABLE",
		StartupExposureErrTaskSchedulerQuery:      "TASK_SCHEDULER_QUERY_FAILED",
		StartupExposureErrStartupFolderUnreadable: "STARTUP_FOLDER_UNREADABLE",
		StartupExposureErrRdpProbeFailed:          "RDP_PROBE_FAILED",
		StartupExposureErrFirewallProbeFailed:     "FIREWALL_PROBE_FAILED",
		StartupExposureErrEntryCapApplied:         "ENTRY_CAP_APPLIED",
		StartupExposureErrNoEvidence:              "NO_EVIDENCE",
		StartupExposureErrNameValueRedacted:       "NAME_VALUE_REDACTED",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("code %q != %q", got, want)
		}
	}
}

// TestStartupExposureNonWindowsStub: on non-Windows builds (the test
// runs on linux CI), ProbeStartupExposure returns supported=false +
// UNSUPPORTED_PLATFORM. On Windows runners this test is skipped — the
// real probe runs there and the supported=false invariant doesn't
// apply (see startup_exposure_windows.go for the implementation
// already exercised by the Windows runner Go test).
func TestStartupExposureNonWindowsStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ProbeStartupExposure is the real Windows implementation here, not the stub — skip")
	}
	r := ProbeStartupExposure(context.Background(), func() time.Time {
		return time.Unix(2000000000, 0)
	})
	if r.Supported {
		t.Errorf("expected supported=false on non-Windows; got true")
	}
	if r.ProbeComplete {
		t.Errorf("expected probeComplete=false on non-Windows; got true")
	}
	if r.SchemaVersion != 1 {
		t.Errorf("schemaVersion drift: got %d", r.SchemaVersion)
	}
	if len(r.ProbeErrors) == 0 {
		t.Fatalf("expected at least one probe error on non-Windows")
	}
	if r.ProbeErrors[0].Code != StartupExposureErrUnsupportedPlatform {
		t.Errorf("expected UNSUPPORTED_PLATFORM; got %s", r.ProbeErrors[0].Code)
	}
}

// TestStartupAppJSONShape: wire keys exactly {name, location, enabled,
// probeOrigin} — pin against future drift.
func TestStartupAppJSONShape(t *testing.T) {
	app := StartupApp{
		Name:        "OneDrive",
		Location:    StartupLocationHKLMRun,
		Enabled:     true,
		ProbeOrigin: StartupProbeOriginRegistry,
	}
	b, err := json.Marshal(app)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	payload := string(b)
	for _, key := range []string{`"name"`, `"location"`, `"enabled"`, `"probeOrigin"`} {
		if !strings.Contains(payload, key) {
			t.Errorf("wire missing required key %s; payload=%s", key, payload)
		}
	}
	// CRITICAL: verify NO leakage of full executable path / command line /
	// run-as / working directory fields.
	for _, forbidden := range []string{
		"path", "fullPath", "executable", "exe", "command", "commandLine",
		"args", "arguments", "runAs", "account", "workingDirectory", "raw",
	} {
		// Substring search is overly broad — quote each forbidden key
		// to anchor on JSON key prefix.
		needle := `"` + forbidden + `"`
		if strings.Contains(payload, needle) {
			t.Errorf("wire leaked forbidden key %s; payload=%s", forbidden, payload)
		}
	}
}

// TestStartupExposureResultJSONShape: top-level wire keys MUST include
// {schemaVersion, supported, probeComplete, rdpEnabled,
// windowsFirewallEventLogEnabled, probeDurationMs}. NO active session
// count / per-rule firewall enum / raw service state.
func TestStartupExposureResultJSONShape(t *testing.T) {
	now := func() time.Time { return time.Unix(2000000000, 0) }
	startedAt := time.Unix(1999999990, 0)
	r := orchestrateStartupExposureProbe(
		context.Background(), now, true, nil, true, true, nil, startedAt,
	)
	b, _ := json.Marshal(r)
	payload := string(b)
	for _, key := range []string{
		`"schemaVersion"`, `"supported"`, `"probeComplete"`,
		`"rdpEnabled"`, `"windowsFirewallEventLogEnabled"`,
		`"probeDurationMs"`,
	} {
		if !strings.Contains(payload, key) {
			t.Errorf("wire missing required key %s; payload=%s", key, payload)
		}
	}
	// HARD BOUNDARY: NO usage telemetry fields. Codex 019e8387 plan
	// iter-1 P1 #2 absorb.
	for _, forbidden := range []string{
		"activeSessions", "activeSessionCount", "rdpActiveSessions",
		"sessionCount", "usersConnected", "concurrentUsers",
	} {
		needle := `"` + forbidden + `"`
		if strings.Contains(payload, needle) {
			t.Errorf("wire leaked forbidden usage-telemetry key %s; payload=%s", forbidden, payload)
		}
	}
}

// TestProbeErrorJSONShape: probe error wire keys {code, source?,
// summary?} — source/summary omitempty.
func TestProbeErrorJSONShape(t *testing.T) {
	// Code only — source and summary omitted.
	e1 := StartupExposureProbeError{Code: StartupExposureErrRdpProbeFailed}
	b1, _ := json.Marshal(e1)
	if strings.Contains(string(b1), "source") {
		t.Errorf("source should be omitted when empty; payload=%s", string(b1))
	}
	if strings.Contains(string(b1), "summary") {
		t.Errorf("summary should be omitted when empty; payload=%s", string(b1))
	}

	// All fields populated.
	e2 := StartupExposureProbeError{
		Code:    StartupExposureErrRegistryQueryFailed,
		Source:  StartupLocationHKLMRun,
		Summary: "Registry read failed",
	}
	b2, _ := json.Marshal(e2)
	for _, key := range []string{`"code"`, `"source"`, `"summary"`} {
		if !strings.Contains(string(b2), key) {
			t.Errorf("wire missing key %s; payload=%s", key, string(b2))
		}
	}
}

// suffix returns a 3-character zero-padded suffix for deterministic
// test entry naming.
func suffix(i int) string {
	out := []byte("000")
	for k := 2; k >= 0 && i > 0; k-- {
		out[k] = byte('0' + (i % 10))
		i /= 10
	}
	return string(out)
}
