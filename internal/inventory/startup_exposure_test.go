package inventory

import (
	"context"
	"encoding/json"
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
// UNSUPPORTED_PLATFORM.
func TestStartupExposureNonWindowsStub(t *testing.T) {
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
