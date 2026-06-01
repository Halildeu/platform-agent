package inventory

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestServicesSchemaVersionPinned guards the wire contract: schemaVersion=1
// is fixed in v1; bumping requires explicit contract migration.
func TestServicesSchemaVersionPinned(t *testing.T) {
	if ServicesSchemaVersion != 1 {
		t.Fatalf("ServicesSchemaVersion drift: got %d, expected 1", ServicesSchemaVersion)
	}
}

// TestCanonicalServiceAllowlist guards the v1 allowlist. Codex 019e8302
// iter-2 #1 absorb: TermService is NOT in v1 (AG-040 scope).
func TestCanonicalServiceAllowlist(t *testing.T) {
	expected := map[string]bool{
		"WinDefend":     true,
		"wuauserv":      true,
		"BITS":          true,
		"EventLog":      true,
		"EndpointAgent": true,
		"MpsSvc":        true,
	}
	if len(CanonicalServiceAllowlist) != len(expected) {
		t.Fatalf("allowlist size drift: got %d, expected %d", len(CanonicalServiceAllowlist), len(expected))
	}
	for _, name := range CanonicalServiceAllowlist {
		if !expected[name] {
			t.Errorf("allowlist contains unexpected service: %s", name)
		}
	}
	// TermService explicit exclusion (AG-040 boundary).
	for _, name := range CanonicalServiceAllowlist {
		if name == "TermService" {
			t.Errorf("TermService leaked into v1 allowlist (AG-040 boundary breach)")
		}
	}
}

// TestServiceStateEnumValues guards bounded enum surface.
func TestServiceStateEnumValues(t *testing.T) {
	cases := map[ServiceState]string{
		ServiceStateRunning:  "RUNNING",
		ServiceStateStopped:  "STOPPED",
		ServiceStateDisabled: "DISABLED",
		ServiceStateUnknown:  "UNKNOWN",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("ServiceState %q != %q", got, want)
		}
	}
}

// TestStartupModeEnumValues guards bounded enum surface — AUTO_DELAYED
// must be DISTINCT from AUTO (Codex 019e8302 iter-2 #3 absorb).
func TestStartupModeEnumValues(t *testing.T) {
	cases := map[StartupMode]string{
		StartupModeAuto:        "AUTO",
		StartupModeAutoDelayed: "AUTO_DELAYED",
		StartupModeManual:      "MANUAL",
		StartupModeDisabled:    "DISABLED",
		StartupModeUnknown:     "UNKNOWN",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("StartupMode %q != %q", got, want)
		}
	}
	if StartupModeAuto == StartupModeAutoDelayed {
		t.Fatal("AUTO and AUTO_DELAYED collapsed — visibility regression")
	}
}

// TestOrchestrateServicesProbeCanonicalSort: SCM enumeration order may
// vary across Windows builds; backend hash projection determinism
// requires a canonical sort (Codex 019e8302 iter-2 #6 absorb).
func TestOrchestrateServicesProbeCanonicalSort(t *testing.T) {
	now := func() time.Time { return time.Unix(2000000000, 0) }
	startedAt := time.Unix(1999999990, 0)
	// Input intentionally out of alphabetic order.
	raw := []ServiceEntry{
		{Name: "wuauserv", Present: true, State: ServiceStateRunning, StartupMode: StartupModeAuto},
		{Name: "BITS", Present: true, State: ServiceStateStopped, StartupMode: StartupModeManual},
		{Name: "EndpointAgent", Present: true, State: ServiceStateRunning, StartupMode: StartupModeAutoDelayed},
		{Name: "WinDefend", Present: true, State: ServiceStateRunning, StartupMode: StartupModeAuto},
		{Name: "MpsSvc", Present: true, State: ServiceStateRunning, StartupMode: StartupModeAuto},
		{Name: "EventLog", Present: true, State: ServiceStateRunning, StartupMode: StartupModeAuto},
	}
	result := orchestrateServicesProbe(context.Background(), now, true, raw, nil, startedAt)
	want := []string{"BITS", "EndpointAgent", "EventLog", "MpsSvc", "WinDefend", "wuauserv"}
	if len(result.Services) != len(want) {
		t.Fatalf("expected %d services, got %d", len(want), len(result.Services))
	}
	for i, n := range want {
		if result.Services[i].Name != n {
			t.Errorf("services[%d] = %s; expected %s", i, result.Services[i].Name, n)
		}
	}
}

// TestOrchestrateServicesProbeCompleteFailClosed: ProbeComplete is true
// ONLY when supported AND zero errors AND services list has the full
// allowlist length.
func TestOrchestrateServicesProbeCompleteFailClosed(t *testing.T) {
	now := func() time.Time { return time.Unix(2000000000, 0) }
	startedAt := time.Unix(1999999990, 0)

	t.Run("supported+full+no-error → complete", func(t *testing.T) {
		raw := fullAllowlistEntries(t)
		r := orchestrateServicesProbe(context.Background(), now, true, raw, nil, startedAt)
		if !r.ProbeComplete {
			t.Fatalf("expected ProbeComplete=true; got false")
		}
	})
	t.Run("unsupported → incomplete", func(t *testing.T) {
		r := orchestrateServicesProbe(context.Background(), now, false, nil, nil, startedAt)
		if r.ProbeComplete {
			t.Fatalf("ProbeComplete should be false when unsupported")
		}
	})
	t.Run("supported+full+error → incomplete", func(t *testing.T) {
		raw := fullAllowlistEntries(t)
		errs := []ServicesProbeError{{Code: ServicesErrServiceQueryFailed, ServiceName: "BITS"}}
		r := orchestrateServicesProbe(context.Background(), now, true, raw, errs, startedAt)
		if r.ProbeComplete {
			t.Fatalf("ProbeComplete should be false with probe error present")
		}
	})
	t.Run("supported+partial-list → incomplete", func(t *testing.T) {
		partial := []ServiceEntry{{Name: "BITS", Present: true, State: ServiceStateRunning, StartupMode: StartupModeManual}}
		r := orchestrateServicesProbe(context.Background(), now, true, partial, nil, startedAt)
		if r.ProbeComplete {
			t.Fatalf("ProbeComplete should be false when services list shorter than allowlist")
		}
	})
}

// TestProbeErrorsJSONOmitemptyShape: wire compact representation —
// probeErrors absent when empty (omitempty), present array when non-empty.
func TestProbeErrorsJSONOmitemptyShape(t *testing.T) {
	now := func() time.Time { return time.Unix(2000000000, 0) }
	startedAt := time.Unix(1999999990, 0)
	full := fullAllowlistEntries(t)
	r := orchestrateServicesProbe(context.Background(), now, true, full, nil, startedAt)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if contains(b, "probeErrors") {
		t.Errorf("probeErrors should be omitted when empty; payload=%s", string(b))
	}
	if !contains(b, `"schemaVersion":1`) {
		t.Errorf("schemaVersion not pinned in wire; payload=%s", string(b))
	}
}

// TestProbeErrorShapeServiceNameOmitempty: serviceName is allowlist-only;
// when absent the field is omitted.
func TestProbeErrorShapeServiceNameOmitempty(t *testing.T) {
	e := ServicesProbeError{Code: ServicesErrSCMUnavailable, Summary: "SCM down"}
	b, _ := json.Marshal(e)
	if contains(b, "serviceName") {
		t.Errorf("serviceName should be omitted when empty; payload=%s", string(b))
	}
}

// TestProbeErrorShapeServiceNamePresent: emitted when set.
func TestProbeErrorShapeServiceNamePresent(t *testing.T) {
	e := ServicesProbeError{Code: ServicesErrServiceQueryFailed, ServiceName: "BITS"}
	b, _ := json.Marshal(e)
	if !contains(b, `"serviceName":"BITS"`) {
		t.Errorf("serviceName missing from wire; payload=%s", string(b))
	}
}

// TestServiceEntryFullShape: wire keys exactly {name, present, state,
// startupMode}.
func TestServiceEntryFullShape(t *testing.T) {
	e := ServiceEntry{
		Name: "BITS", Present: true,
		State: ServiceStateRunning, StartupMode: StartupModeAutoDelayed,
	}
	b, _ := json.Marshal(e)
	for _, key := range []string{"name", "present", "state", "startupMode"} {
		if !contains(b, key) {
			t.Errorf("wire missing key %s; payload=%s", key, string(b))
		}
	}
	// Verify no leakage of other fields.
	for _, forbidden := range []string{"description", "commandLine", "account", "displayName", "raw"} {
		if contains(b, forbidden) {
			t.Errorf("wire leaked forbidden key %s; payload=%s", forbidden, string(b))
		}
	}
}

// TestProbeResultJSONKeysCanonical: top-level wire keys exactly the
// expected set; pin against future drift.
func TestProbeResultJSONKeysCanonical(t *testing.T) {
	now := func() time.Time { return time.Unix(2000000000, 0) }
	startedAt := time.Unix(1999999990, 0)
	full := fullAllowlistEntries(t)
	r := orchestrateServicesProbe(context.Background(), now, true, full, nil, startedAt)
	b, _ := json.Marshal(r)
	for _, key := range []string{"schemaVersion", "supported", "probeComplete", "services", "probeDurationMs"} {
		if !contains(b, key) {
			t.Errorf("wire missing required key %s; payload=%s", key, string(b))
		}
	}
}

// Helpers.

func fullAllowlistEntries(t *testing.T) []ServiceEntry {
	t.Helper()
	out := make([]ServiceEntry, 0, len(CanonicalServiceAllowlist))
	for _, n := range CanonicalServiceAllowlist {
		out = append(out, ServiceEntry{
			Name: n, Present: true,
			State: ServiceStateRunning, StartupMode: StartupModeAuto,
		})
	}
	return out
}

func contains(haystack []byte, needle string) bool {
	if len(needle) == 0 {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
