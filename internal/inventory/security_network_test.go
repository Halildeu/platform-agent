package inventory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSecurityNetworkSchemaVersionPinned(t *testing.T) {
	if SecurityNetworkSchemaVersion != 1 {
		t.Fatalf("SecurityNetworkSchemaVersion = %d, want 1", SecurityNetworkSchemaVersion)
	}
}

func TestSecurityNetworkProjectionRedactsRawIdentifiersAndKeepsStableNullKeys(t *testing.T) {
	startedAt := time.Date(2026, 6, 29, 9, 0, 0, 0, time.UTC)
	now := func() time.Time { return startedAt.Add(250 * time.Millisecond) }
	result := orchestrateSecurityNetworkProbe(
		context.Background(),
		now,
		true,
		[]rawSecurityNetworkEvent{{
			ProcessPath:        `C:\Users\Alice\AppData\Local\Temp\agent.exe`,
			DestinationAddress: "10.44.55.66",
			DestinationPort:    "443",
			Protocol:           "6",
			FilterID:           "{D0F5B6BD-5F81-4DA5-81D1-3F0760C83D83}",
			ObservedAt:         startedAt,
		}},
		nil,
		startedAt,
	)

	if !result.Supported || !result.ProbeComplete {
		t.Fatalf("expected supported+complete result, got %+v", result)
	}
	if result.SchemaVersion != SecurityNetworkSchemaVersion {
		t.Fatalf("schemaVersion = %d", result.SchemaVersion)
	}
	if result.ProbeDurationMs != 250 {
		t.Fatalf("probeDurationMs = %d, want 250", result.ProbeDurationMs)
	}
	if len(result.Events) != 1 {
		t.Fatalf("events len = %d, want 1", len(result.Events))
	}
	event := result.Events[0]
	if event.EDRVendor != SecurityNetworkVendorWindowsFirewall {
		t.Fatalf("edrVendor = %q", event.EDRVendor)
	}
	if event.BlockedProcessHashPrefix == nil || len(*event.BlockedProcessHashPrefix) != 16 {
		t.Fatalf("blockedProcessHashPrefix = %#v, want 16-char hash prefix", event.BlockedProcessHashPrefix)
	}
	if event.BlockedDestination == nil || !strings.HasPrefix(*event.BlockedDestination, "dest-sha256-") {
		t.Fatalf("blockedDestination = %#v, want redacted dest-sha256 token", event.BlockedDestination)
	}
	if event.FirewallRuleID == nil || !strings.HasPrefix(*event.FirewallRuleID, "wfp-filter-") {
		t.Fatalf("firewallRuleId = %#v, want redacted wfp-filter token", event.FirewallRuleID)
	}

	body, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	wire := string(body)
	for _, raw := range []string{"Alice", `C:\Users`, "10.44.55.66", "443", "D0F5B6BD"} {
		if strings.Contains(wire, raw) {
			t.Fatalf("securityNetwork payload leaked raw identifier %q: %s", raw, wire)
		}
	}
	for _, want := range []string{
		`"networkSegmentId":null`,
		`"lastSuccessfulContactAt":null`,
		`"probeErrors":[]`,
	} {
		if !strings.Contains(wire, want) {
			t.Fatalf("securityNetwork payload missing stable key %s: %s", want, wire)
		}
	}
}

func TestSecurityNetworkEventCapAddsTruncationProbeError(t *testing.T) {
	startedAt := time.Date(2026, 6, 29, 9, 0, 0, 0, time.UTC)
	rawEvents := make([]rawSecurityNetworkEvent, 0, MaxSecurityNetworkEvents+5)
	for i := 0; i < MaxSecurityNetworkEvents+5; i++ {
		rawEvents = append(rawEvents, rawSecurityNetworkEvent{
			ProcessPath:        `C:\Program Files\EndpointAgent\agent.exe`,
			DestinationAddress: "203.0.113.10",
			DestinationPort:    "443",
			Protocol:           "6",
			FilterID:           "filter-id",
			ObservedAt:         startedAt.Add(time.Duration(i) * time.Second),
		})
	}

	result := orchestrateSecurityNetworkProbe(
		context.Background(),
		func() time.Time { return startedAt.Add(time.Second) },
		true,
		rawEvents,
		nil,
		startedAt,
	)

	if len(result.Events) != MaxSecurityNetworkEvents {
		t.Fatalf("events len = %d, want cap %d", len(result.Events), MaxSecurityNetworkEvents)
	}
	if !hasProbeErrorCode(result.ProbeErrors, SecurityNetworkErrEventsTruncated) {
		t.Fatalf("probeErrors missing EVENTS_TRUNCATED sentinel: %+v", result.ProbeErrors)
	}
	if !result.ProbeComplete {
		t.Fatalf("EVENTS_TRUNCATED must not make the probe decision-critical incomplete")
	}
}

func TestSecurityNetworkEventCapPreservesTruncationSentinelWhenProbeErrorsFull(t *testing.T) {
	startedAt := time.Date(2026, 6, 29, 9, 0, 0, 0, time.UTC)
	rawEvents := make([]rawSecurityNetworkEvent, 0, MaxSecurityNetworkEvents+1)
	for i := 0; i < MaxSecurityNetworkEvents+1; i++ {
		rawEvents = append(rawEvents, rawSecurityNetworkEvent{
			ProcessPath:        `C:\Program Files\EndpointAgent\agent.exe`,
			DestinationAddress: "203.0.113.10",
			DestinationPort:    "443",
			Protocol:           "6",
			FilterID:           "filter-id",
			ObservedAt:         startedAt.Add(time.Duration(i) * time.Second),
		})
	}
	rawErrors := make([]SecurityNetworkProbeError, 0, MaxSecurityNetworkProbeErrors)
	for i := 0; i < MaxSecurityNetworkProbeErrors; i++ {
		rawErrors = append(rawErrors, SecurityNetworkProbeError{
			Code:    SecurityNetworkErrNoEvidence,
			Summary: securityNetworkSummaryPtr("non-critical placeholder"),
		})
	}

	result := orchestrateSecurityNetworkProbe(
		context.Background(),
		func() time.Time { return startedAt.Add(time.Second) },
		true,
		rawEvents,
		rawErrors,
		startedAt,
	)

	if len(result.ProbeErrors) != MaxSecurityNetworkProbeErrors {
		t.Fatalf("probeErrors len = %d, want cap %d", len(result.ProbeErrors), MaxSecurityNetworkProbeErrors)
	}
	if !hasProbeErrorCode(result.ProbeErrors, SecurityNetworkErrEventsTruncated) {
		t.Fatalf("probeErrors full cap dropped EVENTS_TRUNCATED sentinel: %+v", result.ProbeErrors)
	}
}

func TestSecurityNetworkDecisionCriticalErrorsMarkProbeIncomplete(t *testing.T) {
	startedAt := time.Date(2026, 6, 29, 9, 0, 0, 0, time.UTC)
	result := orchestrateSecurityNetworkProbe(
		context.Background(),
		func() time.Time { return startedAt.Add(time.Second) },
		true,
		nil,
		[]SecurityNetworkProbeError{{
			Code:    SecurityNetworkErrAccessDenied,
			Summary: securityNetworkSummaryPtr("security event log access denied"),
		}},
		startedAt,
	)

	if result.ProbeComplete {
		t.Fatalf("ACCESS_DENIED must make probeComplete=false: %+v", result)
	}
	if len(result.Events) != 0 {
		t.Fatalf("events len = %d, want 0", len(result.Events))
	}
	if len(result.ProbeErrors) != 1 {
		t.Fatalf("probeErrors len = %d, want 1", len(result.ProbeErrors))
	}
}

func TestSecurityNetworkUnsupportedShapeIsExplicit(t *testing.T) {
	startedAt := time.Date(2026, 6, 29, 9, 0, 0, 0, time.UTC)
	result := orchestrateSecurityNetworkProbe(
		context.Background(),
		func() time.Time { return startedAt.Add(time.Second) },
		false,
		nil,
		[]SecurityNetworkProbeError{{
			Code:    SecurityNetworkErrUnsupportedPlatform,
			Summary: securityNetworkSummaryPtr("Security/network probe requires Windows"),
		}},
		startedAt,
	)

	if result.Supported {
		t.Fatalf("supported = true, want false")
	}
	if result.ProbeComplete {
		t.Fatalf("unsupported platform must be probeComplete=false")
	}
	if len(result.Events) != 0 {
		t.Fatalf("events len = %d, want 0", len(result.Events))
	}
	if !hasProbeErrorCode(result.ProbeErrors, SecurityNetworkErrUnsupportedPlatform) {
		t.Fatalf("probeErrors missing UNSUPPORTED_PLATFORM: %+v", result.ProbeErrors)
	}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	wire := string(body)
	if !strings.Contains(wire, `"events":[]`) || !strings.Contains(wire, `"probeErrors":[`) {
		t.Fatalf("unsupported shape must carry explicit empty events and typed errors: %s", wire)
	}
}

func hasProbeErrorCode(errors []SecurityNetworkProbeError, code string) bool {
	for _, err := range errors {
		if err.Code == code {
			return true
		}
	}
	return false
}
