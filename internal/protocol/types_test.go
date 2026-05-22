package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestToWireStatusMapping(t *testing.T) {
	cases := []struct {
		in        CommandStatus
		want      string
		wantError bool
	}{
		{CommandStatusSucceeded, "SUCCEEDED", false},
		{CommandStatusFailed, "FAILED", false},
		{CommandStatusUnsupported, "UNSUPPORTED", false},
		{CommandStatusExpired, "FAILED", true},  // backend has no EXPIRED
		{CommandStatusRunning, "FAILED", false}, // non-terminal → defensive FAILED
	}
	for _, tc := range cases {
		t.Run(string(tc.in), func(t *testing.T) {
			wire := CommandResult{Status: tc.in, ClaimID: "claim-1"}.ToWire()
			if wire.Status != tc.want {
				t.Fatalf("ToWire(%s).Status = %q, want %q", tc.in, wire.Status, tc.want)
			}
			if tc.wantError && wire.ErrorCode == "" {
				t.Fatalf("ToWire(%s) should set an errorCode", tc.in)
			}
		})
	}
}

func TestToWireExpiredCarriesErrorContext(t *testing.T) {
	wire := CommandResult{Status: CommandStatusExpired, ClaimID: "claim-1"}.ToWire()
	if wire.Status != "FAILED" {
		t.Fatalf("expired status = %q, want FAILED", wire.Status)
	}
	if wire.ErrorCode != "COMMAND_EXPIRED" {
		t.Fatalf("expired errorCode = %q, want COMMAND_EXPIRED", wire.ErrorCode)
	}
	if strings.TrimSpace(wire.ErrorMessage) == "" {
		t.Fatal("expired result must carry an errorMessage")
	}
}

func TestToWirePassesThroughClaimAndTimestamps(t *testing.T) {
	started := time.Date(2026, 5, 22, 13, 0, 0, 0, time.UTC)
	finished := started.Add(2 * time.Second)
	result := CommandResult{
		CommandID:     "command-1",
		ClaimID:       "claim-9",
		AttemptNumber: 3,
		Status:        CommandStatusSucceeded,
		Summary:       "ok",
		Details:       map[string]interface{}{"count": 2},
		StartedAt:     started,
		FinishedAt:    finished,
	}
	wire := result.ToWire()
	if wire.ClaimID != "claim-9" || wire.AttemptNumber != 3 || wire.Summary != "ok" {
		t.Fatalf("ToWire did not pass through claim fields: %#v", wire)
	}
	if !wire.StartedAt.Equal(started) || !wire.FinishedAt.Equal(finished) {
		t.Fatalf("ToWire did not pass through timestamps: %#v", wire)
	}
}

func TestCommandResultWireOmitsCommandID(t *testing.T) {
	// commandId is the {commandId} URL path segment, never a body field.
	encoded, err := json.Marshal(CommandResult{
		CommandID: "command-1", ClaimID: "claim-1", Status: CommandStatusSucceeded,
	}.ToWire())
	if err != nil {
		t.Fatalf("marshal wire: %v", err)
	}
	if strings.Contains(string(encoded), "commandId") {
		t.Fatalf("command-result wire body must not contain commandId: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"claimId"`) {
		t.Fatalf("command-result wire body must contain claimId: %s", encoded)
	}
}
