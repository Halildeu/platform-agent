package commands

import (
	"context"
	"testing"
	"time"

	"platform-agent/internal/inventory"
	"platform-agent/internal/protocol"
)

// snapshotFromDetails extracts the inventory.Snapshot the executor
// embedded in CommandResult.Details["inventory"]. The executor stores
// the struct value (not the pointer); we type-assert so the AG-025H
// wire-shape tests can pin Snapshot.Software nilness.
func snapshotFromDetails(t *testing.T, details map[string]interface{}) inventory.Snapshot {
	t.Helper()
	raw, ok := details["inventory"]
	if !ok {
		t.Fatalf("inventory detail missing: %#v", details)
	}
	snap, ok := raw.(inventory.Snapshot)
	if !ok {
		t.Fatalf("inventory detail type = %T, want inventory.Snapshot", raw)
	}
	return snap
}

func TestLocalExecutorCollectInventory(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandCollectInventory}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-1",
		ClaimID:        "claim-1",
		AttemptNumber:  1,
		Type:           protocol.CommandCollectInventory,
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s, want %s", result.Status, protocol.CommandStatusSucceeded)
	}
	if result.Details["inventory"] == nil {
		t.Fatalf("inventory detail missing: %#v", result.Details)
	}
}

func TestLocalExecutorUnsupportedCommandReturnsUnsupported(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandCollectInventory}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-1",
		ClaimID:        "claim-1",
		AttemptNumber:  1,
		Type:           protocol.CommandDisableLocalUser,
		Reason:         "ticket",
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusUnsupported {
		t.Fatalf("status = %s, want %s", result.Status, protocol.CommandStatusUnsupported)
	}
}

// AG-025H — boolPayload mapping + COLLECT_INVENTORY wire shape (Codex
// 019e6aef post-impl iter-1 P2 / iter-2 absorb). When includeSoftware
// is absent / false / non-truthy, Snapshot.Software must stay nil
// (lightweight contract). When truthy, the executor wires the explicit
// CollectWithOptions(IncludeSoftwareApps=true) path. The boolean
// normalization must accept the documented payload typing drift
// (bool true, "true" string, "1" string, 1 int, 1.0 float64).
func TestLocalExecutorCollectInventoryDefaultOmitsSoftware(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandCollectInventory}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-default",
		ClaimID:        "claim-default",
		AttemptNumber:  1,
		Type:           protocol.CommandCollectInventory,
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s", result.Status)
	}
	snap := snapshotFromDetails(t, result.Details)
	if snap.Software != nil {
		t.Fatalf("AG-025H: default payload must keep Snapshot.Software nil (got %+v)", snap.Software)
	}
}

func TestLocalExecutorBoolPayloadAccepts(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		wantOn  bool
	}{
		{"nil-payload", nil, false},
		{"missing-key", map[string]interface{}{"unrelated": true}, false},
		{"bool-false", map[string]interface{}{"includeSoftware": false}, false},
		{"bool-true", map[string]interface{}{"includeSoftware": true}, true},
		{"string-true", map[string]interface{}{"includeSoftware": "true"}, true},
		{"string-True", map[string]interface{}{"includeSoftware": "True"}, true},
		{"string-TRUE", map[string]interface{}{"includeSoftware": "TRUE"}, true},
		{"string-1", map[string]interface{}{"includeSoftware": "1"}, true},
		{"string-false", map[string]interface{}{"includeSoftware": "false"}, false},
		{"string-0", map[string]interface{}{"includeSoftware": "0"}, false},
		{"int-1", map[string]interface{}{"includeSoftware": 1}, true},
		{"int-0", map[string]interface{}{"includeSoftware": 0}, false},
		{"float64-1", map[string]interface{}{"includeSoftware": float64(1)}, true},
		{"float64-0", map[string]interface{}{"includeSoftware": float64(0)}, false},
		{"unknown-type", map[string]interface{}{"includeSoftware": []string{"yes"}}, false},
	}
	for _, tc := range cases {
		got := boolPayload(tc.payload, "includeSoftware")
		if got != tc.wantOn {
			t.Errorf("%s: boolPayload = %v, want %v", tc.name, got, tc.wantOn)
		}
	}
}

func TestLocalExecutorListLocalUsersUnsupportedOutsideWindows(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandListLocalUsers}, "test")
	command := protocol.AgentCommand{
		CommandID:      "cmd-1",
		ClaimID:        "claim-1",
		AttemptNumber:  1,
		Type:           protocol.CommandListLocalUsers,
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	result := executor.Execute(context.Background(), command)

	if result.Status != protocol.CommandStatusUnsupported && result.Status != protocol.CommandStatusSucceeded {
		t.Fatalf("status = %s, want %s or %s", result.Status, protocol.CommandStatusUnsupported, protocol.CommandStatusSucceeded)
	}
}
