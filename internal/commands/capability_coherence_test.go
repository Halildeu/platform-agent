package commands

import (
	"context"
	"testing"
	"time"

	"platform-agent/internal/inventory"
	"platform-agent/internal/protocol"
)

// TestRuntimeCapabilitiesAllDispatchable is the AG-013 regression guard.
//
// Every command reported by inventory.RuntimeCapabilities() must have an
// explicit case in LocalExecutor.Execute()'s switch. If a capability is
// advertised but the switch hits its default arm, the agent does false
// advertising: the backend dispatches the command, the executor returns
// UNSUPPORTED, audit shows "agent fail" while the real cause is the missing
// executor case.
//
// Note: adapter-side failures (e.g. macOS/Linux returning
// ErrLocalUserListingUnsupported for LIST_LOCAL_USERS) also produce
// CommandStatusUnsupported, which is legitimate platform behaviour and not
// what this test guards. We distinguish the two by checking the executor's
// default-arm summary string verbatim.
func TestRuntimeCapabilitiesAllDispatchable(t *testing.T) {
	caps := inventory.RuntimeCapabilities()
	if len(caps) == 0 {
		t.Fatal("RuntimeCapabilities returned empty list")
	}
	executor := NewLocalExecutor(caps, "test")
	ctx := context.Background()
	const executorDefaultSummary = "Command is not implemented by this agent build"
	for _, cmd := range caps {
		c := protocol.AgentCommand{
			CommandID:      "test-" + string(cmd),
			ClaimID:        "test-claim",
			AttemptNumber:  1,
			Type:           cmd,
			ClaimExpiresAt: time.Now().Add(time.Minute),
		}
		if cmd.RequiresReason() {
			c.Reason = "regression-test"
		}
		result := executor.Execute(ctx, c)
		if result.Status == protocol.CommandStatusUnsupported && result.Summary == executorDefaultSummary {
			t.Errorf("capability %q reported but executor switch has no case (false advertising); summary=%q", cmd, result.Summary)
		}
	}
}
