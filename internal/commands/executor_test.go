package commands

import (
	"context"
	"testing"
	"time"

	"platform-agent/internal/protocol"
)

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
