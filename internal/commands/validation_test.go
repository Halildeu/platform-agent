package commands

import (
	"errors"
	"testing"
	"time"

	"platform-agent/internal/protocol"
)

func TestValidateRequiresCapability(t *testing.T) {
	command := protocol.AgentCommand{
		CommandID:      "cmd-1",
		ClaimID:        "claim-1",
		AttemptNumber:  1,
		Type:           protocol.CommandDisableLocalUser,
		Reason:         "ticket",
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	err := Validate(command, []protocol.CommandType{protocol.CommandCollectInventory}, time.Now())
	if !errors.Is(err, ErrUnsupportedCommand) {
		t.Fatalf("err = %v, want ErrUnsupportedCommand", err)
	}
}

func TestValidateRequiresReasonForSensitiveCommands(t *testing.T) {
	command := protocol.AgentCommand{
		CommandID:      "cmd-1",
		ClaimID:        "claim-1",
		AttemptNumber:  1,
		Type:           protocol.CommandDisableLocalUser,
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	err := Validate(command, []protocol.CommandType{protocol.CommandDisableLocalUser}, time.Now())
	if !errors.Is(err, ErrMissingReason) {
		t.Fatalf("err = %v, want ErrMissingReason", err)
	}
}

func TestValidateRequiresReasonForUpdateAgent(t *testing.T) {
	command := protocol.AgentCommand{
		CommandID:      "cmd-update",
		ClaimID:        "claim-update",
		AttemptNumber:  1,
		Type:           protocol.CommandUpdateAgent,
		ClaimExpiresAt: time.Now().Add(time.Minute),
	}

	err := Validate(command, []protocol.CommandType{protocol.CommandUpdateAgent}, time.Now())
	if !errors.Is(err, ErrMissingReason) {
		t.Fatalf("err = %v, want ErrMissingReason", err)
	}
}
