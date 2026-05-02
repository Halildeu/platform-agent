package commands

import (
	"context"
	"errors"
	"time"

	"platform-agent/internal/inventory"
	"platform-agent/internal/protocol"
	"platform-agent/internal/users"
)

type LocalExecutor struct {
	Capabilities []protocol.CommandType
	AgentVersion string
	Now          func() time.Time
}

func NewLocalExecutor(capabilities []protocol.CommandType, agentVersion string) *LocalExecutor {
	return &LocalExecutor{
		Capabilities: capabilities,
		AgentVersion: agentVersion,
		Now:          time.Now,
	}
}

func (e *LocalExecutor) Execute(ctx context.Context, command protocol.AgentCommand) protocol.CommandResult {
	now := e.now()
	result := protocol.CommandResult{
		CommandID:     command.CommandID,
		ClaimID:       command.ClaimID,
		AttemptNumber: command.AttemptNumber,
		Status:        protocol.CommandStatusRunning,
		StartedAt:     now,
		FinishedAt:    now,
	}

	if err := Validate(command, e.Capabilities, now); err != nil {
		return withValidationError(result, err, e.now())
	}

	select {
	case <-ctx.Done():
		result.Status = protocol.CommandStatusFailed
		result.Summary = ctx.Err().Error()
		result.FinishedAt = e.now()
		return result
	default:
	}

	switch command.Type {
	case protocol.CommandCollectInventory:
		snapshot := inventory.Collect(e.AgentVersion, e.now())
		result.Status = protocol.CommandStatusSucceeded
		result.Summary = "Inventory collected"
		result.Details = map[string]interface{}{"inventory": snapshot}
	case protocol.CommandListLocalUsers:
		localUsers, err := users.ListLocal()
		if err != nil {
			if errors.Is(err, users.ErrLocalUserListingUnsupported) {
				result.Status = protocol.CommandStatusUnsupported
			} else {
				result.Status = protocol.CommandStatusFailed
			}
			result.Summary = err.Error()
			break
		}
		result.Status = protocol.CommandStatusSucceeded
		result.Summary = "Local users listed"
		result.Details = map[string]interface{}{"users": localUsers}
	case protocol.CommandGetLoggedInUser:
		current, err := users.Current()
		if err != nil {
			result.Status = protocol.CommandStatusFailed
			result.Summary = err.Error()
			break
		}
		result.Status = protocol.CommandStatusSucceeded
		result.Summary = "Logged-in user resolved"
		result.Details = map[string]interface{}{"user": current}
	case protocol.CommandGetUserHomePaths:
		paths, err := users.CurrentHomePaths()
		if err != nil {
			result.Status = protocol.CommandStatusFailed
			result.Summary = err.Error()
			break
		}
		result.Status = protocol.CommandStatusSucceeded
		result.Summary = "User home paths resolved"
		result.Details = map[string]interface{}{"paths": paths}
	default:
		result.Status = protocol.CommandStatusUnsupported
		result.Summary = "Command is not implemented by this agent build"
	}
	result.FinishedAt = e.now()
	return result
}

func (e *LocalExecutor) now() time.Time {
	if e.Now == nil {
		return time.Now()
	}
	return e.Now()
}

func withValidationError(r protocol.CommandResult, err error, finishedAt time.Time) protocol.CommandResult {
	switch {
	case errors.Is(err, ErrUnsupportedCommand):
		r.Status = protocol.CommandStatusUnsupported
	case errors.Is(err, ErrExpiredClaim):
		r.Status = protocol.CommandStatusExpired
	default:
		r.Status = protocol.CommandStatusFailed
	}
	r.Summary = err.Error()
	r.FinishedAt = finishedAt
	return r
}
