package commands

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"platform-agent/internal/protocol"
)

var (
	ErrUnsupportedCommand = errors.New("unsupported command")
	ErrMissingReason      = errors.New("missing reason")
	ErrExpiredClaim       = errors.New("expired command claim")
	ErrInvalidClaim       = errors.New("invalid command claim")
)

func Validate(command protocol.AgentCommand, capabilities []protocol.CommandType, now time.Time) error {
	if strings.TrimSpace(command.CommandID) == "" || strings.TrimSpace(command.ClaimID) == "" || command.AttemptNumber < 1 {
		return ErrInvalidClaim
	}
	if !command.ClaimExpiresAt.IsZero() && now.After(command.ClaimExpiresAt) {
		return ErrExpiredClaim
	}
	if !hasCapability(capabilities, command.Type) {
		return fmt.Errorf("%w: %s", ErrUnsupportedCommand, command.Type)
	}
	if command.Type.RequiresReason() && strings.TrimSpace(command.Reason) == "" {
		return fmt.Errorf("%w: %s", ErrMissingReason, command.Type)
	}
	return nil
}

func hasCapability(capabilities []protocol.CommandType, target protocol.CommandType) bool {
	for _, capability := range capabilities {
		if capability == target {
			return true
		}
	}
	return false
}

func withoutCapability(capabilities []protocol.CommandType, target protocol.CommandType) []protocol.CommandType {
	filtered := capabilities[:0]
	for _, capability := range capabilities {
		if capability != target {
			filtered = append(filtered, capability)
		}
	}
	return filtered
}
