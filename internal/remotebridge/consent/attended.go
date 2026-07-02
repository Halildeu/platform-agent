package consent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	pb "platform-agent/internal/remotebridge/pb"
)

const (
	defaultPromptTimeout = 2 * time.Minute
	defaultLeaseDuration = 5 * time.Minute
)

// PromptRequest is the endpoint-local, user-facing consent request.
// It intentionally carries no raw broker credential or permit material.
type PromptRequest struct {
	SessionID           string
	OperatorDisplayName string
	Reason              string
	ExpiresAt           time.Time
	Timeout             time.Duration
}

type PromptDecision struct {
	Granted            bool
	InteractiveSession string
}

type UserPromptFunc func(ctx context.Context, req PromptRequest) (PromptDecision, error)

// NewViewOnlyAttendedResponder returns a fail-closed attended consent responder
// for VIEW_ONLY-only prompts. On Windows it uses the active interactive session;
// on other platforms the default prompt implementation returns granted=false.
func NewViewOnlyAttendedResponder() func(context.Context, *pb.ConsentPrompt) (*pb.ConsentResult, error) {
	return NewViewOnlyAttendedResponderWithPrompt(defaultViewOnlyUserPrompt, time.Now)
}

func NewViewOnlyAttendedResponderWithPrompt(prompt UserPromptFunc, now func() time.Time) func(context.Context, *pb.ConsentPrompt) (*pb.ConsentResult, error) {
	if prompt == nil {
		prompt = defaultViewOnlyUserPrompt
	}
	if now == nil {
		now = time.Now
	}
	return func(ctx context.Context, cp *pb.ConsentPrompt) (*pb.ConsentResult, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if cp == nil || strings.TrimSpace(cp.GetSessionId()) == "" {
			return nil, errors.New("remote-bridge view-only attended consent requires a session id")
		}
		current := now()
		expiresAt := consentExpiry(cp, current)
		if !ViewOnlyOnly(cp.GetCapabilities()) {
			return consentResult(cp, false, "view-only-attended-consent-capability-denied", current, expiresAt), nil
		}
		if !expiresAt.After(current) {
			return consentResult(cp, false, "view-only-attended-consent-expired", current, expiresAt), nil
		}
		timeout := expiresAt.Sub(current)
		if timeout > defaultPromptTimeout {
			timeout = defaultPromptTimeout
		}
		if timeout < time.Second {
			timeout = time.Second
		}
		decision, err := prompt(ctx, PromptRequest{
			SessionID:           cp.GetSessionId(),
			OperatorDisplayName: cp.GetOperatorDisplayName(),
			Reason:              cp.GetReason(),
			ExpiresAt:           expiresAt,
			Timeout:             timeout,
		})
		if err != nil {
			return nil, err
		}
		finished := now()
		granted := decision.Granted && expiresAt.After(finished)
		session := strings.TrimSpace(decision.InteractiveSession)
		if session == "" {
			if granted {
				session = "attended-view-only-consent"
			} else {
				session = "attended-view-only-consent-denied"
			}
		}
		if decision.Granted && !granted {
			session = "view-only-attended-consent-expired-after-prompt"
		}
		return consentResult(cp, granted, session, finished, expiresAt), nil
	}
}

func ViewOnlyOnly(caps []pb.Capability) bool {
	if len(caps) == 0 {
		return false
	}
	for _, cap := range caps {
		if cap != pb.Capability_VIEW_ONLY {
			return false
		}
	}
	return true
}

func consentExpiry(cp *pb.ConsentPrompt, now time.Time) time.Time {
	if expiry := cp.GetExpiryEpochMillis(); expiry > 0 {
		return time.UnixMilli(expiry)
	}
	return now.Add(defaultLeaseDuration)
}

func consentResult(cp *pb.ConsentPrompt, granted bool, interactiveSession string, now time.Time, expiresAt time.Time) *pb.ConsentResult {
	return &pb.ConsentResult{
		SessionId:                 cp.GetSessionId(),
		Granted:                   granted,
		WindowsInteractiveSession: interactiveSession,
		GrantedAtEpochMillis:      now.UnixMilli(),
		ExpiryEpochMillis:         expiresAt.UnixMilli(),
	}
}

func promptMessage(req PromptRequest) string {
	operator := strings.TrimSpace(req.OperatorDisplayName)
	if operator == "" {
		operator = "unknown operator"
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "remote support"
	}
	return fmt.Sprintf(
		"Endpoint Agent VIEW_ONLY request\n\nOperator: %s\nReason: %s\nSession: %s\nExpires: %s\n\nApprove only if you are present and allow screen observation for this session. This does not grant keyboard or mouse control.",
		operator,
		reason,
		req.SessionID,
		req.ExpiresAt.Format(time.RFC3339),
	)
}
