package consent

import (
	"context"
	"testing"
	"time"

	pb "platform-agent/internal/remotebridge/pb"
)

func viewOnlyPrompt(sessionID string, expiry time.Time) *pb.ConsentPrompt {
	return &pb.ConsentPrompt{
		SessionId:           sessionID,
		OperatorDisplayName: "operator@example",
		Reason:              "support",
		Capabilities:        []pb.Capability{pb.Capability_VIEW_ONLY},
		ExpiryEpochMillis:   expiry.UnixMilli(),
	}
}

func TestViewOnlyAttendedResponderGrantsOnlyAfterUserDecision(t *testing.T) {
	now := time.Unix(1000, 0)
	called := false
	responder := NewViewOnlyAttendedResponderWithPrompt(func(_ context.Context, req PromptRequest) (PromptDecision, error) {
		called = true
		if req.SessionID != "sess-1" {
			t.Fatalf("session id = %q", req.SessionID)
		}
		if req.Timeout <= 0 || req.Timeout > defaultPromptTimeout {
			t.Fatalf("timeout = %s", req.Timeout)
		}
		return PromptDecision{Granted: true, InteractiveSession: "wts-session-2"}, nil
	}, func() time.Time { return now })

	result, err := responder(context.Background(), viewOnlyPrompt("sess-1", now.Add(10*time.Minute)))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	if !called {
		t.Fatal("prompt was not called")
	}
	if result.GetSessionId() != "sess-1" || !result.GetGranted() {
		t.Fatalf("result = %+v, want granted sess-1", result)
	}
	if result.GetWindowsInteractiveSession() != "wts-session-2" {
		t.Fatalf("interactive session = %q", result.GetWindowsInteractiveSession())
	}
}

func TestViewOnlyAttendedResponderDeniesUnsupportedCapabilitiesWithoutPrompt(t *testing.T) {
	now := time.Unix(1000, 0)
	called := false
	responder := NewViewOnlyAttendedResponderWithPrompt(func(context.Context, PromptRequest) (PromptDecision, error) {
		called = true
		return PromptDecision{Granted: true}, nil
	}, func() time.Time { return now })

	prompt := viewOnlyPrompt("sess-2", now.Add(time.Minute))
	prompt.Capabilities = []pb.Capability{pb.Capability_VIEW_ONLY, pb.Capability_CONSTRAINED_PTY}
	result, err := responder(context.Background(), prompt)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	if called {
		t.Fatal("unsupported mixed capabilities must not prompt the user")
	}
	if result.GetGranted() || result.GetWindowsInteractiveSession() != "view-only-attended-consent-capability-denied" {
		t.Fatalf("result = %+v, want capability-denied", result)
	}
}

func TestViewOnlyAttendedResponderDeniesExpiredWithoutPrompt(t *testing.T) {
	now := time.Unix(1000, 0)
	called := false
	responder := NewViewOnlyAttendedResponderWithPrompt(func(context.Context, PromptRequest) (PromptDecision, error) {
		called = true
		return PromptDecision{Granted: true}, nil
	}, func() time.Time { return now })

	result, err := responder(context.Background(), viewOnlyPrompt("sess-3", now.Add(-time.Second)))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	if called {
		t.Fatal("expired prompt must not open attended consent")
	}
	if result.GetGranted() || result.GetWindowsInteractiveSession() != "view-only-attended-consent-expired" {
		t.Fatalf("result = %+v, want expired deny", result)
	}
}

func TestViewOnlyOnly(t *testing.T) {
	if !ViewOnlyOnly([]pb.Capability{pb.Capability_VIEW_ONLY}) {
		t.Fatal("single VIEW_ONLY capability should be accepted")
	}
	for name, caps := range map[string][]pb.Capability{
		"empty": nil,
		"pty":   {pb.Capability_CONSTRAINED_PTY},
		"mixed": {pb.Capability_VIEW_ONLY, pb.Capability_CONSTRAINED_PTY},
	} {
		if ViewOnlyOnly(caps) {
			t.Fatalf("%s capabilities should be rejected", name)
		}
	}
}
