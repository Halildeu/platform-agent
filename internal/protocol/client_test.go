package protocol

import (
	"context"
	"strings"
	"testing"
)

func TestDeriveSigningPathPrefix(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"gateway external path", "/api/v1/endpoint-agent", "/api/v1/agent"},
		{"gateway external path trailing slash", "/api/v1/endpoint-agent/", "/api/v1/agent"},
		{"gateway external path with sub-path", "/api/v1/endpoint-agent/x", "/api/v1/agent/x"},
		{"direct backend path passthrough", "/api/v1/agent", "/api/v1/agent"},
		{"unrelated path passthrough", "/custom/base", "/custom/base"},
		{"non-segment match left alone", "/foo/endpoint-agent-extra", "/foo/endpoint-agent-extra"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveSigningPathPrefix(tc.in); got != tc.want {
				t.Fatalf("DeriveSigningPathPrefix(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNewClientDerivesSigningPrefixFromGatewayPath(t *testing.T) {
	// BE-011: the agent dials /api/v1/endpoint-agent but must sign the
	// backend-visible /api/v1/agent path.
	client, err := NewClient("https://testai.example/api/v1/endpoint-agent", "", nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got := client.SigningPathPrefix(); got != "/api/v1/agent" {
		t.Fatalf("SigningPathPrefix() = %q, want /api/v1/agent", got)
	}
}

func TestNewClientHonoursExplicitSigningPrefix(t *testing.T) {
	client, err := NewClient("https://testai.example/api/v1/endpoint-agent", "/custom/agent", nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got := client.SigningPathPrefix(); got != "/custom/agent" {
		t.Fatalf("SigningPathPrefix() = %q, want /custom/agent", got)
	}
}

func TestNewClientRejectsInvalidURL(t *testing.T) {
	if _, err := NewClient("not-a-url", "", nil); err == nil {
		t.Fatal("NewClient accepted a URL with no scheme/host")
	}
}

func TestSubmitResultRejectsMissingClaimOrCommandID(t *testing.T) {
	client, err := NewClient("https://testai.example/api/v1/endpoint-agent", "", nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.SetIdentity("cred-1", "secret", "device-1")
	ctx := context.Background()

	err = client.SubmitResult(ctx, CommandResult{CommandID: "command-1", ClaimID: ""})
	if err == nil || !strings.Contains(err.Error(), "claim id") {
		t.Fatalf("SubmitResult with no claim id: err = %v, want a claim-id error", err)
	}
	err = client.SubmitResult(ctx, CommandResult{CommandID: "", ClaimID: "claim-1"})
	if err == nil || !strings.Contains(err.Error(), "command id") {
		t.Fatalf("SubmitResult with no command id: err = %v, want a command-id error", err)
	}
}

func TestSignedRequestRequiresEnrolledIdentity(t *testing.T) {
	client, err := NewClient("https://testai.example/api/v1/endpoint-agent", "", nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.IsEnrolled() {
		t.Fatal("a fresh client must not report enrolled")
	}
	// SubmitResult is signed; with no device credential it must fail fast.
	err = client.SubmitResult(context.Background(), CommandResult{CommandID: "c1", ClaimID: "claim-1"})
	if err == nil || !strings.Contains(err.Error(), "device credential") {
		t.Fatalf("signed request without identity: err = %v, want a device-credential error", err)
	}
}
