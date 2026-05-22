package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/config"
	"platform-agent/internal/protocol"
	"platform-agent/internal/security"
)

// TestRunnerRunOnceFullLifecycle drives enroll → heartbeat → command poll →
// command result against a stub server that enforces the BE-011 backend
// contract: the /enrollments/consume enroll path, the X-Device-Credential-*
// HMAC headers, and an X-Signature computed over the backend-visible
// (gateway-rewritten) /api/v1/agent canonical path. A regression to the old
// /enroll path or X-Agent-* headers fails this test.
func TestRunnerRunOnceFullLifecycle(t *testing.T) {
	const deviceSecret = "device-hmac-secret"
	var enrollSeen, heartbeatSeen, pollSeen, resultSeen bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/endpoint-agent/enrollments/consume":
			if sig := r.Header.Get("X-Signature"); sig != "" {
				t.Fatalf("enrollment must be unsigned, got X-Signature=%q", sig)
			}
			var req protocol.EnrollRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode enroll request: %v", err)
			}
			if req.EnrollmentToken == "" || req.Hostname == "" || req.OsType == "" ||
				req.MachineFingerprint == "" || req.AgentVersion == "" {
				t.Fatalf("enroll request missing backend-required fields: %#v", req)
			}
			enrollSeen = true
			writeJSON(t, w, protocol.EnrollResponse{
				DeviceID:        "device-1",
				CredentialKeyID: "cred-1",
				Secret:          deviceSecret,
				HmacAlgorithm:   "hmac-sha256",
				ServerTime:      time.Now().UTC(),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/endpoint-agent/heartbeat":
			requireValidSignature(t, r, deviceSecret)
			heartbeatSeen = true
			writeJSON(t, w, protocol.HeartbeatResponse{
				Accepted: true, DeviceID: "device-1", Status: "ACTIVE", ServerTime: time.Now().UTC(),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/endpoint-agent/commands/next":
			requireValidSignature(t, r, deviceSecret)
			pollSeen = true
			writeJSON(t, w, protocol.AgentCommand{
				CommandID:      "11111111-1111-1111-1111-111111111111",
				ClaimID:        "claim-1",
				AttemptNumber:  1,
				Type:           protocol.CommandCollectInventory,
				ClaimExpiresAt: time.Now().Add(time.Minute),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/endpoint-agent/commands/11111111-1111-1111-1111-111111111111/result":
			requireValidSignature(t, r, deviceSecret)
			var wire protocol.CommandResultWire
			if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
				t.Fatalf("decode result: %v", err)
			}
			if wire.ClaimID != "claim-1" {
				t.Fatalf("result claimId = %q, want claim-1", wire.ClaimID)
			}
			switch wire.Status {
			case "SUCCEEDED", "FAILED", "PARTIAL", "UNSUPPORTED":
			default:
				t.Fatalf("result status %q is not a backend CommandResultStatus", wire.Status)
			}
			resultSeen = true
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := protocol.NewClient(server.URL+"/api/v1/endpoint-agent", "", server.Client())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	runner := NewRunner(config.Config{
		APIURL:              server.URL + "/api/v1/endpoint-agent",
		EnrollmentToken:     "enroll-token",
		AgentVersion:        "test",
		CommandTimeout:      5 * time.Second,
		CommandPollInterval: time.Second,
	}, client, log.New(io.Discard, "", 0))

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !enrollSeen || !heartbeatSeen || !pollSeen || !resultSeen {
		t.Fatalf("lifecycle incomplete: enroll=%v heartbeat=%v poll=%v result=%v",
			enrollSeen, heartbeatSeen, pollSeen, resultSeen)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("write json: %v", err)
	}
}

// requireValidSignature enforces the BE-011 device-credential HMAC contract:
// the X-Device-Credential-* headers are present, no legacy X-Agent-* header is
// sent, and X-Signature verifies over the canonical string built from the
// BACKEND-VISIBLE path. The stub server receives the request at the dialed
// /api/v1/endpoint-agent path; the gateway rewrite to /api/v1/agent is
// reapplied here, so a signature over the wrong (dialed) path is rejected.
func requireValidSignature(t *testing.T, r *http.Request, secret string) {
	t.Helper()
	if r.Header.Get("X-Agent-Signature") != "" || r.Header.Get("X-Agent-Id") != "" {
		t.Fatalf("agent sent a legacy X-Agent-* header for %s %s", r.Method, r.URL.Path)
	}
	if r.Header.Get("X-Device-Credential-Id") == "" {
		t.Fatalf("missing X-Device-Credential-Id for %s %s", r.Method, r.URL.Path)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	canonicalPath := strings.Replace(r.URL.Path, "/endpoint-agent", "/agent", 1)
	canonical := security.CanonicalRequest(
		r.Method, canonicalPath, r.URL.RawQuery,
		r.Header.Get("X-Request-Timestamp"),
		r.Header.Get("X-Request-Nonce"),
		security.BodyHashHex(body),
	)
	if !security.Verify(secret, canonical, r.Header.Get("X-Signature")) {
		t.Fatalf("invalid signature for %s %s (canonical path %s)", r.Method, r.URL.Path, canonicalPath)
	}
}
