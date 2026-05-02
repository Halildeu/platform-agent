package app

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/config"
	"platform-agent/internal/protocol"
	"platform-agent/internal/security"
)

func TestRunnerRunOnceEnrollHeartbeatCommandResult(t *testing.T) {
	agentSecret := "test-agent-secret"
	var heartbeatSeen bool
	var resultSeen bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/endpoint-agent/enroll":
			writeJSON(t, w, protocol.EnrollResponse{
				AgentID:     "agent-1",
				AgentSecret: agentSecret,
				InstallID:   "install-1",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/endpoint-agent/heartbeat":
			requireValidSignature(t, r, agentSecret)
			heartbeatSeen = true
			writeJSON(t, w, protocol.HeartbeatResponse{
				Accepted:   true,
				ServerTime: time.Now(),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/endpoint-agent/commands/next":
			requireValidSignature(t, r, agentSecret)
			writeJSON(t, w, protocol.AgentCommand{
				CommandID:      "command-1",
				ClaimID:        "claim-1",
				AttemptNumber:  1,
				Type:           protocol.CommandCollectInventory,
				ClaimExpiresAt: time.Now().Add(time.Minute),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/endpoint-agent/commands/command-1/result":
			requireValidSignature(t, r, agentSecret)
			var result protocol.CommandResult
			if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
				t.Fatalf("decode result: %v", err)
			}
			if result.Status != protocol.CommandStatusSucceeded {
				t.Fatalf("result status = %s, want %s", result.Status, protocol.CommandStatusSucceeded)
			}
			if result.ClaimID != "claim-1" || result.AttemptNumber != 1 {
				t.Fatalf("invalid claim result: %#v", result)
			}
			resultSeen = true
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := protocol.NewClient(server.URL+"/api/v1/endpoint-agent", server.Client())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	runner := NewRunner(config.Config{
		APIURL:              server.URL + "/api/v1/endpoint-agent",
		EnrollmentToken:     "enroll-token",
		AgentVersion:        "test",
		CommandTimeout:      time.Second,
		CommandPollInterval: time.Second,
	}, client, log.New(io.Discard, "", 0))

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !heartbeatSeen {
		t.Fatal("heartbeat was not submitted")
	}
	if !resultSeen {
		t.Fatal("command result was not submitted")
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("write json: %v", err)
	}
}

func requireValidSignature(t *testing.T, r *http.Request, secret string) {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	timestamp, err := strconv.ParseInt(r.Header.Get("X-Agent-Timestamp"), 10, 64)
	if err != nil {
		t.Fatalf("invalid timestamp: %v", err)
	}
	ok := security.VerifyRequestSignature(
		secret,
		r.Method,
		r.URL.Path,
		timestamp,
		r.Header.Get("X-Agent-Nonce"),
		body,
		r.Header.Get("X-Agent-Signature"),
	)
	if !ok {
		t.Fatalf("invalid signature for %s %s", r.Method, r.URL.Path)
	}
}
