package app

// AG-038 (Codex 019e76c5 finding #1): prove the runner wires the REAL agent
// config into the inventory diagnostics provider at construction, and the
// REAL NextCommand round-trip latency after each poll. Before this wiring a
// live agent reported agentVersion:"unknown" / configHash(unknown|unknown) /
// lastPollLatencyMs:0 — the probe was non-functional in production.

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"platform-agent/internal/config"
	"platform-agent/internal/inventory"
	"platform-agent/internal/protocol"
)

// restoreDiagnosticsProviderDefaults resets the process-wide provider so a
// test cannot leak its fixture config into a later test in the package.
func restoreDiagnosticsProviderDefaults(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		inventory.SetDiagnosticsConfig("unknown", "unknown", "")
		inventory.RecordPollLatency(0)
	})
}

// TestNewRunner_WiresDiagnosticsConfig asserts NewRunner registers the live
// AgentVersion + APIURL with the diagnostics provider (so the probe stops
// emitting "unknown"), and that the credentialID is recorded as PRESENCE only
// — the snapshot accessor never returns the raw value.
func TestNewRunner_WiresDiagnosticsConfig(t *testing.T) {
	restoreDiagnosticsProviderDefaults(t)

	const (
		ver  = "5.1.0-agent"
		api  = "https://endpoint-agent.example.com:8443/api/v1/endpoint-agent"
		cred = "device-cred-id-PROVIDER-ONLY"
	)
	client, err := protocol.NewClient(api, "", &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_ = NewRunner(config.Config{
		AgentVersion: ver,
		APIURL:       api,
		CredentialID: cred,
	}, client, log.New(io.Discard, "", 0))

	gotVer, gotAPI, hasCred, _ := inventory.DiagnosticsConfigSnapshot()
	if gotVer != ver {
		t.Errorf("provider AgentVersion = %q; want %q", gotVer, ver)
	}
	if gotVer == "unknown" {
		t.Error("provider AgentVersion still 'unknown' — NewRunner did not wire config")
	}
	if gotAPI != api {
		t.Errorf("provider APIURL = %q; want %q", gotAPI, api)
	}
	if !hasCred {
		t.Error("provider hasCredential = false; want true (credentialID was supplied)")
	}
}

// TestRunOnce_RecordsRealPollLatency drives an enroll→heartbeat→poll
// lifecycle against a stub backend (mirroring TestRunnerRunOnceFullLifecycle's
// BE-011 HMAC contract) and asserts the diagnostics provider's recorded poll
// latency is non-zero afterward — i.e. the runner measured the real
// NextCommand round-trip instead of leaving the seam at 0. The poll returns
// 204 (no command) so no command executes; an empty poll is still a real
// round-trip and must be measured.
func TestRunOnce_RecordsRealPollLatency(t *testing.T) {
	restoreDiagnosticsProviderDefaults(t)

	const deviceSecret = "device-hmac-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/endpoint-agent/enrollments/consume":
			writeJSON(t, w, protocol.EnrollResponse{
				DeviceID:        "device-1",
				CredentialKeyID: "cred-1",
				Secret:          deviceSecret,
				HmacAlgorithm:   "hmac-sha256",
				ServerTime:      time.Now().UTC(),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/endpoint-agent/heartbeat":
			requireValidSignature(t, r, deviceSecret)
			writeJSON(t, w, protocol.HeartbeatResponse{
				Accepted: true, DeviceID: "device-1", Status: "ACTIVE", ServerTime: time.Now().UTC(),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/endpoint-agent/commands/next":
			requireValidSignature(t, r, deviceSecret)
			// Small server-side delay so the measured round-trip is reliably
			// > 0 ms, then 204 (no command queued).
			time.Sleep(5 * time.Millisecond)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := protocol.NewClient(server.URL+"/api/v1/endpoint-agent", "", server.Client())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	runner := NewRunner(config.Config{
		AgentVersion:        "5.1.0-agent",
		APIURL:              server.URL + "/api/v1/endpoint-agent",
		EnrollmentToken:     "enroll-token",
		CommandTimeout:      5 * time.Second,
		CommandPollInterval: time.Second,
	}, client, log.New(io.Discard, "", 0))

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	_, _, _, latency := inventory.DiagnosticsConfigSnapshot()
	if latency <= 0 {
		t.Errorf("recorded poll latency = %d ms; want > 0 (runner must measure the real NextCommand round-trip)", latency)
	}
}
