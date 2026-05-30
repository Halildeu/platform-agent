package inventory

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/url"
	"time"
)

// probeConfig holds the runtime values the diagnostics probe reads from
// the runner's config. Exported so tests can supply fixture values without
// importing the config package.
type probeConfig struct {
	AgentVersion  string
	APIURL        string
	CredentialID  string
}

// getProbeConfig reads runtime diagnostics values. Tests override the seam.
var getProbeConfig = func() probeConfig {
	return probeConfig{
		AgentVersion: "unknown",
		APIURL:       "unknown",
		CredentialID: "",
	}
}

// getLastPollLatencyMs returns the most recent NextCommand round-trip
// duration in milliseconds. Tests override the seam.
var getLastPollLatencyMs = func() int {
	return 0
}

// AG-038 — Agent Self-Diagnostics Probe (Faz 22.5 Sprint B P2 operational visibility).

const DiagnosticsSchemaVersion = 1

type DiagnosticsResult struct {
	SchemaVersion       int                      `json:"schemaVersion"`
	Supported           bool                     `json:"supported"`
	ProbeComplete       bool                     `json:"probeComplete"`
	AgentVersion        string                   `json:"agentVersion"`
	ConfigHash          string                  `json:"configHash"`
	LastPollLatencyMs   int                      `json:"lastPollLatencyMs"`
	BackendDNSReachable bool                     `json:"backendDNSReachable"`
	BackendTLSValid     bool                     `json:"backendTLSValid"`
	LastError           *DiagnosticsLastError    `json:"lastError,omitempty"`
	ProbeErrors         []DiagnosticsProbeError  `json:"probeErrors,omitempty"`
	ProbeDurationMs     int                      `json:"probeDurationMs"`
}

type DiagnosticsLastError struct {
	OccurredAt time.Time `json:"occurredAt"`
	Code      string     `json:"code"`
	Summary   string     `json:"summary"`
}

type DiagnosticsProbeError struct {
	Code    string `json:"code"`
	Summary string `json:"summary,omitempty"`
}

func deriveDiagnosticsSummary(result *DiagnosticsResult) {
	if result.ConfigHash == "" {
		result.ConfigHash = "unknown"
	}
	result.ProbeComplete = len(result.ProbeErrors) == 0 && result.Supported
}

func diagnosticsElapsedMs(start time.Time, now func() time.Time) int {
	if now == nil {
		now = time.Now
	}
	return int(now().Sub(start) / time.Millisecond)
}

// configHash computes a short SHA-256 hex of the agent version and API URL.
// No PII, credentials, or paths appear in the hash — only static config.
func configHash(agentVersion, apiURL string) string {
	input := agentVersion + "|" + apiURL
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:16]
}

// parseBackendHost extracts the host:port from a backend API URL for DNS check.
// Returns empty string if URL is unparseable.
func parseBackendHost(apiURL string) string {
	if apiURL == "" {
		return ""
	}
	// Strip query and fragment
	parsed, err := url.Parse(apiURL)
	if err != nil {
		return ""
	}
	if parsed.Host == "" {
		return ""
	}
	return parsed.Host
}

// checkDNSReachability performs a DNS lookup for the backend host.
func checkDNSReachability(host string) bool {
	if host == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := &net.Resolver{}
	_, err := r.LookupHost(ctx, host)
	return err == nil
}

// checkBackendTLS attempts a TLS handshake to the backend host.
// Returns false on any connection or certificate error.
// Timeout is caller-controlled via the provided context.
func checkBackendTLS(ctx context.Context, host string) bool {
	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS10,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}