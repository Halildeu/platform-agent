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
//
// REDACTION CONTRACT: CredentialID is read here only so the probe can fold
// the *presence* of a credential into operational reasoning; it is NEVER
// emitted raw on the wire and is NEVER fed into ConfigHash. configHash hashes
// only AgentVersion + APIURL. See TestRunDiagnosticsProbeReal_GetProbeConfigSeam
// and TestDiagnosticsResult_JSONKeys_NoPII for the regression guards.
type probeConfig struct {
	AgentVersion string
	APIURL       string
	CredentialID string
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

// diagnosticsProbeTimeout bounds the DNS + TLS reachability checks. The probe
// is fire-and-forget: a slow or unreachable backend yields
// BackendDNSReachable=false / BackendTLSValid=false rather than blocking the
// inventory collection.
const diagnosticsProbeTimeout = 5 * time.Second

type DiagnosticsResult struct {
	SchemaVersion       int                     `json:"schemaVersion"`
	Supported           bool                    `json:"supported"`
	ProbeComplete       bool                    `json:"probeComplete"`
	AgentVersion        string                  `json:"agentVersion"`
	ConfigHash          string                  `json:"configHash"`
	LastPollLatencyMs   int                     `json:"lastPollLatencyMs"`
	BackendDNSReachable bool                    `json:"backendDNSReachable"`
	BackendTLSValid     bool                    `json:"backendTLSValid"`
	LastError           *DiagnosticsLastError   `json:"lastError,omitempty"`
	ProbeErrors         []DiagnosticsProbeError `json:"probeErrors,omitempty"`
	ProbeDurationMs     int                     `json:"probeDurationMs"`
}

type DiagnosticsLastError struct {
	OccurredAt time.Time `json:"occurredAt"`
	Code       string    `json:"code"`
	Summary    string    `json:"summary"`
}

type DiagnosticsProbeError struct {
	Code    string `json:"code"`
	Summary string `json:"summary,omitempty"`
}

func deriveDiagnosticsSummary(result *DiagnosticsResult) {
	if result.ConfigHash == "" {
		result.ConfigHash = "unknown"
	}
	// Fail-closed: ProbeComplete is true only when the probe ran on a
	// supported platform AND no probe error was recorded.
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

// checkDNSReachability and checkBackendTLS are package-level seams (function
// variables) so the diagnostics orchestration can be unit-tested fully offline
// on the linux CI host — no real DNS query or TLS dial is required to assert
// the result-derivation and redaction contracts. Production wires the real
// network implementations below; tests override these with t.Cleanup-restored
// stubs.
var (
	checkDNSReachability = checkDNSReachabilityReal
	checkBackendTLS      = checkBackendTLSReal
)

// checkDNSReachabilityReal performs a DNS lookup for the backend host.
func checkDNSReachabilityReal(host string) bool {
	if host == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := &net.Resolver{}
	_, err := r.LookupHost(ctx, host)
	return err == nil
}

// checkBackendTLSReal attempts a TLS handshake to the backend host.
// Returns false on any connection or certificate error.
// Timeout is caller-controlled via the provided context.
func checkBackendTLSReal(ctx context.Context, host string) bool {
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

// runDiagnosticsProbeReal is the platform-neutral diagnostics orchestration.
// It is intentionally NOT build-tagged so its DNS / TLS reachability and
// result-derivation logic execute under the linux CI host (AG-036 build-tag
// lesson). The reachability primitives it calls (configHash, parseBackendHost,
// checkDNSReachability, checkBackendTLS) are pure cross-platform Go; nothing in
// this orchestration requires a Windows syscall. The Windows entry point
// (ProbeDiagnostics in diagnostics_windows.go) wires Supported=true and the
// real getProbeConfig/getLastPollLatencyMs seams into it; tests override those
// seams to assert behavior without real network calls.
//
// The apiURL/agentVersion parameters are retained for signature stability but
// the authoritative values come from the getProbeConfig seam, so the probe
// reflects the live agent config rather than caller-passed strings.
var runDiagnosticsProbeReal = func(ctx context.Context, apiURL, agentVersion string) DiagnosticsResult {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	result := DiagnosticsResult{
		SchemaVersion: DiagnosticsSchemaVersion,
		Supported:     true,
	}

	cfg := getProbeConfig()
	result.AgentVersion = cfg.AgentVersion
	result.ConfigHash = configHash(cfg.AgentVersion, cfg.APIURL)
	result.LastPollLatencyMs = getLastPollLatencyMs()

	host := parseBackendHost(cfg.APIURL)
	if host != "" {
		result.BackendDNSReachable = checkDNSReachability(host)

		tlsCtx, cancel := context.WithTimeout(ctx, diagnosticsProbeTimeout)
		defer cancel()
		result.BackendTLSValid = checkBackendTLS(tlsCtx, host)
	} else {
		// No resolvable backend host (empty or unparseable API URL) means
		// the reachability probe could not run. Record a bounded, static
		// probe error so ProbeComplete derives to false (fail-closed): the
		// backend must not read "DNS/TLS both false" as an authoritative
		// "backend unreachable" verdict when the probe was actually
		// degraded. The summary is static phrasing — no host, URL, path,
		// or credential is echoed.
		result.ProbeErrors = append(result.ProbeErrors, DiagnosticsProbeError{
			Code:    "BACKEND_HOST_UNRESOLVED",
			Summary: "backend API URL missing or unparseable; reachability checks skipped",
		})
	}

	deriveDiagnosticsSummary(&result)
	result.ProbeDurationMs = diagnosticsElapsedMs(start, time.Now)
	return result
}
