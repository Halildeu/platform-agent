package inventory

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/url"
	"sync"
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

// diagnosticsProvider is the process-wide source of truth the diagnostics
// probe reads in production. The runner populates it: the static agent
// config once at startup (SetDiagnosticsConfig), and the most recent
// NextCommand round-trip latency after every poll (RecordPollLatency). The
// getProbeConfig / getLastPollLatencyMs seams read from it by default so a
// live agent reports its REAL version + API-URL hash + poll latency rather
// than the "unknown" / 0 placeholders. Guarded by a mutex because the
// runner loop writes latency from the poll goroutine while a COLLECT_INVENTORY
// command may read it from the executor.
//
// REDACTION: CredentialID is stored here only so the probe MAY fold
// credential *presence* into operational reasoning. It is never serialized
// on the wire and never fed into configHash (which hashes AgentVersion|APIURL
// only). The diagnosticsProvider value itself is never marshalled.
var diagnosticsProvider = struct {
	mu                sync.RWMutex
	cfg               probeConfig
	lastPollLatencyMs int
}{
	cfg: probeConfig{
		// Pre-startup defaults. Overwritten by SetDiagnosticsConfig once
		// the runner has parsed config; if the probe somehow fires before
		// that, it fails closed to "unknown" rather than leaking anything.
		AgentVersion: "unknown",
		APIURL:       "unknown",
	},
}

// SetDiagnosticsConfig records the live agent config the self-diagnostics
// probe reports. The runner calls this once at startup with the real
// AgentVersion + APIURL from internal/config. credentialID is stored for
// optional presence-reasoning ONLY — it is never emitted on the wire nor
// hashed (see the REDACTION CONTRACT on probeConfig + configHash).
func SetDiagnosticsConfig(agentVersion, apiURL, credentialID string) {
	diagnosticsProvider.mu.Lock()
	defer diagnosticsProvider.mu.Unlock()
	diagnosticsProvider.cfg = probeConfig{
		AgentVersion: agentVersion,
		APIURL:       apiURL,
		CredentialID: credentialID,
	}
}

// RecordPollLatency records the most recent NextCommand round-trip duration
// (milliseconds) so a subsequent COLLECT_INVENTORY diagnostics probe can
// report it as lastPollLatencyMs. The runner calls this after each poll.
// Negative inputs are clamped to 0 so a clock skew never produces a negative
// wire value.
func RecordPollLatency(ms int) {
	if ms < 0 {
		ms = 0
	}
	diagnosticsProvider.mu.Lock()
	defer diagnosticsProvider.mu.Unlock()
	diagnosticsProvider.lastPollLatencyMs = ms
}

// DiagnosticsConfigSnapshot reports what the diagnostics provider currently
// holds, for operational logging and as a wiring regression check. It
// deliberately returns hasCredential (presence) rather than the raw
// credentialID so this accessor can never become a credential-leak path:
// the redaction contract holds even here.
func DiagnosticsConfigSnapshot() (agentVersion, apiURL string, hasCredential bool, lastPollLatencyMs int) {
	diagnosticsProvider.mu.RLock()
	defer diagnosticsProvider.mu.RUnlock()
	return diagnosticsProvider.cfg.AgentVersion,
		diagnosticsProvider.cfg.APIURL,
		diagnosticsProvider.cfg.CredentialID != "",
		diagnosticsProvider.lastPollLatencyMs
}

// getProbeConfig reads runtime diagnostics values. In production it returns
// the config registered by SetDiagnosticsConfig; tests override the seam to
// supply fixture values without touching the provider.
var getProbeConfig = func() probeConfig {
	diagnosticsProvider.mu.RLock()
	defer diagnosticsProvider.mu.RUnlock()
	return diagnosticsProvider.cfg
}

// getLastPollLatencyMs returns the most recent NextCommand round-trip
// duration in milliseconds. In production it returns the value recorded by
// RecordPollLatency; tests override the seam.
var getLastPollLatencyMs = func() int {
	diagnosticsProvider.mu.RLock()
	defer diagnosticsProvider.mu.RUnlock()
	return diagnosticsProvider.lastPollLatencyMs
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

// backendHostParts holds the three distinct values the reachability probe
// needs, each derived from the backend API URL:
//
//   - Hostname:    the bare host with NO port — fed to net.Resolver.LookupHost
//     and used as the TLS ServerName (SNI). A "host:port" string is never a
//     valid DNS name or SNI value.
//   - DialAddress: host:port for tls.DialContext("tcp", ...). The port is the
//     URL's explicit port, or "443" (https default) when the URL omits it —
//     a bare hostname has no port and the dial would otherwise fail.
//   - ServerName:  the SNI / certificate-verification name, equal to Hostname
//     (no port). Including the port in SNI breaks certificate validation.
//
// OK reports whether a usable host was derived; false (empty / unparseable /
// hostless URL) drives the fail-closed BACKEND_HOST_UNRESOLVED path.
type backendHostParts struct {
	Hostname    string
	DialAddress string
	ServerName  string
	OK          bool
}

// parseBackendHost derives the DNS / dial / SNI values from a backend API URL.
// It uses url.Hostname() (port-stripped) for DNS + SNI and net.JoinHostPort
// with the URL port (or the https default 443) for the dial address. So
// "https://api.example.com" (no port) still dials :443, and
// "https://api.example.com:8443/x" resolves the bare hostname rather than
// "api.example.com:8443" and sends SNI "api.example.com" rather than
// "api.example.com:8443". Returns OK=false for an empty / unparseable /
// hostless URL.
func parseBackendHost(apiURL string) backendHostParts {
	if apiURL == "" {
		return backendHostParts{}
	}
	parsed, err := url.Parse(apiURL)
	if err != nil {
		return backendHostParts{}
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return backendHostParts{}
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	return backendHostParts{
		Hostname:    hostname,
		DialAddress: net.JoinHostPort(hostname, port),
		ServerName:  hostname,
		OK:          true,
	}
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

// checkBackendTLSReal attempts a TLS handshake to the backend.
// dialAddress is the host:port to connect to; serverName is the bare
// hostname used for SNI + certificate verification (never host:port).
// Returns false on any connection or certificate error. Timeout is
// caller-controlled via the provided context.
func checkBackendTLSReal(ctx context.Context, dialAddress, serverName string) bool {
	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS10,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", dialAddress)
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
// the authoritative values come from the getProbeConfig / getLastPollLatencyMs
// seams. In production those seams read the diagnosticsProvider, which the
// runner populates via SetDiagnosticsConfig (live AgentVersion + APIURL at
// startup) and RecordPollLatency (real NextCommand round-trip after each
// poll) — so the probe reflects the live agent config rather than the
// "unknown" placeholders or caller-passed strings.
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
	if host.OK {
		// DNS resolves the bare hostname; TLS dials host:port and verifies
		// SNI against the bare hostname. Three distinct values — a
		// "host:port" string is neither a valid DNS name nor SNI value.
		result.BackendDNSReachable = checkDNSReachability(host.Hostname)

		tlsCtx, cancel := context.WithTimeout(ctx, diagnosticsProbeTimeout)
		defer cancel()
		result.BackendTLSValid = checkBackendTLS(tlsCtx, host.DialAddress, host.ServerName)
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
