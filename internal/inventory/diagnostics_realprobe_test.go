package inventory

// These tests exercise the platform-neutral diagnostics orchestration
// (runDiagnosticsProbeReal in diagnostics.go). The orchestration is
// intentionally NOT build-tagged so this logic — config hashing, host parse,
// DNS/TLS reachability seam wiring, and result derivation — runs under the
// linux CI host (AG-036 build-tag lesson). The Windows-platform entry point
// (ProbeDiagnostics) is covered separately in diagnostics_windows_test.go.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// stubDiagnosticsReachable points the config + DNS/TLS seams at a healthy
// fixture (parseable host, DNS reachable, TLS valid) so happy-path tests run
// fully offline and deterministically. It returns a restore function the
// caller defers; it does NOT register t.Cleanup, so the caller controls the
// restore point.
func stubDiagnosticsReachable(t *testing.T, version, apiURL string) func() {
	t.Helper()
	origCfg := getProbeConfig
	origDNS := checkDNSReachability
	origTLS := checkBackendTLS
	getProbeConfig = func() probeConfig {
		return probeConfig{AgentVersion: version, APIURL: apiURL}
	}
	checkDNSReachability = func(string) bool { return true }
	checkBackendTLS = func(context.Context, string, string) bool { return true }
	return func() {
		getProbeConfig = origCfg
		checkDNSReachability = origDNS
		checkBackendTLS = origTLS
	}
}

func TestDiagnosticsProbeResultSchemaVersion(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.SchemaVersion != DiagnosticsSchemaVersion {
		t.Errorf("SchemaVersion = %d; want %d", result.SchemaVersion, DiagnosticsSchemaVersion)
	}
}

func TestDiagnosticsProbeResultSupported(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if !result.Supported {
		t.Error("Supported should be true from runDiagnosticsProbeReal")
	}
}

func TestDiagnosticsProbeResultConfigHashNotEmpty(t *testing.T) {
	orig := getProbeConfig
	t.Cleanup(func() { getProbeConfig = orig })
	getProbeConfig = func() probeConfig {
		return probeConfig{AgentVersion: "1.0.0", APIURL: "https://api.example.com"}
	}
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.ConfigHash == "" || result.ConfigHash == "unknown" {
		t.Errorf("ConfigHash = %q; want non-empty", result.ConfigHash)
	}
}

func TestDiagnosticsProbeResultConfigHashStable(t *testing.T) {
	orig := getProbeConfig
	t.Cleanup(func() { getProbeConfig = orig })
	getProbeConfig = func() probeConfig {
		return probeConfig{AgentVersion: "1.0.0", APIURL: "https://api.example.com"}
	}
	r1 := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	r2 := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if r1.ConfigHash != r2.ConfigHash {
		t.Errorf("ConfigHash not stable: %q vs %q", r1.ConfigHash, r2.ConfigHash)
	}
}

func TestDiagnosticsProbeResultConfigHashDiffersByVersion(t *testing.T) {
	orig := getProbeConfig
	t.Cleanup(func() { getProbeConfig = orig })

	getProbeConfig = func() probeConfig {
		return probeConfig{AgentVersion: "1.0.0", APIURL: "https://api.example.com"}
	}
	r1 := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")

	getProbeConfig = func() probeConfig {
		return probeConfig{AgentVersion: "2.0.0", APIURL: "https://api.example.com"}
	}
	r2 := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "2.0.0")

	if r1.ConfigHash == r2.ConfigHash {
		t.Error("ConfigHash should differ between versions")
	}
}

func TestDiagnosticsProbeResultProbeDurationMs(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.ProbeDurationMs < 0 {
		t.Errorf("ProbeDurationMs = %d; want >= 0", result.ProbeDurationMs)
	}
}

func TestDiagnosticsProbeResultLastErrorNil(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.LastError != nil {
		t.Errorf("LastError = %+v; want nil", result.LastError)
	}
}

func TestRunDiagnosticsProbeReal_ProbeCompleteTrue(t *testing.T) {
	restore := stubDiagnosticsReachable(t, "1.0.0", "https://api.example.com")
	defer restore()
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if !result.ProbeComplete {
		t.Error("ProbeComplete should be true with a parseable host and no probe errors")
	}
	if !result.BackendDNSReachable || !result.BackendTLSValid {
		t.Error("seam-mocked DNS/TLS should report reachable/valid")
	}
}

func TestDiagnosticsProbeResultProbeErrorsEmpty(t *testing.T) {
	restore := stubDiagnosticsReachable(t, "1.0.0", "https://api.example.com")
	defer restore()
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if len(result.ProbeErrors) != 0 {
		t.Errorf("ProbeErrors = %v; want empty for a healthy probe", result.ProbeErrors)
	}
}

func TestRunDiagnosticsProbeReal_UnreachableHostNoProbeError(t *testing.T) {
	// A backend that is parseable but unreachable yields false reachability
	// booleans but is NOT a probe error — the probe ran to completion, it just
	// observed an unreachable backend. ProbeComplete must stay true so the
	// backend can trust the reachability verdict.
	origCfg := getProbeConfig
	origDNS := checkDNSReachability
	origTLS := checkBackendTLS
	t.Cleanup(func() {
		getProbeConfig = origCfg
		checkDNSReachability = origDNS
		checkBackendTLS = origTLS
	})
	getProbeConfig = func() probeConfig {
		return probeConfig{AgentVersion: "1.0.0", APIURL: "https://api.example.com"}
	}
	checkDNSReachability = func(string) bool { return false }
	checkBackendTLS = func(context.Context, string, string) bool { return false }

	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.BackendDNSReachable || result.BackendTLSValid {
		t.Error("expected unreachable backend booleans to be false")
	}
	if !result.ProbeComplete {
		t.Error("ProbeComplete should stay true: an unreachable backend is a verdict, not a probe failure")
	}
	if len(result.ProbeErrors) != 0 {
		t.Errorf("ProbeErrors = %v; want empty (unreachable != probe error)", result.ProbeErrors)
	}
}

func TestRunDiagnosticsProbeReal_PollLatency(t *testing.T) {
	origLatency := getLastPollLatencyMs
	origCfg := getProbeConfig
	t.Cleanup(func() {
		getLastPollLatencyMs = origLatency
		getProbeConfig = origCfg
	})

	getLastPollLatencyMs = func() int { return 999 }
	getProbeConfig = func() probeConfig {
		return probeConfig{AgentVersion: "1.0.0", APIURL: "https://api.example.com"}
	}

	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.LastPollLatencyMs != 999 {
		t.Errorf("LastPollLatencyMs = %d; want 999", result.LastPollLatencyMs)
	}
}

func TestRunDiagnosticsProbeReal_InvalidURLNoCrash(t *testing.T) {
	orig := getProbeConfig
	t.Cleanup(func() { getProbeConfig = orig })
	getProbeConfig = func() probeConfig {
		return probeConfig{AgentVersion: "1.0.0", APIURL: "://invalid"}
	}
	// Should not panic even with unparseable URL; host becomes "".
	result := runDiagnosticsProbeReal(context.Background(), "://invalid", "1.0.0")
	if result.SchemaVersion != DiagnosticsSchemaVersion {
		t.Errorf("SchemaVersion = %d; want %d", result.SchemaVersion, DiagnosticsSchemaVersion)
	}
	// Fail-closed: no resolvable host → BACKEND_HOST_UNRESOLVED probe error → ProbeComplete false.
	if result.ProbeComplete {
		t.Error("ProbeComplete should be false when URL unparseable (no host)")
	}
}

func TestRunDiagnosticsProbeReal_NilCtxNoCrash(t *testing.T) {
	// A nil context must be tolerated by the platform-neutral orchestration.
	result := runDiagnosticsProbeReal(nil, "https://api.example.com", "1.0.0")
	if result.SchemaVersion != DiagnosticsSchemaVersion {
		t.Errorf("SchemaVersion = %d; want %d", result.SchemaVersion, DiagnosticsSchemaVersion)
	}
	if !result.Supported {
		t.Error("Supported should be true from runDiagnosticsProbeReal")
	}
}

func TestRunDiagnosticsProbeReal_GetProbeConfigSeam(t *testing.T) {
	origCfg := getProbeConfig
	origDNS := checkDNSReachability
	origTLS := checkBackendTLS
	t.Cleanup(func() {
		getProbeConfig = origCfg
		checkDNSReachability = origDNS
		checkBackendTLS = origTLS
	})

	getProbeConfig = func() probeConfig {
		return probeConfig{
			AgentVersion: "9.9.9-test",
			APIURL:       "https://diag.test.local",
			CredentialID: "cred-id-should-not-appear-on-wire",
		}
	}
	// Keep the probe fully offline: the redaction assertion does not need a
	// real DNS/TLS round-trip, and mocking avoids a 3s resolver timeout.
	checkDNSReachability = func(string) bool { return false }
	checkBackendTLS = func(context.Context, string, string) bool { return false }

	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.AgentVersion != "9.9.9-test" {
		t.Errorf("AgentVersion = %q; want %q", result.AgentVersion, "9.9.9-test")
	}
	// REDACTION REGRESSION: the credentialID supplied via the seam must never
	// surface anywhere in the marshalled wire payload.
	bytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if strings.Contains(string(bytes), "cred-id-should-not-appear-on-wire") {
		t.Error("JSON output contains credentialID — wire boundary violation")
	}
}

func TestRunDiagnosticsProbeReal_EmptyAPIURL(t *testing.T) {
	orig := getProbeConfig
	t.Cleanup(func() { getProbeConfig = orig })

	getProbeConfig = func() probeConfig {
		return probeConfig{AgentVersion: "1.0.0", APIURL: ""}
	}

	result := runDiagnosticsProbeReal(context.Background(), "", "1.0.0")
	// Empty API URL → no host → DNS/TLS checks skipped + BACKEND_HOST_UNRESOLVED.
	if result.ProbeComplete {
		t.Error("ProbeComplete should be false when no host (empty API URL)")
	}
	if len(result.ProbeErrors) == 0 {
		t.Error("expected a BACKEND_HOST_UNRESOLVED probe error when no host")
	}
}

func TestDiagnosticsResult_LastErrorOnNil(t *testing.T) {
	result := runDiagnosticsProbeReal(context.Background(), "https://api.example.com", "1.0.0")
	if result.LastError != nil {
		t.Errorf("LastError = %+v; want nil", result.LastError)
	}
}

// TestDiagnosticsProductionProvider_YieldsRealValues proves the PRODUCTION
// path (Codex 019e76c5 finding #1). It does NOT override the getProbeConfig /
// getLastPollLatencyMs seams; instead it drives them through the real
// provider setters SetDiagnosticsConfig + RecordPollLatency exactly as the
// runner does at startup / after each poll. The probe must then emit the
// concrete agent version, a hash of the REAL API URL (not "unknown"), and the
// recorded poll latency — and must NEVER leak the credentialID. Only the DNS
// and TLS *network* seams are mocked (legitimately — no real round-trip on
// the CI host); the config + latency come straight from production code.
func TestDiagnosticsProductionProvider_YieldsRealValues(t *testing.T) {
	const (
		realVersion = "3.7.2-prod"
		realURL     = "https://endpoint-agent.prod.example.com:8443/api/v1/endpoint-agent"
		credID      = "cred-PROD-must-not-leak"
		pollMs      = 137
	)

	// Snapshot + restore the package provider and the DNS/TLS network seams.
	// getProbeConfig / getLastPollLatencyMs are intentionally left at their
	// production (provider-reading) defaults.
	origCfg := getProbeConfig
	origLat := getLastPollLatencyMs
	origDNS := checkDNSReachability
	origTLS := checkBackendTLS
	origProviderCfg, origProviderLat := snapshotDiagnosticsProvider()
	t.Cleanup(func() {
		getProbeConfig = origCfg
		getLastPollLatencyMs = origLat
		checkDNSReachability = origDNS
		checkBackendTLS = origTLS
		restoreDiagnosticsProvider(origProviderCfg, origProviderLat)
	})
	checkDNSReachability = func(string) bool { return true }
	checkBackendTLS = func(context.Context, string, string) bool { return true }

	// Drive production setters exactly as the runner does.
	SetDiagnosticsConfig(realVersion, realURL, credID)
	RecordPollLatency(pollMs)

	result := runDiagnosticsProbeReal(context.Background(), "ignored-param", "ignored-param")

	if result.AgentVersion != realVersion {
		t.Errorf("AgentVersion = %q; want %q (provider must override 'unknown')", result.AgentVersion, realVersion)
	}
	if result.AgentVersion == "unknown" {
		t.Error("AgentVersion is still 'unknown' — production provider not wired")
	}
	wantHash := configHash(realVersion, realURL)
	if result.ConfigHash != wantHash {
		t.Errorf("ConfigHash = %q; want %q (hash of REAL version|url)", result.ConfigHash, wantHash)
	}
	if result.ConfigHash == configHash("unknown", "unknown") {
		t.Error("ConfigHash equals the unknown|unknown placeholder hash — real config not wired")
	}
	if result.LastPollLatencyMs != pollMs {
		t.Errorf("LastPollLatencyMs = %d; want %d (RecordPollLatency value)", result.LastPollLatencyMs, pollMs)
	}
	// Real URL has a host → reachability ran → no probe error → complete.
	if !result.ProbeComplete {
		t.Errorf("ProbeComplete = false; want true (real URL resolves to a host)")
	}

	// REDACTION: the credentialID handed to SetDiagnosticsConfig must never
	// surface on the wire, even though the provider stored it.
	wire, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if strings.Contains(string(wire), credID) {
		t.Error("wire payload contains credentialID — redaction boundary violation")
	}
	if strings.Contains(string(wire), realURL) {
		t.Error("wire payload contains the raw API URL — only its hash may appear")
	}
}

// TestRecordPollLatency_ClampsNegative: a negative input is clamped to 0 so a
// clock skew never produces a negative wire value.
func TestRecordPollLatency_ClampsNegative(t *testing.T) {
	origLat := getLastPollLatencyMs
	origCfg, origProvLat := snapshotDiagnosticsProvider()
	t.Cleanup(func() {
		getLastPollLatencyMs = origLat
		restoreDiagnosticsProvider(origCfg, origProvLat)
	})
	RecordPollLatency(-5)
	if got := getLastPollLatencyMs(); got != 0 {
		t.Errorf("getLastPollLatencyMs after RecordPollLatency(-5) = %d; want 0", got)
	}
}

// snapshotDiagnosticsProvider / restoreDiagnosticsProvider let provider tests
// leave the process-wide provider exactly as they found it.
func snapshotDiagnosticsProvider() (probeConfig, int) {
	diagnosticsProvider.mu.RLock()
	defer diagnosticsProvider.mu.RUnlock()
	return diagnosticsProvider.cfg, diagnosticsProvider.lastPollLatencyMs
}

func restoreDiagnosticsProvider(cfg probeConfig, lat int) {
	diagnosticsProvider.mu.Lock()
	defer diagnosticsProvider.mu.Unlock()
	diagnosticsProvider.cfg = cfg
	diagnosticsProvider.lastPollLatencyMs = lat
}
