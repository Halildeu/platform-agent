//go:build windows

package inventory

import (
	"context"
	"time"
)

const diagnosticsProbeTimeout = 5 * time.Second

// ProbeDiagnostics is the AG-038 self-diagnostics entry point. It reads
// runtime config via the getProbeConfig seam, checks DNS reachability and
// TLS validity of the backend, and returns a DiagnosticsResult. Tests
// override the getProbeConfig and getLastPollLatencyMs seams to supply
// fixture values without invoking real network calls.
func ProbeDiagnostics(ctx context.Context, now func() time.Time) DiagnosticsResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if now == nil {
		now = time.Now
	}
	return runDiagnosticsProbeReal(ctx, "", "")
}

// runDiagnosticsProbeReal is the production probe. Exported for test seam.
var runDiagnosticsProbeReal = func(ctx context.Context, apiURL, agentVersion string) DiagnosticsResult {
	start := time.Now()
	result := DiagnosticsResult{
		SchemaVersion: DiagnosticsSchemaVersion,
		Supported:    true,
	}

	cfg := getProbeConfig()
	result.AgentVersion = cfg.AgentVersion
	result.ConfigHash = configHash(cfg.AgentVersion, cfg.APIURL)
	result.LastPollLatencyMs = getLastPollLatencyMs()

	host := parseBackendHost(cfg.APIURL)
	if host != "" {
		result.BackendDNSReachable = checkDNSReachability(host)
	}

	tlsCtx, cancel := context.WithTimeout(ctx, diagnosticsProbeTimeout)
	defer cancel()
	if host != "" {
		result.BackendTLSValid = checkBackendTLS(tlsCtx, host)
	}

	deriveDiagnosticsSummary(&result)
	result.ProbeDurationMs = diagnosticsElapsedMs(start, time.Now)
	return result
}