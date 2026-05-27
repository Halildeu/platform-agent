//go:build windows

package winget

import (
	"time"
)

// DetectSourceEgress wires the production locator + executor into
// RunSourceEgressPreflight. AG-026A Windows entry point.
//
// The Resolve/Dial/HTTPCheck seams default to the production
// implementations defined in source_egress.go (net.DefaultResolver,
// net.Dialer, http.Client with TLS 1.2 minimum). Tests inject
// stubs directly via SourceEgressOptions rather than touching
// this wrapper.
//
// The `now` parameter is kept for caller-side audit stamping (the
// inventory snapshot uses it as CollectedAt); the preflight's
// internal duration measurement uses the real wall clock, mirroring
// the AG-026 Detect pattern (Codex 019e691c peer review iter-1).
func DetectSourceEgress(now time.Time) SourceEgressReadiness {
	_ = now
	return RunSourceEgressPreflight(SourceEgressOptions{
		Locator: defaultLocator,
		Execute: defaultExecutor,
		Timeout: DefaultSourceEgressTimeout * time.Second,
		Now:     time.Now,
	})
}
