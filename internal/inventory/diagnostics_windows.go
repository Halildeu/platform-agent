//go:build windows

package inventory

import (
	"context"
	"time"
)

// ProbeDiagnostics is the AG-038 self-diagnostics entry point on Windows. It
// marks the result Supported=true and delegates to the platform-neutral
// runDiagnosticsProbeReal orchestration (in diagnostics.go), which reads
// runtime config via the getProbeConfig seam and checks DNS reachability and
// TLS validity of the backend. Tests override the getProbeConfig and
// getLastPollLatencyMs seams to supply fixture values without invoking real
// network calls. Keeping the orchestration untagged means its logic also runs
// under the linux CI host (AG-036 build-tag lesson); this file holds only the
// Windows-platform Supported=true wiring.
func ProbeDiagnostics(ctx context.Context, now func() time.Time) DiagnosticsResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if now == nil {
		now = time.Now
	}
	return runDiagnosticsProbeReal(ctx, "", "")
}
