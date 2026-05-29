//go:build !windows

package inventory

import (
	"context"
	"runtime"
	"time"
)

// ProbeSecurityPosture — non-Windows stub. Returns the explicit
// "unsupported platform" shape: supported=false + probeComplete=false +
// single UNSUPPORTED_PLATFORM error. All boolean / count fields stay
// at their zero values; nullable fields stay nil. Caller MUST honor
// probeComplete before drawing conclusions.
func ProbeSecurityPosture(ctx context.Context, now func() time.Time) SecurityPostureResult {
	if now == nil {
		now = time.Now
	}
	start := now()
	result := SecurityPostureResult{
		SchemaVersion: SecurityPostureSchemaVersion,
		Supported:     false,
		ProbeErrors: []SecurityProbeError{
			{
				Code: SecurityProbeErrUnsupportedPlatform,
				Summary: "Security posture probe is not implemented for runtime " +
					runtime.GOOS,
			},
		},
	}
	deriveSecurityPostureSummary(&result)
	result.ProbeDurationMs = securityPostureElapsedMs(start, now)
	_ = ctx
	return result
}
