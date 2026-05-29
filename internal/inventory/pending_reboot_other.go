//go:build !windows

package inventory

import (
	"context"
	"runtime"
	"time"
)

// ProbePendingReboot — non-Windows stub. Returns the explicit
// "unsupported platform" shape documented in pending_reboot.go
// (Codex 019e749c iter-1 P0#2 absorb): supported=false +
// probeComplete=false + a single UNSUPPORTED_PLATFORM error, NOT
// silent empty. The pendingReboot bool stays false because there
// is no positive evidence — but the caller MUST honor probeComplete
// before concluding "no reboot needed".
func ProbePendingReboot(ctx context.Context, now func() time.Time) PendingRebootResult {
	if now == nil {
		now = time.Now
	}
	start := now()
	result := PendingRebootResult{
		SchemaVersion: PendingRebootSchemaVersion,
		Supported:     false,
		ProbeErrors: []PendingRebootProbeError{
			{
				Code: PendingRebootErrUnsupportedPlatform,
				Summary: "Pending reboot probe is not implemented for runtime " +
					runtime.GOOS,
			},
		},
	}
	derivePendingRebootSummary(&result)
	result.ProbeDurationMs = pendingRebootElapsedMs(start, now)
	_ = ctx
	return result
}
