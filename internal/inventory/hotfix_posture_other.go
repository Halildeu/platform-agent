//go:build !windows

package inventory

import (
	"context"
	"runtime"
	"time"
)

// ProbeHotfixPosture — non-Windows stub. Returns the explicit
// "unsupported platform" shape documented in hotfix_posture.go: a
// supported=false, probeComplete=false snapshot with a single
// UNSUPPORTED_PLATFORM error attributed to source="none" (no canonical
// query is even attempted on non-Windows). The caller MUST honor
// probeComplete before concluding "no pending updates" from this
// stub — there is no positive evidence, just an unrunnable probe.
//
// Mirrors AG-030/031/032/033/036/038 non-Windows stub discipline.
func ProbeHotfixPosture(ctx context.Context, now func() time.Time) HotfixPostureResult {
	if now == nil {
		now = time.Now
	}
	start := now()
	result := HotfixPostureResult{
		SchemaVersion:       HotfixPostureSchemaVersion,
		Supported:           false,
		ProbeComplete:       false,
		CollectedAt:         start.UTC(),
		InstalledSourceUsed: HotfixPostureSourceNone,
		PendingSourceUsed:   HotfixPostureSourceNone,
		HealthSourceUsed:    HotfixPostureSourceNone,
		AgentHealth: WindowsUpdateAgentHealth{
			WuaServiceState:  ServiceStateUnknown,
			BitsServiceState: ServiceStateUnknown,
		},
		ProbeErrors: []HotfixPostureProbeError{
			{
				Source: HotfixPostureSourceNone,
				Code:   HotfixPostureUnsupportedPlatform,
				Summary: "Hotfix posture probe is not implemented for runtime " +
					runtime.GOOS,
			},
		},
	}
	end := now()
	result.ProbeDurationMs = end.Sub(start).Milliseconds()
	if result.ProbeDurationMs < 0 {
		result.ProbeDurationMs = 0
	}
	// ctx is intentionally unused on the stub — there is nothing to
	// cancel.
	_ = ctx
	return result
}
