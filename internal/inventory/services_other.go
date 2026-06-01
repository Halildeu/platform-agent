//go:build !windows

package inventory

import (
	"context"
	"time"
)

// ProbeServices is the non-Windows fail-closed stub. Returns
// supported=false + a UNSUPPORTED_PLATFORM probe error. Services list is
// empty (NOT all-allowlist entries with UNKNOWN) — Codex 019e8302 iter-2
// #4 absorb: a non-Windows runtime is "probe not supported" rather than
// "all services unknown".
func ProbeServices(ctx context.Context, now func() time.Time) ServicesResult {
	if now == nil {
		now = time.Now
	}
	startedAt := now()
	return orchestrateServicesProbe(
		ctx,
		now,
		false, // supported
		nil,   // services
		[]ServicesProbeError{{
			Code:    ServicesErrUnsupportedPlatform,
			Summary: "Critical services probe requires Windows",
		}},
		startedAt,
	)
}
