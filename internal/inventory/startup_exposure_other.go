//go:build !windows

package inventory

import (
	"context"
	"time"
)

// ProbeStartupExposure is the non-Windows fail-closed stub. Returns
// supported=false + a UNSUPPORTED_PLATFORM probe error. StartupApps is
// empty (NOT a "we'd see these on Windows" placeholder list); RDP and
// firewall event-log scalars stay false because there is no analogue
// to read on non-Windows. Codex 019e8387 plan iter-1 P1 absorb: a
// non-Windows runtime is "probe not supported" rather than "no autorun
// entries observed" — the consumer MUST NOT infer "host is clean" from
// supported=false.
func ProbeStartupExposure(ctx context.Context, now func() time.Time) StartupExposureResult {
	if now == nil {
		now = time.Now
	}
	startedAt := now()
	return orchestrateStartupExposureProbe(
		ctx,
		now,
		false, // supported
		nil,   // startupApps
		false, // rdpEnabled
		false, // firewallEventLogEnabled
		[]StartupExposureProbeError{{
			Code:    StartupExposureErrUnsupportedPlatform,
			Summary: "Startup/exposure probe requires Windows",
		}},
		startedAt,
	)
}
