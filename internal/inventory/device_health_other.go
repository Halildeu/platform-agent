//go:build !windows

package inventory

import (
	"context"
	"runtime"
	"time"
)

// ProbeDeviceHealth — non-Windows stub. Returns the explicit
// "unsupported platform" shape: supported=false +
// probeComplete=false + single UNSUPPORTED_PLATFORM error +
// sourceUsed=none. FixedDisks normalized to `[]` and MaxFixedDisks
// surfaced so the wire contract holds on every platform.
func ProbeDeviceHealth(ctx context.Context, now func() time.Time) DeviceHealthResult {
	if now == nil {
		now = time.Now
	}
	start := now()
	result := DeviceHealthResult{
		SchemaVersion: DeviceHealthSchemaVersion,
		Supported:     false,
		SourceUsed:    DeviceHealthSourceNone,
		MaxFixedDisks: MaxFixedDisks,
		ProbeErrors: []DeviceHealthProbeError{
			{
				Source:  DeviceHealthSourceNone,
				Code:    DeviceHealthErrUnsupportedPlatform,
				Summary: "device health probe is not implemented for runtime " + runtime.GOOS,
			},
		},
	}
	deriveDeviceHealthSummary(&result)
	result.ProbeDurationMs = deviceHealthElapsedMs(start, now)
	_ = ctx
	return result
}
