//go:build !windows

package inventory

import (
	"context"
	"runtime"
	"time"
)

// ProbeOutdatedSoftware — non-Windows stub. Mirrors the AG-033
// device-health precedent (device_health_other.go): returns the
// explicit "unsupported platform" shape — Supported=false +
// ProbeComplete=false + a single UNSUPPORTED_PLATFORM error +
// SourceUsed=none, with Upgrade normalized to a non-nil empty slice
// (serializes as `[]`, never `null`, so consumers can iterate
// unconditionally) and MaxUpgrade + ProbeDurationMs surfaced so the
// wire contract holds on every platform. The probe error carries
// source=none.
func ProbeOutdatedSoftware(ctx context.Context, now func() time.Time) OutdatedSoftwareResult {
	if now == nil {
		now = time.Now
	}
	start := now()
	result := OutdatedSoftwareResult{
		SchemaVersion: OutdatedSoftwareSchemaVersion,
		Supported:     false,
		SourceUsed:    OutdatedSoftwareSourceNone,
		MaxUpgrade:    MaxOutdatedPackages,
		ProbeErrors: []OutdatedSoftwareProbeError{{
			Source:  OutdatedSoftwareSourceNone,
			Code:    OutdatedSoftwareErrUnsupportedPlatform,
			Summary: "outdated software probe is not implemented for runtime " + runtime.GOOS,
		}},
	}
	deriveOutdatedSoftwareSummary(&result)
	result.ProbeDurationMs = outdatedSoftwareElapsedMs(start, now)
	_ = ctx
	return result
}
