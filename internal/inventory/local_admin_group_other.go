//go:build !windows

package inventory

import (
	"context"
	"runtime"
	"time"
)

// ProbeLocalAdminGroup — non-Windows stub. Returns the explicit
// "unsupported platform" shape: supported=false + probeComplete=false +
// single UNSUPPORTED_PLATFORM error + sourceUsed=none. Members[]
// normalized to `[]` so the wire contract is honored on every
// platform.
func ProbeLocalAdminGroup(ctx context.Context, now func() time.Time) LocalAdminGroupResult {
	if now == nil {
		now = time.Now
	}
	start := now()
	result := LocalAdminGroupResult{
		SchemaVersion: LocalAdminGroupSchemaVersion,
		Supported:     false,
		SourceUsed:    LocalAdminSourceNone,
		MaxMembers:    maxLocalAdminMembers,
		ProbeErrors: []LocalAdminProbeError{
			{
				Source:  LocalAdminSourceNone,
				Code:    LocalAdminErrUnsupportedPlatform,
				Summary: "local administrators probe is not implemented for runtime " + runtime.GOOS,
			},
		},
	}
	deriveLocalAdminGroupSummary(&result)
	result.ProbeDurationMs = localAdminGroupElapsedMs(start, now)
	_ = ctx
	return result
}
