//go:build !windows

package inventory

import (
	"context"
	"time"
)

func ProbeDiagnostics(ctx context.Context, now func() time.Time) DiagnosticsResult {
	if now == nil {
		now = time.Now
	}
	return DiagnosticsResult{
		SchemaVersion: DiagnosticsSchemaVersion,
		Supported:     false,
		ProbeErrors: []DiagnosticsProbeError{{
			Code:    "UNSUPPORTED_PLATFORM",
			Summary: "Agent self-diagnostics probe requires Windows",
		}},
	}
}