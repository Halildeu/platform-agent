//go:build !windows

package inventory

import (
	"context"
	"time"
)

func ProbeOutdatedSoftware(ctx context.Context, now func() time.Time) OutdatedSoftwareResult {
	if now == nil {
		now = time.Now
	}
	return OutdatedSoftwareResult{
		SchemaVersion: OutdatedSoftwareSchemaVersion,
		Supported:     false,
		SourceUsed:    OutdatedSoftwareSourceNone,
		MaxUpgrade:    MaxOutdatedPackages,
		ProbeErrors: []OutdatedSoftwareProbeError{{
			Code:    OutdatedSoftwareErrUnsupportedPlatform,
			Summary: "Outdated software probe requires Windows with WinGet",
		}},
	}
}
