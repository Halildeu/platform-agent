//go:build !windows

package inventory

import (
	"context"
	"time"
)

// ProbeSecurityNetwork is the non-Windows fail-closed stub. It emits a
// structured unsupported block instead of omitting the probe when explicitly
// requested, so backend consumers can distinguish "not supported here" from
// "agent did not run this probe".
func ProbeSecurityNetwork(ctx context.Context, now func() time.Time) SecurityNetworkResult {
	if now == nil {
		now = time.Now
	}
	startedAt := now()
	return orchestrateSecurityNetworkProbe(
		ctx,
		now,
		false,
		nil,
		[]SecurityNetworkProbeError{{
			Code:    SecurityNetworkErrUnsupportedPlatform,
			Summary: securityNetworkSummaryPtr("Security/network probe requires Windows"),
		}},
		startedAt,
	)
}
