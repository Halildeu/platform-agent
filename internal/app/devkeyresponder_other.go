//go:build !windows

package app

import (
	"context"
	"errors"

	"platform-agent/internal/remotebridge/harness"
)

// newTPMDeviceKeyResponder refuses on non-Windows builds: the #548 device-key session strong path needs a real
// Windows TPM, so an explicitly enabled flag fails closed (refusing the bridge) rather than half-starting
// without a responder. The wiring itself is covered cross-platform via the deps.deviceKeyResponder test seam.
func newTPMDeviceKeyResponder(_ context.Context) (harness.DeviceKeyResponder, error) {
	return nil, errors.New("device-key session attestation requires a Windows TPM")
}
