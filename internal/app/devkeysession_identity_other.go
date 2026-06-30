//go:build !windows

package app

import (
	"context"
	"crypto/tls"
	"errors"

	"platform-agent/internal/config"
	"platform-agent/internal/remotebridge/harness"
)

// newTPMDeviceKeySessionIdentity refuses on non-Windows builds: the #548 device-key
// session strong path needs a real Windows TPM (the device key is a go-tpm primary and
// the mTLS leaf must be signed by it). An explicitly enabled flag fails closed (refusing
// the bridge) rather than half-starting. The wiring is covered cross-platform via the
// deps.tlsConfig + deps.deviceKeyResponder test seams.
func newTPMDeviceKeySessionIdentity(_ context.Context, _ config.Config) (*tls.Config, harness.DeviceKeyResponder, error) {
	return nil, nil, errors.New("device-key session attestation requires a Windows TPM")
}
