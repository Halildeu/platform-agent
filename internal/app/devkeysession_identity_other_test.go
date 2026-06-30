//go:build !windows

package app

import (
	"context"
	"testing"

	"platform-agent/internal/config"
)

// On non-Windows, enabling the device-key session WITHOUT injecting BOTH a TLS config and
// a responder falls through to newTPMDeviceKeySessionIdentity, which refuses (no Windows
// TPM) — the bridge config fails closed rather than half-starting the strong path. Here
// neither is injected, so the build must error.
func TestRemoteBridgeDeviceKeySessionRefusesWithoutTPMOnNonWindows(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgeDeviceKeySessionEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgePermitBrokerPublicKeyB64 = testBrokerPermitPublicKeyB64
	cfg.RemoteBridgePermitKeyID = "kid-1"

	_, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{})
	if err == nil {
		t.Fatal("device-key session without a TPM (and no injected TLS/responder) must refuse on non-Windows")
	}
}
