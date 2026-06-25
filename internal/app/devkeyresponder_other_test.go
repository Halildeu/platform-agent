//go:build !windows

package app

import (
	"context"
	"crypto/tls"
	"testing"

	"platform-agent/internal/config"
)

// On non-Windows, enabling the device-key session WITHOUT injecting a responder falls through to
// newTPMDeviceKeyResponder, which refuses (no Windows TPM) — the bridge config fails closed rather than
// half-starting the strong path.
func TestRemoteBridgeDeviceKeySessionRefusesWithoutTPMOnNonWindows(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgeDeviceKeySessionEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgePermitBrokerPublicKeyB64 = testBrokerPermitPublicKeyB64
	cfg.RemoteBridgePermitKeyID = "kid-1"

	_, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
	})
	if err == nil {
		t.Fatal("device-key session without a TPM responder must refuse on non-Windows")
	}
}
