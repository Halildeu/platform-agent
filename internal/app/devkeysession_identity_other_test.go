//go:build !windows

package app

import (
	"context"
	"crypto/tls"
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

// The device-key session's mTLS leaf and responder must share one TPM, so the deps seams
// must be injected together — both or neither. Injecting only one must refuse before any
// TPM open (so a test can never pair an injected leaf with a different-keyed responder).
func TestRemoteBridgeDeviceKeySessionRequiresBothSeamsOrNeither(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgeDeviceKeySessionEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgePermitBrokerPublicKeyB64 = testBrokerPermitPublicKeyB64
	cfg.RemoteBridgePermitKeyID = "kid-1"

	// Only tlsConfig injected (no responder) → must refuse.
	_, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
	})
	if err == nil {
		t.Fatal("injecting only tlsConfig (no responder) for a device-key session must refuse (both-or-neither)")
	}
}
