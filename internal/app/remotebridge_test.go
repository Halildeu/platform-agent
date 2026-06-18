package app

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"testing"

	"platform-agent/internal/config"
)

const testBrokerPermitPublicKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY7DAtgJHZjLaQdftKvXyhbbNlvYCmbuOjoxfTk5LII9UrdN/xZMmP43qQ6zJtERHS7PpBbIppbPMTNxcPk9aIQ=="

// The remote-bridge harness is disabled-by-default (ADR-0034 discipline):
// a default config must produce NO harness, NO goroutine, NO dial.
func TestStartRemoteBridgeDisabledByDefault(t *testing.T) {
	cfg := config.Default()
	if cfg.RemoteBridgeEnabled {
		t.Fatal("RemoteBridgeEnabled must default to false")
	}
	h := StartRemoteBridge(context.Background(), cfg, func() string { return "device" }, log.New(io.Discard, "", 0))
	if h != nil {
		t.Fatal("disabled remote-bridge flag still produced a harness")
	}
}

// Enabled-but-misconfigured (no broker address) refuses loudly instead of
// half-starting.
func TestStartRemoteBridgeRefusesWithoutBrokerAddr(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	h := StartRemoteBridge(context.Background(), cfg, func() string { return "device" }, log.New(io.Discard, "", 0))
	if h != nil {
		t.Fatal("enabled harness without a broker address must refuse init")
	}
}

func TestRemoteBridgeOperationDispatcherDisabledByDefault(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"

	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{})
	if err != nil {
		t.Fatalf("idle harness config should be valid without operation config: %v", err)
	}
	if hcfg.PTYDispatcher != nil {
		t.Fatal("remote-bridge PTY dispatcher must be disabled by default")
	}
	if hcfg.TLSConfig != nil {
		t.Fatal("idle harness should not require operation mTLS config")
	}
}

func TestRemoteBridgeOperationDispatcherWiringRequiresTrustConfig(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"

	_, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
	})
	if err == nil {
		t.Fatal("operation-capable remote bridge must require a broker permit public key and kid")
	}
}

func TestRemoteBridgeOperationDispatcherWiringRejectsPlaintext(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgeInsecurePlaintext = true
	cfg.RemoteBridgeBrokerAddr = "127.0.0.1:9444"
	cfg.RemoteBridgePermitBrokerPublicKeyB64 = testBrokerPermitPublicKeyB64
	cfg.RemoteBridgePermitKeyID = "kid-1"

	_, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
	})
	if err == nil {
		t.Fatal("operation-capable remote bridge must reject plaintext")
	}
}

func TestRemoteBridgeOperationDispatcherWiresStatefulPTY(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgePermitBrokerPublicKeyB64 = testBrokerPermitPublicKeyB64
	cfg.RemoteBridgePermitKeyID = "kid-1"

	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
	})
	if err != nil {
		t.Fatalf("operation harness config: %v", err)
	}
	if hcfg.PTYDispatcher == nil {
		t.Fatal("operation-capable remote bridge did not wire a PTY dispatcher")
	}
	if hcfg.TLSConfig == nil {
		t.Fatal("operation-capable remote bridge did not wire mTLS config")
	}
	dispatcher, ok := hcfg.PTYDispatcher.(*deviceBoundPTYDispatcher)
	if !ok {
		t.Fatalf("dispatcher type = %T, want *deviceBoundPTYDispatcher", hcfg.PTYDispatcher)
	}
	first, err := dispatcher.handlerFor("dev-1")
	if err != nil {
		t.Fatalf("first handler: %v", err)
	}
	second, err := dispatcher.handlerFor("dev-1")
	if err != nil {
		t.Fatalf("second handler: %v", err)
	}
	if first != second {
		t.Fatal("same device must reuse the stateful PTY handler so seq replay state is preserved")
	}
	rotated, err := dispatcher.handlerFor("dev-2")
	if err != nil {
		t.Fatalf("rotated handler: %v", err)
	}
	if rotated == first {
		t.Fatal("device identity change must rebuild the verifier-bound handler")
	}
}
