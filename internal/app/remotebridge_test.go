package app

import (
	"context"
	"io"
	"log"
	"testing"

	"platform-agent/internal/config"
)

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
