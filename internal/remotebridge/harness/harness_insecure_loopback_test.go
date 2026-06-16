package harness

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
)

// The remote-bridge harness must refuse insecure plaintext (no TLS) to any
// non-loopback broker — machine-enforcing the "lab/loopback only" promise the
// config comments make, and mirroring the broker's own server-side
// non-loopback-plaintext refusal.

func TestNewRefusesInsecurePlaintextToNonLoopback(t *testing.T) {
	for _, addr := range []string{
		"broker.example.com:443",
		"mtls.testai.acik.com:443",
		"10.9.10.53:9444",
		"203.0.113.7:9444",
		"0.0.0.0:9444", // unspecified, not loopback
	} {
		_, err := New(Config{
			BrokerAddr:        addr,
			InsecurePlaintext: true,
			DeviceIDProvider:  func() string { return "device" },
		}, nil)
		if err == nil {
			t.Fatalf("New must refuse insecure plaintext to non-loopback %q", addr)
		}
		if !strings.Contains(err.Error(), "insecure plaintext") {
			t.Fatalf("addr %q: unexpected error %v", addr, err)
		}
	}
}

func TestNewAllowsInsecurePlaintextToLoopback(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:9444",
		"localhost:9444",
		"LOCALHOST:9444", // case-insensitive
		"[::1]:9444",
		"127.0.0.1", // bare host, no port
	} {
		h, err := New(Config{
			BrokerAddr:        addr,
			InsecurePlaintext: true,
			DeviceIDProvider:  func() string { return "device" },
		}, nil)
		if err != nil {
			t.Fatalf("New must allow insecure plaintext to loopback %q: %v", addr, err)
		}
		if h == nil {
			t.Fatalf("addr %q: nil harness", addr)
		}
	}
}

func TestNewAllowsTLSToNonLoopback(t *testing.T) {
	// TLS (InsecurePlaintext=false) to a remote broker is the normal path —
	// the guard only constrains the no-TLS case.
	h, err := New(Config{
		BrokerAddr:       "broker.example.com:443",
		DeviceIDProvider: func() string { return "device" },
	}, nil)
	if err != nil {
		t.Fatalf("TLS to a remote broker must be allowed: %v", err)
	}
	if h == nil {
		t.Fatal("nil harness")
	}
}

func TestNewAllowsInsecurePlaintextWithDialerOverride(t *testing.T) {
	// The bufconn test seam: a Dialer override means no real network dial, so
	// the loopback guard does not apply (in-process transport).
	h, err := New(Config{
		BrokerAddr:        "broker.example.com:443", // ignored when Dialer is set
		InsecurePlaintext: true,
		DeviceIDProvider:  func() string { return "device" },
		Dialer: func(context.Context) (*grpc.ClientConn, error) {
			return nil, context.Canceled
		},
	}, nil)
	if err != nil {
		t.Fatalf("a Dialer override must bypass the loopback guard: %v", err)
	}
	if h == nil {
		t.Fatal("nil harness")
	}
}

func TestIsLoopbackBrokerAddr(t *testing.T) {
	for _, a := range []string{
		"127.0.0.1:9444", "localhost:9444", "[::1]:9444",
		"127.0.0.1", "::1", "localhost", "127.5.6.7:80", // 127.0.0.0/8 is all loopback
	} {
		if !isLoopbackBrokerAddr(a) {
			t.Errorf("expected loopback: %q", a)
		}
	}
	for _, a := range []string{
		"broker.example.com:443", "10.0.0.1:9444", "203.0.113.7:9444",
		"example.com", "0.0.0.0:9444", "", "  ",
	} {
		if isLoopbackBrokerAddr(a) {
			t.Errorf("expected NON-loopback: %q", a)
		}
	}
}
