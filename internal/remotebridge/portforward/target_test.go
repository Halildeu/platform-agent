package portforward

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// safeForwardAddr is the SSRF/pivot defense — it must refuse every address that is
// never a legitimate remote forward destination, even if a broker signed it.
func TestSafeForwardAddrCorpus(t *testing.T) {
	unsafe := []string{
		"127.0.0.1", "::1", // loopback
		"0.0.0.0", "::", // unspecified
		"169.254.1.1", "fe80::1", // link-local unicast
		"169.254.169.254",                 // cloud metadata (link-local unicast)
		"224.0.0.1", "ff02::1", "ff01::1", // multicast / interface-local multicast
		"255.255.255.255", // limited broadcast
		// IPv4-mapped IPv6 must not bypass IPv4 classification (Unmap):
		"::ffff:127.0.0.1", "::ffff:0.0.0.0", "::ffff:169.254.169.254", "::ffff:224.0.0.1", "::ffff:255.255.255.255",
		// documentation / benchmark ranges (never a real DC):
		"192.0.2.1", "198.51.100.10", "203.0.113.5", "198.18.0.1", "2001:db8::1",
		// IPv6 transition/translation mechanisms (default-deny):
		"64:ff9b::7f00:1", "64:ff9b:1::1", "2002::1", "2001::1",
	}
	for _, s := range unsafe {
		if err := safeForwardAddr(addr(s)); err == nil {
			t.Errorf("safeForwardAddr(%s) = nil, want refusal (never a legit DC target)", s)
		}
	}
	// a zoned address is rejected outright
	if err := safeForwardAddr(netip.MustParseAddr("fe80::1%eth0")); err == nil {
		t.Error("safeForwardAddr(zoned) = nil, want refusal")
	}
	safe := []string{
		"10.0.0.5", "192.168.1.10", "172.16.0.1", // RFC1918 (a real DC may be private)
		"8.8.8.8", "2001:4860:4860::8888", // global unicast
		"::ffff:10.0.0.5", // IPv4-mapped private is fine (unmaps to a safe v4)
	}
	for _, s := range safe {
		if err := safeForwardAddr(addr(s)); err != nil {
			t.Errorf("safeForwardAddr(%s) = %v, want safe (a DC can be here)", s, err)
		}
	}
}

func TestNewAllowlistValidation(t *testing.T) {
	good := Target{ID: "dc-1", Addr: addr("10.0.0.5"), Port: 389}
	cases := []struct {
		name    string
		targets []Target
	}{
		{"empty set", nil},
		{"empty id", []Target{{ID: "", Addr: addr("10.0.0.5"), Port: 389}}},
		{"duplicate id", []Target{good, {ID: "dc-1", Addr: addr("10.0.0.6"), Port: 389}}},
		{"invalid addr", []Target{{ID: "dc-1", Port: 389}}},
		{"port 0", []Target{{ID: "dc-1", Addr: addr("10.0.0.5"), Port: 0}}},
		{"signed loopback (SSRF at construction)", []Target{{ID: "dc-1", Addr: addr("127.0.0.1"), Port: 389}}},
		{"signed metadata", []Target{{ID: "dc-1", Addr: addr("169.254.169.254"), Port: 80}}},
		{"signed mapped loopback", []Target{{ID: "dc-1", Addr: addr("::ffff:127.0.0.1"), Port: 389}}},
		{"signed documentation range", []Target{{ID: "dc-1", Addr: addr("192.0.2.1"), Port: 389}}},
		{"signed limited broadcast", []Target{{ID: "dc-1", Addr: addr("255.255.255.255"), Port: 389}}},
	}
	for _, c := range cases {
		if _, err := NewAllowlist(c.targets, nil); err == nil {
			t.Errorf("NewAllowlist(%s) = nil error, want rejection", c.name)
		}
	}
	if _, err := NewAllowlist([]Target{good}, []uint16{88, 389, 445}); err != nil {
		t.Fatalf("NewAllowlist(valid) = %v, want ok", err)
	}
}

func TestDialUnknownTargetFailsClosed(t *testing.T) {
	a, err := NewAllowlist([]Target{{ID: "dc-1", Addr: addr("10.0.0.5"), Port: 389}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Dial(context.Background(), "nope", time.Second); !errors.Is(err, ErrTargetUnknown) {
		t.Fatalf("unknown target Dial err = %v, want ErrTargetUnknown", err)
	}
}

func TestDialPortNotAllowed(t *testing.T) {
	// port 445 signed, but the allowed set is {389} → refused BEFORE any dial.
	a, err := NewAllowlist([]Target{{ID: "dc-1", Addr: addr("10.0.0.5"), Port: 445}}, []uint16{389})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Dial(context.Background(), "dc-1", time.Second); !errors.Is(err, ErrPortNotAllowed) {
		t.Fatalf("port-not-allowed Dial err = %v, want ErrPortNotAllowed", err)
	}
}

// Dial resolves ONLY by id and connects to EXACTLY the signed addr:port. Built
// directly with a permissive guard (the construction + dial SSRF guard refuses the
// loopback test listener) to exercise the resolve→dial-exact mechanics.
func TestDialReachesExactSignedTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ap := netip.MustParseAddrPort(ln.Addr().String())

	a := &Allowlist{
		byID:  map[string]Target{"dc-1": {ID: "dc-1", Addr: ap.Addr(), Port: ap.Port()}},
		guard: func(netip.Addr) error { return nil }, // test seam: allow the loopback listener
	}

	accepted := make(chan struct{}, 1)
	go func() {
		if c, _ := ln.Accept(); c != nil {
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()

	conn, err := a.Dial(context.Background(), "dc-1", 2*time.Second)
	if err != nil {
		t.Fatalf("dial signed target: %v", err)
	}
	defer conn.Close()
	if conn.RemoteAddr().String() != ap.String() {
		t.Fatalf("dialed %s, want exactly the signed %s", conn.RemoteAddr(), ap)
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("listener never accepted (did not dial the exact target)")
	}
}

func TestResolve(t *testing.T) {
	a, err := NewAllowlist([]Target{{ID: "dc-1", Addr: addr("10.0.0.5"), Port: 389}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tgt, ok := a.Resolve("dc-1"); !ok || tgt.Port != 389 {
		t.Fatalf("Resolve(dc-1) = %+v, %v", tgt, ok)
	}
	if _, ok := a.Resolve("nope"); ok {
		t.Fatal("Resolve(unknown) must be ok=false")
	}
}

// NewAllowlist stores the canonical (unmapped) address, so the classified address
// equals the dialed address even when the broker signs an IPv4-mapped IPv6 form.
func TestNewAllowlistCanonicalizesMappedAddr(t *testing.T) {
	a, err := NewAllowlist([]Target{{ID: "dc-1", Addr: addr("::ffff:10.0.0.5"), Port: 389}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tgt, ok := a.Resolve("dc-1"); !ok || tgt.Addr.String() != "10.0.0.5" {
		t.Fatalf("stored addr = %v (ok=%v), want canonical 10.0.0.5", tgt.Addr, ok)
	}
}
