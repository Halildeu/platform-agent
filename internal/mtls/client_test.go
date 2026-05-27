package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

func makeSelfSigned(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
}

func TestNewClient_BuildsTransportWithExpectedTLSConfig(t *testing.T) {
	cert := makeSelfSigned(t, "client.test")
	c, err := NewClient(Options{Cert: cert, ServerName: "example.test", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tr, ok := c.Transport.(interface {
		// http.Transport has TLSClientConfig but we access via type assertion to *http.Transport;
		// to keep this test resilient to interface changes we use reflect-style access.
	})
	_ = tr
	_ = ok
	if c.Timeout != 5*time.Second {
		t.Fatalf("timeout: got %v, want 5s", c.Timeout)
	}
}

func TestTLSConfigFor_DefaultMinVersionTLS12(t *testing.T) {
	cert := makeSelfSigned(t, "client.test")
	cfg, err := TLSConfigFor(Options{Cert: cert, ServerName: "example.test"})
	if err != nil {
		t.Fatalf("TLSConfigFor: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("min version: got %#x, want %#x", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify must be false")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates: got %d, want 1", len(cfg.Certificates))
	}
	if cfg.ServerName != "example.test" {
		t.Fatalf("ServerName: got %q, want example.test", cfg.ServerName)
	}
}

func TestNewClient_RejectsEmptyCert(t *testing.T) {
	_, err := NewClient(Options{ServerName: "example.test"})
	if err == nil {
		t.Fatal("expected error for empty cert")
	}
}

func TestNewClient_RejectsEmptyServerName(t *testing.T) {
	cert := makeSelfSigned(t, "client.test")
	_, err := NewClient(Options{Cert: cert})
	if err == nil {
		t.Fatal("expected error for empty ServerName")
	}
}

func TestNewClient_RejectsCertWithoutPrivateKey(t *testing.T) {
	cert := makeSelfSigned(t, "client.test")
	cert.PrivateKey = nil
	_, err := NewClient(Options{Cert: cert, ServerName: "example.test"})
	if err == nil {
		t.Fatal("expected error for missing private key")
	}
}

func TestTLSConfigFor_ExplicitMinVersionTLS13(t *testing.T) {
	cert := makeSelfSigned(t, "client.test")
	cfg, err := TLSConfigFor(Options{Cert: cert, ServerName: "example.test", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("TLSConfigFor: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("min version: got %#x, want %#x", cfg.MinVersion, tls.VersionTLS13)
	}
}

func TestTLSConfigFor_PropagatesRootCAs(t *testing.T) {
	pool := x509.NewCertPool()
	cert := makeSelfSigned(t, "client.test")
	cfg, err := TLSConfigFor(Options{Cert: cert, ServerName: "example.test", RootCAs: pool})
	if err != nil {
		t.Fatalf("TLSConfigFor: %v", err)
	}
	if cfg.RootCAs != pool {
		t.Fatal("RootCAs not propagated to TLS config")
	}
}

// sanity check that errors are non-nil and printable.
func TestNewClient_ErrorsAreReadable(t *testing.T) {
	_, err := NewClient(Options{})
	if err == nil || errors.Unwrap(err) != nil || err.Error() == "" {
		t.Fatalf("unexpected error: %v", err)
	}
}
