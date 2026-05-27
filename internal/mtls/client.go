// Package mtls builds an http.Client that performs mutual-TLS handshakes
// for the auto-enroll wire (ADR-0029 Katman 3). The client is intentionally
// thin: it owns nothing but the TLS configuration and the timeout. Wire-
// level logic (paths, retries, token handling) lives in
// internal/autoenroll/client.go so the same http.Client can be reused across
// enroll, heartbeat, command poll, command result, and token refresh
// requests.
//
// Production builds use the OS trust store (RootCAs=nil → system roots; AD
// CS Enterprise Root arrives via GPO). Tests inject a custom *x509.CertPool
// so httptest servers can authenticate themselves to the client.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

// Options configures a mTLS client.
type Options struct {
	// Cert is the client certificate presented during the TLS handshake.
	// Cert.PrivateKey MUST satisfy crypto.Signer; on Windows the signer is
	// backed by CNG so non-exportable keys work — Codex F7 absorb.
	Cert tls.Certificate

	// RootCAs is the pool used to verify the server certificate. nil means
	// "use the OS trust store" — the production default. Tests pass a
	// pool that contains the httptest CA.
	RootCAs *x509.CertPool

	// ServerName is the SNI / hostname used for verification. It must
	// match the server cert's DNS SAN or CN. Required.
	ServerName string

	// Timeout is the per-request timeout for the returned http.Client.
	// Zero means "use 30s". The transport's own dial timeouts are derived
	// from this.
	Timeout time.Duration

	// MinVersion bounds the negotiated TLS version. Zero means TLS 1.2.
	// Set to tls.VersionTLS13 to require 1.3.
	MinVersion uint16
}

// NewClient returns a *http.Client configured for the auto-enroll mTLS wire.
// Errors out if Cert has no certificate bytes or ServerName is empty.
func NewClient(opts Options) (*http.Client, error) {
	if len(opts.Cert.Certificate) == 0 {
		return nil, fmt.Errorf("mtls: Options.Cert has no certificate bytes")
	}
	if opts.Cert.PrivateKey == nil {
		return nil, fmt.Errorf("mtls: Options.Cert has no private key")
	}
	if opts.ServerName == "" {
		return nil, fmt.Errorf("mtls: Options.ServerName is required")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	minVersion := opts.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{opts.Cert},
		RootCAs:            opts.RootCAs,
		ServerName:         opts.ServerName,
		MinVersion:         minVersion,
		InsecureSkipVerify: false, //nolint:gosec // explicit pin — fail-closed.
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

// TLSConfigFor is a test helper that exposes the TLS configuration the
// client would build, without constructing a transport. Production code
// should call NewClient.
func TLSConfigFor(opts Options) (*tls.Config, error) {
	if len(opts.Cert.Certificate) == 0 {
		return nil, fmt.Errorf("mtls: Options.Cert has no certificate bytes")
	}
	if opts.ServerName == "" {
		return nil, fmt.Errorf("mtls: Options.ServerName is required")
	}
	minVersion := opts.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{opts.Cert},
		RootCAs:            opts.RootCAs,
		ServerName:         opts.ServerName,
		MinVersion:         minVersion,
		InsecureSkipVerify: false, //nolint:gosec // explicit pin.
	}, nil
}
