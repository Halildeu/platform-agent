//go:build windows

package certstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/google/certtostore"

	"platform-agent/internal/autoenroll"
)

// LoadEligibleCert opens LocalMachine\My, finds the first cert that
// matches the configured Issuers and Client Authentication EKU
// (certtostore default), applies the post-load CertFilter
// (Subject/SAN/validity), and returns the CertMaterial.
// ErrNoCertMatch is returned when no cert satisfies the filter; the
// runner translates that into the backoff/retry loop (Codex Q7 absorb).
//
// The returned tls.Certificate.PrivateKey is a *certtostore.Key, which
// implements crypto.Signer via NCryptSignHash. Non-exportable
// TPM-protected keys work unchanged — Codex F7 absorb.
func (p *Provider) LoadEligibleCert(ctx context.Context, filter autoenroll.CertFilter) (autoenroll.CertMaterial, error) {
	if err := ctx.Err(); err != nil {
		return autoenroll.CertMaterial{}, err
	}

	// Open the cert store under the Microsoft Platform Crypto Provider
	// (TPM-backed) container "" (default). Issuers list is taken from
	// the agent CertFilter so the operator can scope the lookup tightly
	// via env. An empty list means "no issuer narrowing" and the
	// certtostore lookup will return nil — the agent then surfaces
	// ErrNoCertMatch and waits for the operator to configure the issuer.
	store, err := certtostore.OpenWinCertStore(
		"Microsoft Platform Crypto Provider",
		"",
		filter.Issuers,
		nil,
		false,
	)
	if err != nil {
		return autoenroll.CertMaterial{}, fmt.Errorf("open LocalMachine\\My: %w", err)
	}
	defer func() { _ = store.Close() }()

	leaf, certCtx, err := store.CertWithContext()
	if err != nil {
		return autoenroll.CertMaterial{}, fmt.Errorf("query cert with context: %w", err)
	}
	if leaf == nil || certCtx == nil {
		return autoenroll.CertMaterial{}, autoenroll.ErrNoCertMatch
	}
	// FreeCertContext after we've acquired the signer; the signer keeps
	// the NCRYPT key handle so the cert context can be released safely.
	defer func() { _ = certtostore.FreeCertContext(certCtx) }()

	// Re-apply the full agent CertFilter in Go so the wire-time invariants
	// (EKU, SAN URI prefix, Subject suffix, validity window) hold even when
	// certtostore would otherwise accept a cert that only matched Issuer.
	eligible := autoenroll.FilterCandidates([]*x509.Certificate{leaf}, filter, time.Now())
	if len(eligible) == 0 {
		return autoenroll.CertMaterial{}, autoenroll.ErrNoCertMatch
	}

	signer, err := store.CertKey(certCtx)
	if err != nil {
		return autoenroll.CertMaterial{}, fmt.Errorf("acquire CNG signer: %w", err)
	}
	if signer == nil {
		return autoenroll.CertMaterial{}, fmt.Errorf("cert has no private key (non-exportable handle missing)")
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  signer,
		Leaf:        leaf,
	}

	return autoenroll.CertMaterial{
		TLSCertificate:   tlsCert,
		Leaf:             leaf,
		ThumbprintSHA256: autoenroll.ThumbprintSHA256Hex(leaf),
		ThumbprintSHA1:   autoenroll.ThumbprintSHA1Hex(leaf),
	}, nil
}
