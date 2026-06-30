package app

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sync"

	"platform-agent/internal/mtls"
)

// buildDeviceKeySessionTLSConfig builds the remote-bridge mTLS client config for the
// Faz 22.6 #548 device-key strong path.
//
// The broker enforces TRIPLE-SPKI equality (attested device-key SPKI == LIVE mTLS leaf
// SPKI == persisted binding SPKI), so the transport leaf MUST be the agent's TPM device
// key. That key is a go-tpm deterministic transient primary — NOT a Windows CNG key — so
// it can never be an acquirable LocalMachine\My cert (the cert-store loader's
// requirement). The only correct binding is: the cert chain comes from the
// enrollment-issued PEM, and the private key is the supplied go-tpm-backed crypto.Signer.
//
// The leaf's public key is verified to equal the signer's public key (the agent-side
// half of the triple-SPKI check). A mismatch fails CLOSED with a re-enroll hint rather
// than presenting a leaf the broker will reject as device-key-leaf-binding-mismatch
// (e.g. a stale RSA cert from before the Vault role was fixed to EC).
func buildDeviceKeySessionTLSConfig(certPEM []byte, signer crypto.Signer, serverName string, minVersion uint16) (*tls.Config, error) {
	if signer == nil {
		return nil, errors.New("device-key session: nil device-key signer")
	}
	chain, err := parseCertChainPEM(certPEM)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]
	if err := assertSamePublicKey(leaf.PublicKey, signer.Public()); err != nil {
		return nil, fmt.Errorf("device-key session: issued cert does not match the TPM device key (re-enroll required): %w", err)
	}
	der := make([][]byte, len(chain))
	for i, c := range chain {
		der[i] = c.Raw
	}
	tlsCert := tls.Certificate{
		Certificate: der,
		PrivateKey:  signer,
		Leaf:        leaf,
	}
	return mtls.TLSConfigFor(mtls.Options{
		Cert:       tlsCert,
		ServerName: serverName,
		MinVersion: minVersion,
	})
}

// parseCertChainPEM decodes every CERTIFICATE block in order (leaf first). A PEM with no
// CERTIFICATE block means enrollment never wrote a device cert (e.g. the issuance leg
// failed) — fail closed with a re-enroll hint, never proceed with an empty chain.
func parseCertChainPEM(certPEM []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("device-key session: parse device cert: %w", err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, errors.New("device-key session: device cert PEM has no CERTIFICATE block (enrollment did not issue a cert — re-enroll required)")
	}
	return chain, nil
}

// assertSamePublicKey checks two public keys are equal using the standard library's
// per-key Equal method (ecdsa/rsa/ed25519 all implement Equal(crypto.PublicKey) bool).
func assertSamePublicKey(leaf, device crypto.PublicKey) error {
	type equaler interface{ Equal(x crypto.PublicKey) bool }
	le, ok := leaf.(equaler)
	if !ok {
		return errors.New("leaf public key type does not support equality comparison")
	}
	if !le.Equal(device) {
		return errors.New("leaf public key != device-key public key")
	}
	return nil
}

// lockedSigner serializes crypto.Signer calls under a shared mutex. The #548 device-key
// session uses ONE single-threaded go-tpm device for BOTH the mTLS handshake signer and
// the DeviceKeyChallenge responder; the shared mutex guarantees they never issue
// concurrent TPM operations (and never race the device Close on ctx end).
//
// Public() does not touch the TPM (the device public area is cached at creation) so it
// is not locked; the responder, when it holds the mutex, calls the UNDERLYING signer
// (tpm.DeviceKeySigner()) directly — never this wrapper — so there is no re-entrant lock.
type lockedSigner struct {
	inner crypto.Signer
	mu    *sync.Mutex
}

func (s *lockedSigner) Public() crypto.PublicKey { return s.inner.Public() }

func (s *lockedSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.Sign(rand, digest, opts)
}

var _ crypto.Signer = (*lockedSigner)(nil)
