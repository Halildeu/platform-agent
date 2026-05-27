// Package certstore loads the agent's machine certificate from the
// Windows LocalMachine\My certificate store. Non-Windows builds expose
// the same Provider type but always return ErrUnsupportedOS so the
// auto-enroll runner can compile and unit-test on darwin/linux while the
// production primitives stay Windows-only — Codex F7 + Q10 absorb.
//
// The Provider does NOT export the private key. It returns a
// tls.Certificate whose PrivateKey is a crypto.Signer that calls
// NCryptSignHash via CNG under the hood (provided by certtostore on
// Windows). This is the only safe way to use TPM-backed
// non-exportable AD CS certs in Go's crypto/tls.
package certstore

import (
	"platform-agent/internal/autoenroll"
)

// Provider satisfies autoenroll.CertProvider. The concrete type is the
// same on all platforms; the build tag selects between the Windows
// implementation (certtostore-backed) and the non-Windows stub.
type Provider struct{}

// New returns a fresh Provider. There is no global state to manage; the
// Windows backend opens and closes the cert store on every call so the
// runner can safely treat the Provider as immutable.
func New() autoenroll.CertProvider { return &Provider{} }
