package autoenroll

import (
	"crypto/sha1" //nolint:gosec // SHA-1 is intentional for the diagnostic-only Windows UI cross-reference; SHA-256 is canonical.
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// ThumbprintSHA256Hex returns the lowercase hex SHA-256 of the cert's DER
// bytes. This is the canonical thumbprint for token binding and audit —
// Codex F10 absorb.
func ThumbprintSHA256Hex(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// ThumbprintSHA1Hex returns the lowercase hex SHA-1 of the cert's DER
// bytes. Diagnostic only — Windows MMC and certutil display SHA-1
// thumbprints; matching them helps an operator cross-reference the cert
// the agent is actually using.
func ThumbprintSHA1Hex(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha1.Sum(cert.Raw) //nolint:gosec // diagnostic only
	return hex.EncodeToString(sum[:])
}
