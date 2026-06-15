package tpmenroll

import (
	"encoding/binary"
	"fmt"
	"math/big"
)

// tpmtWriter builds a TPMT_PUBLIC body big-endian (TCG Part 1 marshaling), the
// inverse of tpm2public.go's parser.
type tpmtWriter struct{ b []byte }

func (w *tpmtWriter) u16(v int) {
	var t [2]byte
	binary.BigEndian.PutUint16(t[:], uint16(v))
	w.b = append(w.b, t[:]...)
}
func (w *tpmtWriter) u32(v uint32) {
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], v)
	w.b = append(w.b, t[:]...)
}
func (w *tpmtWriter) tpm2b(p []byte) { w.u16(len(p)); w.b = append(w.b, p...) }

// wrapTPM2B prefixes a UINT16 size — turning a TPMT_PUBLIC body into a TPM2B_PUBLIC.
func wrapTPM2B(body []byte) []byte {
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(body)))
	copy(out[2:], body)
	return out
}

// Object-attribute templates for the signing keys the enrollment flow produces.
// These match the golden swtpm vectors (a restricted AK from `tpm2_createak` and
// a non-restricted device signing key) and are pinned in tpm2marshal_test.go.
const (
	// AKObjectAttributes: fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|restricted|sign (0x00050072).
	AKObjectAttributes uint32 = 0x00050072
	// DeviceKeyObjectAttributes: fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|sign (0x00060072,
	// the noDA bit set, NOT restricted — it is the cert subject key, not an attestation key).
	DeviceKeyObjectAttributes uint32 = 0x00060072
)

// BuildRSASigningPublicArea constructs a TPM2B_PUBLIC for an RSA signing key
// (symmetric=NULL, empty authPolicy, exponent field 0 → the TPM default 65537),
// the canonical form a TPM emits for an AK (`tpm2_createak`, restricted) and for
// a non-restricted device signing key. scheme is AlgRSASSA / AlgRSAPSS, or AlgNull
// (then schemeHash is omitted, as the TPM does). nameAlg is the Name hash
// (AlgSHA256 for this feature).
//
// Reproducing the golden akPub / devkeyPub byte-for-byte from their parsed
// modulus + attributes (tpm2marshal_test.go) is the ground-truth proof that this
// marshaler matches real-TPM output — the inverse direction of ParsePublicArea.
func BuildRSASigningPublicArea(modulus *big.Int, nameAlg int, objectAttributes uint32, scheme, schemeHash int) ([]byte, error) {
	if modulus == nil || modulus.Sign() <= 0 {
		return nil, fmt.Errorf("tpmenroll: positive RSA modulus required")
	}
	if _, err := newHash(nameAlg); err != nil {
		return nil, fmt.Errorf("tpmenroll: marshal nameAlg: %w", err)
	}
	if scheme != AlgNull && scheme != AlgRSASSA && scheme != AlgRSAPSS {
		return nil, fmt.Errorf("tpmenroll: unsupported RSA scheme 0x%x", scheme)
	}
	mod := modulus.Bytes() // big-endian, minimal — 256 bytes for a 2048-bit modulus
	keyBits := len(mod) * 8
	// Sane RSA range (Codex 019ec723 optional hardening): rejects a malformed
	// tiny/oversized modulus fail-closed, and keeps the body far under the u16
	// TPM2B size limit so the size prefix can never silently overflow. A valid
	// RSA modulus has its MSB set, so len(Bytes())*8 is the nominal key size.
	if keyBits < 2048 || keyBits > 16384 {
		return nil, fmt.Errorf("tpmenroll: implausible RSA key size %d bits", keyBits)
	}

	w := &tpmtWriter{}
	w.u16(AlgRSA)           // type
	w.u16(nameAlg)          // nameAlg
	w.u32(objectAttributes) // objectAttributes
	w.tpm2b(nil)            // authPolicy (empty for these templates)
	// TPMS_RSA_PARMS: symmetric ‖ scheme ‖ keyBits ‖ exponent
	w.u16(AlgNull) // symmetric = NULL (a signing key carries no symmetric block)
	w.u16(scheme)  // scheme.scheme
	if scheme != AlgNull {
		w.u16(schemeHash) // scheme.details.<sig>.hashAlg
	}
	w.u16(keyBits) // keyBits
	w.u32(0)       // exponent 0 → TPM default 65537 (the canonical encoding)
	w.tpm2b(mod)   // unique (modulus)

	return wrapTPM2B(w.b), nil
}
