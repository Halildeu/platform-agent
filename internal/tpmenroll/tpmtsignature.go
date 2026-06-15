package tpmenroll

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// TPMT_SIGNATURE (TCG Part 2) for the AK's RSASSA quote/certify signatures:
//
//	sigAlg(UINT16) ‖ hashAlg(UINT16) ‖ signature(TPM2B_PUBLIC_KEY_RSA)
//
// The AK in this feature is an RSASSA restricted signing key (golden akPub), so
// RSASSA is the only scheme produced; the parser/verifier reject others
// fail-closed. ECDSA/RSAPSS verify branches are layered when a non-RSA AK is
// supported (the backend already parses them).

// MarshalRSASSASignature wraps a raw PKCS#1 v1.5 signature as a TPMT_SIGNATURE.
func MarshalRSASSASignature(hashAlg int, sig []byte) []byte {
	w := &tpmtWriter{}
	w.u16(AlgRSASSA)
	w.u16(hashAlg)
	w.tpm2b(sig)
	return w.b
}

// SignAttestRSASSA produces the AK's TPMT_SIGNATURE over a TPMS_ATTEST: PKCS#1
// v1.5 over H_nameAlg(attest) — the exact scheme the backend verifies (it feeds
// the raw attest to a "<hash>withRSA" JCA Signature, which hashes internally).
func SignAttestRSASSA(akPriv *rsa.PrivateKey, nameAlg int, attest []byte) ([]byte, error) {
	ch, err := cryptoHash(nameAlg)
	if err != nil {
		return nil, err
	}
	hh := ch.New()
	hh.Write(attest)
	sig, err := rsa.SignPKCS1v15(rand.Reader, akPriv, ch, hh.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("tpmenroll: AK sign: %w", err)
	}
	return MarshalRSASSASignature(nameAlg, sig), nil
}

// VerifyAttestSignature verifies a TPMT_SIGNATURE over a TPMS_ATTEST against the
// AK public key — used to round-trip our own output AND to cross-check the
// golden quote/certify signatures against the golden akPub. RSASSA only.
func VerifyAttestSignature(akPub *rsa.PublicKey, attest, tpmtSig []byte) error {
	if akPub == nil {
		return fmt.Errorf("tpmenroll: AK public key required")
	}
	c := &cursor{b: tpmtSig}
	sigAlg, err := c.u16("sigAlg")
	if err != nil {
		return err
	}
	if sigAlg != AlgRSASSA {
		return fmt.Errorf("tpmenroll: unsupported sigAlg 0x%x (RSASSA only)", sigAlg)
	}
	hashAlg, err := c.u16("hashAlg")
	if err != nil {
		return err
	}
	sig, err := c.tpm2b("rsa.sig")
	if err != nil {
		return err
	}
	if err := c.requireFullyConsumed(); err != nil {
		return err
	}
	ch, err := cryptoHash(hashAlg)
	if err != nil {
		return err
	}
	hh := ch.New()
	hh.Write(attest)
	if err := rsa.VerifyPKCS1v15(akPub, ch, hh.Sum(nil), sig); err != nil {
		return fmt.Errorf("tpmenroll: attest signature invalid: %w", err)
	}
	return nil
}

// cryptoHash maps a TPM nameAlg/hashAlg to its crypto.Hash. The SHA-2 family is
// registered via crypto/sha256 + crypto/sha512 (imported in makecredential.go),
// so crypto.Hash.New() is available.
func cryptoHash(alg int) (crypto.Hash, error) {
	switch alg {
	case AlgSHA256:
		return crypto.SHA256, nil
	case AlgSHA384:
		return crypto.SHA384, nil
	case AlgSHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("tpmenroll: unsupported hashAlg 0x%x", alg)
	}
}
