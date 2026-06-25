package devkeysession

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"
)

// White-box coverage of signBindingContext for BOTH device-key types the enrollment policy issues: RSA (the test
// mock) and EC P-256 (the production Windows TPM device key). The black-box Produce test only exercises the RSA
// mock, so the EC path — the real-hardware default — is proven here (Codex #548 step-6a REVISE).

func TestSignBindingContext_RSAProducesAVerifiableRSASSASignature(t *testing.T) {
	ctx := []byte("F22.6 binding context — rsa path")
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	sig, err := signBindingContext(key, ctx)
	if err != nil {
		t.Fatalf("signBindingContext(RSA): %v", err)
	}
	sigAlg, hashAlg, fields := parseTPMTSignature(t, sig)
	if sigAlg != 0x0014 { // ALG_RSASSA
		t.Fatalf("sigAlg = 0x%x, want RSASSA 0x0014", sigAlg)
	}
	if hashAlg != 0x000b { // ALG_SHA256
		t.Fatalf("hashAlg = 0x%x, want SHA256 0x000b", hashAlg)
	}
	if len(fields) != 1 {
		t.Fatalf("RSASSA TPMT_SIGNATURE must carry exactly one TPM2B, got %d", len(fields))
	}
	digest := sha256.Sum256(ctx)
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], fields[0]); err != nil {
		t.Fatalf("wrapped RSASSA signature must verify: %v", err)
	}
}

func TestSignBindingContext_ECProducesAVerifiableECDSASignature(t *testing.T) {
	ctx := []byte("F22.6 binding context — ec p-256 path (production windows tpm)")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec key: %v", err)
	}
	sig, err := signBindingContext(key, ctx)
	if err != nil {
		t.Fatalf("signBindingContext(EC): %v", err)
	}
	sigAlg, hashAlg, fields := parseTPMTSignature(t, sig)
	if sigAlg != 0x0018 { // ALG_ECDSA
		t.Fatalf("sigAlg = 0x%x, want ECDSA 0x0018", sigAlg)
	}
	if hashAlg != 0x000b {
		t.Fatalf("hashAlg = 0x%x, want SHA256 0x000b", hashAlg)
	}
	if len(fields) != 2 {
		t.Fatalf("ECDSA TPMT_SIGNATURE must carry R ‖ S (two TPM2B), got %d", len(fields))
	}
	if want := 32; len(fields[0]) != want || len(fields[1]) != want {
		t.Fatalf("P-256 R/S must be %d-byte fixed width, got R=%d S=%d", want, len(fields[0]), len(fields[1]))
	}
	digest := sha256.Sum256(ctx)
	r := new(big.Int).SetBytes(fields[0])
	s := new(big.Int).SetBytes(fields[1])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatalf("wrapped ECDSA signature must verify over sha256(ctx)")
	}
}

func TestSignBindingContext_NilSignerErrors(t *testing.T) {
	if _, err := signBindingContext(nil, []byte("ctx")); err == nil {
		t.Fatal("nil signer must error")
	}
}

// parseTPMTSignature reads sigAlg ‖ hashAlg ‖ then every remaining TPM2B field (the RSA sig, or ECDSA R then S).
func parseTPMTSignature(t *testing.T, sig []byte) (sigAlg, hashAlg int, fields [][]byte) {
	t.Helper()
	if len(sig) < 4 {
		t.Fatalf("TPMT_SIGNATURE too short: %d", len(sig))
	}
	p := 0
	u16 := func() int {
		v := int(binary.BigEndian.Uint16(sig[p:]))
		p += 2
		return v
	}
	sigAlg = u16()
	hashAlg = u16()
	for p < len(sig) {
		if p+2 > len(sig) {
			t.Fatalf("truncated TPM2B length at %d", p)
		}
		n := int(binary.BigEndian.Uint16(sig[p:]))
		p += 2
		if p+n > len(sig) {
			t.Fatalf("TPM2B overruns buffer (len=%d, remaining=%d)", n, len(sig)-p)
		}
		fields = append(fields, sig[p:p+n])
		p += n
	}
	return sigAlg, hashAlg, fields
}
