//go:build windows

package tpmenroll

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"testing"
)

// TestWindowsTPMDevice_RealTPM exercises the FULL enrollment flow against the
// local hardware/firmware TPM (Windows TBS) and verifies every artifact with the
// SAME tpmenroll primitives the backend uses — the runtime proof that the go-tpm
// adapter produces backend-acceptable output. Gated by TPMENROLL_REAL_TPM=1 so it
// never runs in CI (no TPM); built with `go test -c` and run on the Win11 vTPM.
//
// Self-contained: it uses the TPM's own TPM2_MakeCredential to challenge its AK,
// then ActivateCredential to recover it (proving EK↔AK one-TPM + that our wire
// format round-trips). Cross-language MakeCredential (backend lib ↔ this TPM) is
// covered by the live-backend e2e (3c).
func TestWindowsTPMDevice_RealTPM(t *testing.T) {
	if os.Getenv("TPMENROLL_REAL_TPM") != "1" {
		t.Skip("set TPMENROLL_REAL_TPM=1 to run against the local TPM")
	}
	dev, err := NewWindowsTPMDevice()
	if err != nil {
		t.Fatalf("open device: %v", err)
	}
	defer dev.Close()

	// --- key shapes (parsed with the backend's parser) ---
	ekPub, _, _, err := dev.EndorsementKey()
	if err != nil {
		t.Fatal(err)
	}
	ekPA, err := ParsePublicArea(ekPub, true)
	if err != nil {
		t.Fatalf("parse EK: %v", err)
	}
	if !ekPA.IsDecrypt() || ekPA.IsSign() {
		t.Errorf("EK must be decrypt-not-sign")
	}

	akPub, akName, err := dev.AttestationKey()
	if err != nil {
		t.Fatal(err)
	}
	akPA, err := ParsePublicArea(akPub, true)
	if err != nil {
		t.Fatalf("parse AK: %v", err)
	}
	if !akPA.IsRestrictedSigningKey() {
		t.Error("AK must be a restricted signing key")
	}
	if name, _ := akPA.ComputeName(); string(name) != string(akName) {
		t.Error("AttestationKey name != ComputeName(akPub) — Name encoding mismatch")
	}
	akRSA := mustRSA(t, akPA)

	devPub, err := dev.DeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	devPA, err := ParsePublicArea(devPub, true)
	if err != nil {
		t.Fatalf("parse device key: %v", err)
	}
	// Device key is EC P-256 (meets the V12 "EC-P256+" floor; RSA-3072 is optional
	// and unsupported on many TPMs).
	if devPA.Type() != AlgECC {
		t.Errorf("device key type 0x%x, want ECC", devPA.Type())
	}
	if bits, _ := devPA.KeyBits(); bits < 256 {
		t.Errorf("device key %d bits, want >= 256 (EC)", bits)
	}
	if devPA.IsRestricted() {
		t.Error("device key must NOT be restricted")
	}

	// --- ActivateCredential (CROSS-LANGUAGE one-TPM proof): our backend lib
	//     (tpmenroll.MakeCredential) wraps a secret for THIS TPM's EK + AK Name;
	//     the REAL TPM recovers it via TPM2_ActivateCredential. This proves the
	//     backend's MakeCredential is byte-compatible with a real TPM ---
	ekRSA := mustRSA(t, ekPA)
	secret := []byte("0123456789abcdef") // 16 bytes
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	cred, err := MakeCredential(ekRSA, AlgSHA256, akName, secret, seed)
	if err != nil {
		t.Fatalf("backend MakeCredential: %v", err)
	}
	recovered, err := dev.ActivateCredential(cred.CredentialBlob, cred.EncSecret)
	if err != nil {
		t.Fatalf("ActivateCredential: %v", err)
	}
	if string(recovered) != string(secret) {
		t.Fatalf("activated secret %x != %x", recovered, secret)
	}

	// --- Quote over a nonce, verified with the backend's verifier ---
	nonce := []byte("real-tpm-nonce-0123456789abcdef!")
	qa, qs, err := dev.Quote(nonce, []PCRSelection{{HashAlg: AlgSHA256, Bitmap: []byte{0x03, 0x00, 0x00}}})
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	qi, err := ParseAttest(qa)
	if err != nil || !qi.IsQuote() || string(qi.ExtraData) != string(nonce) {
		t.Fatalf("quote attest: err=%v info=%+v", err, qi)
	}
	if err := VerifyAttestSignature(akRSA, qa, qs); err != nil {
		t.Fatalf("quote sig verify: %v", err)
	}

	// --- Certify the device key by the AK, verified with the backend's verifier ---
	ca, cs, err := dev.CertifyDeviceKey(nonce)
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}
	ci, err := ParseAttest(ca)
	if err != nil || !ci.IsCertify() {
		t.Fatalf("certify attest: %v", err)
	}
	if dn, _ := devPA.ComputeName(); string(ci.CertifiedName) != string(dn) {
		t.Fatal("certifiedName != device key Name")
	}
	if err := VerifyAttestSignature(akRSA, ca, cs); err != nil {
		t.Fatalf("certify sig verify: %v", err)
	}

	// --- Device key PoP (the CSR signature), EC P-256/ECDSA ---
	digest := sha256.Sum256([]byte("csr-tbs"))
	sig, err := dev.DeviceKeySigner().Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("device sign: %v", err)
	}
	devPub2, err := devPA.PublicKey()
	if err != nil {
		t.Fatalf("device public key: %v", err)
	}
	devEC, ok := devPub2.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("device key not ECDSA: %T", devPub2)
	}
	if !ecdsa.VerifyASN1(devEC, digest[:], sig) {
		t.Fatal("device PoP (ECDSA) verify failed")
	}

	t.Log("REAL-TPM full enrollment flow verified (EK/AK/device + activate + quote + certify + PoP)")
}

func mustRSA(t *testing.T, pa *PublicArea) *rsa.PublicKey {
	t.Helper()
	pub, err := pa.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("not RSA: %T", pub)
	}
	return k
}
