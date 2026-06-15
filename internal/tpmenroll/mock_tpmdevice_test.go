package tpmenroll

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// MockTPMDevice must satisfy the TPMDevice interface (compile-time).
var _ TPMDevice = (*MockTPMDevice)(nil)

func TestMockDevice_KeyShapes(t *testing.T) {
	m, err := NewMockTPMDevice()
	if err != nil {
		t.Fatal(err)
	}
	akPub, akName, err := m.AttestationKey()
	if err != nil {
		t.Fatal(err)
	}
	ak, err := ParsePublicArea(akPub, true)
	if err != nil {
		t.Fatalf("parse akPub: %v", err)
	}
	if !ak.IsRestrictedSigningKey() {
		t.Error("mock AK must be a restricted signing key")
	}
	wantName, _ := ak.ComputeName()
	if !bytes.Equal(akName, wantName) {
		t.Error("AttestationKey name != ComputeName(akPub)")
	}

	dkPub, err := m.DeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	dk, err := ParsePublicArea(dkPub, true)
	if err != nil {
		t.Fatalf("parse deviceKey: %v", err)
	}
	if dk.IsRestricted() {
		t.Error("mock device key must NOT be restricted")
	}

	ekPub, certDER, _, err := m.EndorsementKey()
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ParsePublicArea(ekPub, true)
	if err != nil {
		t.Fatalf("parse ekPub: %v", err)
	}
	if !ek.IsDecrypt() || ek.IsSign() {
		t.Error("mock EK must be a decrypt (not sign) key")
	}
	if len(certDER) == 0 {
		t.Error("mock EK cert missing")
	}
}

// Full enrollment-crypto flow against the mock: the test plays "backend"
// (MakeCredential), the mock activates, quotes, certifies, and signs — every leg
// the backend verifier checks (V10 activation, V5 quote-over-nonce, V4 certify of
// the device key, V9 CSR PoP) round-trips.
func TestMockDevice_FullEnrollmentFlow(t *testing.T) {
	m, err := NewMockTPMDevice()
	if err != nil {
		t.Fatal(err)
	}
	akPub, akName, _ := m.AttestationKey()
	ekPub, _, _, _ := m.EndorsementKey()
	ekPA, _ := ParsePublicArea(ekPub, true)
	ekKey, _ := ekPA.PublicKey()

	// --- backend leg 1: MakeCredential for (EK, AK Name) ---
	secret := make([]byte, SecretBytes)
	for i := range secret {
		secret[i] = byte(0xA0 + i)
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 3)
	}
	cred, err := MakeCredential(ekKey.(*rsa.PublicKey), AlgSHA256, akName, secret, seed)
	if err != nil {
		t.Fatalf("backend MakeCredential: %v", err)
	}

	// --- device: ActivateCredential (V10/V3) ---
	got, err := m.ActivateCredential(cred.CredentialBlob, cred.EncSecret)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("activated secret %x != %x", got, secret)
	}

	akPA, _ := ParsePublicArea(akPub, true)
	akKey, _ := akPA.PublicKey()

	// --- device: Quote over the nonce (V5) ---
	nonce := []byte("backend-issued-nonce-32-bytes-xx")
	sels := []PCRSelection{{HashAlg: AlgSHA256, Bitmap: []byte{0x03, 0x00, 0x00}}}
	qAttest, qSig, err := m.Quote(nonce, sels)
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	qInfo, err := ParseAttest(qAttest)
	if err != nil || !qInfo.IsQuote() || !bytes.Equal(qInfo.ExtraData, nonce) {
		t.Fatalf("quote attest bad: err=%v info=%+v", err, qInfo)
	}
	if err := VerifyAttestSignature(akKey.(*rsa.PublicKey), qAttest, qSig); err != nil {
		t.Fatalf("quote sig verify: %v", err)
	}

	// --- device: Certify the device key by the AK (V4) ---
	cAttest, cSig, err := m.CertifyDeviceKey([]byte("qualify"))
	if err != nil {
		t.Fatalf("certify: %v", err)
	}
	cInfo, err := ParseAttest(cAttest)
	if err != nil || !cInfo.IsCertify() {
		t.Fatalf("certify attest bad: %v", err)
	}
	dkPub, _ := m.DeviceKey()
	dkPA, _ := ParsePublicArea(dkPub, true)
	dkName, _ := dkPA.ComputeName()
	if !bytes.Equal(cInfo.CertifiedName, dkName) {
		t.Fatalf("certifiedName != device key Name")
	}
	if err := VerifyAttestSignature(akKey.(*rsa.PublicKey), cAttest, cSig); err != nil {
		t.Fatalf("certify sig verify: %v", err)
	}

	// --- device: CSR proof-of-possession over the device key (V9) ---
	signer := m.DeviceKeySigner()
	dkParsedKey, _ := dkPA.PublicKey()
	if signer.Public().(*rsa.PublicKey).N.Cmp(dkParsedKey.(*rsa.PublicKey).N) != 0 {
		t.Fatal("DeviceKeySigner public key != published device key")
	}
	digest := sha256.Sum256([]byte("csr-tbs"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("device key sign: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(signer.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("device key PoP verify: %v", err)
	}
}
