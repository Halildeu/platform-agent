package tpmenroll

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// loadGoldenField decodes an arbitrary base64 field from the golden fixture
// (the typed goldenVector only carries the public-area fields).
func loadGoldenField(t *testing.T, field string) ([]byte, error) {
	t.Helper()
	raw, err := os.ReadFile("testdata/golden-rsa.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	v, ok := m[field]
	if !ok || v == "" {
		return nil, fmt.Errorf("no field %s", field)
	}
	return base64.StdEncoding.DecodeString(v)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// External oracle: NIST SP800-38A F.3.13/F.3.14 CFB128-AES128 vectors. Proves
// the hand-rolled cfb128 matches the standard (so it interoperates with the JDK
// "AES/CFB/NoPadding" backend layer and a real TPM) without the deprecated
// crypto/cipher CFB API.
func TestCFB128_NISTVectors(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	iv := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	pt := mustHex(t, "6bc1bee22e409f96e93d7e117393172a"+
		"ae2d8a571e03ac9c9eb76fac45af8e51"+
		"30c81c46a35ce411e5fbc1191a0a52ef"+
		"f69f2445df4f9b17ad2b417be66c3710")
	ct := mustHex(t, "3b3fd92eb72dad20333449f8e83cfb4a"+
		"c8a64537a0b3a93fcde3cdad9f1ce58b"+
		"26751f67a3cbb140b1808cf187a4f4df"+
		"c04b05357c5d1c0eeac4c66f9ff7f2e6")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfb128(block, iv, pt, false); !bytes.Equal(got, ct) {
		t.Fatalf("CFB128 encrypt:\n got  %x\n want %x", got, ct)
	}
	if got := cfb128(block, iv, ct, true); !bytes.Equal(got, pt) {
		t.Fatalf("CFB128 decrypt:\n got  %x\n want %x", got, pt)
	}
}

// cfb128 must handle a non-block-multiple length (the TPM2B(secret) is 18 bytes
// = one full block + a 2-byte partial), matching encrypt↔decrypt.
func TestCFB128_PartialFinalBlock(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	data := mustHex(t, "00112233445566778899aabbccddeeff0102") // 18 bytes
	enc := cfb128(block, make([]byte, 16), data, false)
	dec := cfb128(block, make([]byte, 16), enc, true)
	if !bytes.Equal(dec, data) {
		t.Fatalf("partial-block round-trip: got %x want %x", dec, data)
	}
}

// MakeCredential (server) ↔ ActivateCredential (device) round-trip: the device
// recovers exactly the server's secret. This exercises KDFa(STORAGE/INTEGRITY),
// OAEP(label "IDENTITY\0"), AES-128-CFB and the outer HMAC end-to-end. The AK
// Name that keys it is the golden ak.name (3a-1 proved it byte-exact), so this is
// the documented-algorithm round-trip; the cross-language interop vs the live
// backend Make is the deferred swtpm/integration test.
func TestMakeActivate_RoundTrip(t *testing.T) {
	g := loadGolden(t)
	akName := mustHex(t, g.AKNameHex)

	ek, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	secret := mustHex(t, "0102030405060708090a0b0c0d0e0f10") // 16 bytes
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	cred, err := MakeCredential(&ek.PublicKey, AlgSHA256, akName, secret, seed)
	if err != nil {
		t.Fatalf("make: %v", err)
	}
	// Structural conformance: credentialBlob = TPM2B(outerHMAC=32B) ‖ encIdentity(=18B for a 16B secret).
	if got := int(cred.CredentialBlob[0])<<8 | int(cred.CredentialBlob[1]); got != 32 {
		t.Fatalf("outer HMAC length = %d, want 32 (SHA-256)", got)
	}
	if len(cred.CredentialBlob) != 2+32+18 {
		t.Fatalf("credentialBlob len = %d, want %d", len(cred.CredentialBlob), 2+32+18)
	}
	if len(cred.EncSecret) != 256 { // RSA-2048 OAEP output
		t.Fatalf("encSecret len = %d, want 256", len(cred.EncSecret))
	}

	got, err := ActivateCredential(ek, AlgSHA256, akName, cred.CredentialBlob, cred.EncSecret)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("recovered secret %x != %x", got, secret)
	}
}

func TestActivate_FailsClosed(t *testing.T) {
	g := loadGolden(t)
	akName := mustHex(t, g.AKNameHex)
	ek, _ := rsa.GenerateKey(rand.Reader, 2048)
	secret := make([]byte, SecretBytes)
	seed := make([]byte, 32)
	cred, err := MakeCredential(&ek.PublicKey, AlgSHA256, akName, secret, seed)
	if err != nil {
		t.Fatal(err)
	}

	// Tampered outer HMAC → integrity failure.
	bad := bytes.Clone(cred.CredentialBlob)
	bad[5] ^= 0xFF
	if _, err := ActivateCredential(ek, AlgSHA256, akName, bad, cred.EncSecret); err == nil {
		t.Error("tampered credentialBlob must fail activation")
	}

	// Wrong AK Name → HMAC keyed differently → integrity failure.
	otherName := bytes.Clone(akName)
	otherName[len(otherName)-1] ^= 0xFF
	if _, err := ActivateCredential(ek, AlgSHA256, otherName, cred.CredentialBlob, cred.EncSecret); err == nil {
		t.Error("wrong akName must fail activation")
	}

	// Wrong EK private key → OAEP unwrap fails.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := ActivateCredential(other, AlgSHA256, akName, cred.CredentialBlob, cred.EncSecret); err == nil {
		t.Error("wrong EK key must fail activation")
	}

	// Wrong-size secret rejected at make.
	if _, err := MakeCredential(&ek.PublicKey, AlgSHA256, akName, make([]byte, 15), seed); err == nil {
		t.Error("15-byte secret must be rejected")
	}
}

// Sanity: the golden credBlob field is the tpm2-tools credential file
// (0xBADCC0DE header), NOT the raw wire idObject — documents why activate is
// round-trip-verified here, not golden-activated.
func TestGoldenCredBlobIsToolsFormat(t *testing.T) {
	raw, err := loadGoldenField(t, "credBlob")
	if err != nil {
		t.Skip("no credBlob in golden")
	}
	if len(raw) < 4 || raw[0] != 0xBA || raw[1] != 0xDC || raw[2] != 0xC0 || raw[3] != 0xDE {
		t.Fatalf("golden credBlob first bytes %x, expected tpm2-tools header 0xBADCC0DE", raw[:min(4, len(raw))])
	}
}
