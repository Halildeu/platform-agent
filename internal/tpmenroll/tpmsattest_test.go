package tpmenroll

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"
)

func goldenAKPub(t *testing.T) *rsa.PublicKey {
	t.Helper()
	g := loadGolden(t)
	pa, err := ParsePublicArea(b64d(t, g.AKPub), true)
	if err != nil {
		t.Fatalf("parse akPub: %v", err)
	}
	pub, err := pa.PublicKey()
	if err != nil {
		t.Fatalf("akPub key: %v", err)
	}
	return pub.(*rsa.PublicKey)
}

// Cross-check: the REAL-TPM golden quote attest parses, its extraData is the
// golden nonce, and its golden signature VERIFIES against the golden akPub with
// our verifier — proving the parse + RSASSA verify match real-TPM output.
func TestGoldenQuote_ParsesAndVerifies(t *testing.T) {
	quote, err := loadGoldenField(t, "quoteAttest")
	if err != nil {
		t.Skip("no quoteAttest")
	}
	sig, _ := loadGoldenField(t, "quoteSig")
	nonceHex, err := loadGoldenString(t, "nonceHex")
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString(nonceHex)

	info, err := ParseAttest(quote)
	if err != nil {
		t.Fatalf("parse golden quote: %v", err)
	}
	if !info.IsQuote() {
		t.Fatalf("type = 0x%x, want QUOTE", info.Type)
	}
	if !bytes.Equal(info.ExtraData, nonce) {
		t.Fatalf("quote extraData %x != nonce %x", info.ExtraData, nonce)
	}
	if err := VerifyAttestSignature(goldenAKPub(t), quote, sig); err != nil {
		t.Fatalf("golden quoteSig must verify against golden akPub: %v", err)
	}
}

func TestGoldenCertify_ParsesAndVerifies(t *testing.T) {
	certify, err := loadGoldenField(t, "certifyAttest")
	if err != nil {
		t.Skip("no certifyAttest")
	}
	sig, _ := loadGoldenField(t, "certifySig")

	info, err := ParseAttest(certify)
	if err != nil {
		t.Fatalf("parse golden certify: %v", err)
	}
	if !info.IsCertify() {
		t.Fatalf("type = 0x%x, want CERTIFY", info.Type)
	}
	if len(info.CertifiedName) == 0 {
		t.Fatal("certify must carry a certifiedName")
	}
	if err := VerifyAttestSignature(goldenAKPub(t), certify, sig); err != nil {
		t.Fatalf("golden certifySig must verify against golden akPub: %v", err)
	}
}

// Produce side: marshal a CERTIFY attest, AK-sign it, then parse + verify — the
// device key's Name is carried as certifiedName (what the backend V4 binds).
func TestMarshalCertify_SignParseVerify_RoundTrip(t *testing.T) {
	ak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	akName := mustHex(t, loadGolden(t).AKNameHex)
	deviceName := mustHex(t, "000b"+"11"+hex.EncodeToString(make([]byte, 31))) // a 34-byte SHA-256 Name shape

	attest := MarshalCertifyAttest(akName, []byte("qual-data"), deviceName)
	sig, err := SignAttestRSASSA(ak, AlgSHA256, attest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	info, err := ParseAttest(attest)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !info.IsCertify() || !bytes.Equal(info.CertifiedName, deviceName) {
		t.Fatalf("certifiedName round-trip mismatch")
	}
	if err := VerifyAttestSignature(&ak.PublicKey, attest, sig); err != nil {
		t.Fatalf("self round-trip verify: %v", err)
	}
}

func TestMarshalQuote_SignParseVerify_RoundTrip(t *testing.T) {
	ak, _ := rsa.GenerateKey(rand.Reader, 2048)
	nonce := mustHex(t, "9d5e4c341e4071728a4e27ff9c146013ebc15b67")
	sels := []PCRSelection{{HashAlg: AlgSHA256, Bitmap: mustHex(t, "030000")}} // PCR 0,1
	pcrDigest := make([]byte, 32)

	attest := MarshalQuoteAttest(mustHex(t, loadGolden(t).AKNameHex), nonce, sels, pcrDigest)
	sig, err := SignAttestRSASSA(ak, AlgSHA256, attest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	info, err := ParseAttest(attest)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !info.IsQuote() || !bytes.Equal(info.ExtraData, nonce) {
		t.Fatalf("quote round-trip mismatch")
	}
	if len(info.PCRSelections) != 1 || info.PCRSelections[0].HashAlg != AlgSHA256 {
		t.Fatalf("pcrSelections round-trip mismatch: %+v", info.PCRSelections)
	}
	if err := VerifyAttestSignature(&ak.PublicKey, attest, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyAttest_FailsClosed(t *testing.T) {
	ak, _ := rsa.GenerateKey(rand.Reader, 2048)
	attest := MarshalCertifyAttest([]byte("ak"), []byte("x"), make([]byte, 34))
	sig, _ := SignAttestRSASSA(ak, AlgSHA256, attest)

	// Tampered attest → verify fails.
	bad := bytes.Clone(attest)
	bad[len(bad)-1] ^= 0xFF
	if err := VerifyAttestSignature(&ak.PublicKey, bad, sig); err == nil {
		t.Error("tampered attest must fail verify")
	}
	// Wrong AK → verify fails.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := VerifyAttestSignature(&other.PublicKey, attest, sig); err == nil {
		t.Error("wrong AK must fail verify")
	}
	// Non-RSASSA sigAlg rejected.
	if err := VerifyAttestSignature(&ak.PublicKey, attest, []byte{0x00, 0x18, 0x00, 0x0b, 0x00, 0x00}); err == nil {
		t.Error("ECDSA sigAlg must be rejected (RSASSA-only)")
	}
}

func TestParseAttest_Rejects(t *testing.T) {
	if _, err := ParseAttest([]byte{0x00, 0x00, 0x00, 0x00}); err == nil {
		t.Error("bad magic must be rejected")
	}
	if _, err := ParseAttest(nil); err == nil {
		t.Error("nil must be rejected")
	}
}
