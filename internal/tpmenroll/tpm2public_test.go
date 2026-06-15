package tpmenroll

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// golden mirrors the shared ground-truth swtpm vector
// (testdata/golden-rsa.json, copied from the backend's
// endpoint-admin-service test resources) — the SAME vector the backend
// verifier asserts against. Cross-checking the Go encoder against it proves the
// two sides agree byte-for-byte without a real TPM.
type goldenVector struct {
	Activate  string `json:"activate"`
	AKPub     string `json:"akPub"`
	EKPub     string `json:"ekPub"`
	DevkeyPub string `json:"devkeyPub"`
	AKNameHex string `json:"akNameHex"`
}

func loadGolden(t *testing.T) goldenVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/golden-rsa.json")
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	var g goldenVector
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parse golden fixture: %v", err)
	}
	if g.AKPub == "" || g.AKNameHex == "" {
		t.Fatal("golden fixture missing akPub/akNameHex")
	}
	return g
}

func b64d(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return b
}

// THE decisive cross-language check: ComputeName(akPub) MUST equal the
// TPM-emitted ak.name the backend validates (V11).
func TestComputeName_MatchesGoldenAkName(t *testing.T) {
	g := loadGolden(t)
	ak, err := ParsePublicArea(b64d(t, g.AKPub), true)
	if err != nil {
		t.Fatalf("parse akPub: %v", err)
	}
	gotHex, err := ak.ComputeNameHex()
	if err != nil {
		t.Fatalf("compute name: %v", err)
	}
	if gotHex != g.AKNameHex {
		t.Fatalf("akName mismatch:\n got  %s\n want %s", gotHex, g.AKNameHex)
	}
}

func TestParse_GoldenAkIsRestrictedSigningRSA2048(t *testing.T) {
	g := loadGolden(t)
	ak, err := ParsePublicArea(b64d(t, g.AKPub), true)
	if err != nil {
		t.Fatalf("parse akPub: %v", err)
	}
	if ak.Type() != AlgRSA {
		t.Errorf("type = 0x%x, want RSA 0x%x", ak.Type(), AlgRSA)
	}
	if ak.NameAlg() != AlgSHA256 {
		t.Errorf("nameAlg = 0x%x, want SHA256 0x%x", ak.NameAlg(), AlgSHA256)
	}
	if !ak.IsRestrictedSigningKey() {
		t.Error("akPub must be a restricted signing key (V11 shape)")
	}
	bits, err := ak.KeyBits()
	if err != nil {
		t.Fatalf("keyBits: %v", err)
	}
	if bits != 2048 {
		t.Errorf("keyBits = %d, want 2048", bits)
	}
}

// The device key is a NON-restricted signing key (it is the cert subject key,
// not an attestation key) — the resolver/verifier relies on this distinction.
func TestParse_GoldenDeviceKeyIsNotRestricted(t *testing.T) {
	g := loadGolden(t)
	if g.DevkeyPub == "" {
		t.Skip("golden has no devkeyPub")
	}
	dk, err := ParsePublicArea(b64d(t, g.DevkeyPub), true)
	if err != nil {
		t.Fatalf("parse devkeyPub: %v", err)
	}
	if dk.IsRestricted() {
		t.Error("device key must NOT be restricted")
	}
	pub, err := dk.PublicKey()
	if err != nil {
		t.Fatalf("device key PublicKey(): %v", err)
	}
	if rk, ok := pub.(*rsa.PublicKey); !ok || rk.N.BitLen() < 2048 {
		t.Errorf("device key = %T (want *rsa.PublicKey >=2048 bits)", pub)
	}
}

// MarshalTPM2B must round-trip the parsed area byte-for-byte (it retains the raw
// pubArea, so re-serialization equals the original TPM2B_PUBLIC).
func TestMarshalTPM2B_RoundTripsGolden(t *testing.T) {
	g := loadGolden(t)
	for _, tc := range []struct {
		name, b64 string
	}{
		{"akPub", g.AKPub},
		{"ekPub", g.EKPub},
		{"devkeyPub", g.DevkeyPub},
	} {
		if tc.b64 == "" {
			continue
		}
		raw := b64d(t, tc.b64)
		pa, err := ParsePublicArea(raw, true)
		if err != nil {
			t.Fatalf("%s parse: %v", tc.name, err)
		}
		got := pa.MarshalTPM2B()
		if len(got) != len(raw) {
			t.Fatalf("%s round-trip length %d != %d", tc.name, len(got), len(raw))
		}
		for i := range raw {
			if got[i] != raw[i] {
				t.Fatalf("%s round-trip byte %d differs", tc.name, i)
			}
		}
	}
}

func TestParse_RejectsTPM2BSizeMismatch(t *testing.T) {
	g := loadGolden(t)
	raw := b64d(t, g.AKPub)
	bad := make([]byte, len(raw))
	copy(bad, raw)
	bad[0] ^= 0xFF // corrupt the declared size prefix
	if _, err := ParsePublicArea(bad, true); err == nil {
		t.Fatal("expected size-mismatch rejection")
	}
}

func TestParse_RejectsTruncated(t *testing.T) {
	if _, err := ParsePublicArea([]byte{0x00, 0x02, 0x00}, true); err == nil {
		t.Fatal("expected truncation rejection")
	}
}

func TestRSAExponentInt_Guard(t *testing.T) {
	if got, err := rsaExponentInt(big.NewInt(65537)); err != nil || got != 65537 {
		t.Errorf("65537 should pass: got=%d err=%v", got, err)
	}
	if _, err := rsaExponentInt(big.NewInt(0)); err == nil {
		t.Error("zero exponent should be rejected")
	}
	if _, err := rsaExponentInt(big.NewInt(-3)); err == nil {
		t.Error("negative exponent should be rejected")
	}
	// 2^100 does not fit an int on any platform → rejected (the crafted-big.Int / 32-bit guard).
	if _, err := rsaExponentInt(new(big.Int).Lsh(big.NewInt(1), 100)); err == nil {
		t.Error("oversized exponent should be rejected")
	}
}

func TestComputeName_UnsupportedNameAlgRejected(t *testing.T) {
	// type(2)=RSA nameAlg(2)=0x0099 (unsupported) objectAttributes(4)=0 → 8 bytes.
	pa, err := ParsePublicArea([]byte{0x00, 0x01, 0x00, 0x99, 0x00, 0x00, 0x00, 0x00}, false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := pa.ComputeName(); err == nil {
		t.Fatal("expected unsupported-nameAlg error")
	}
}
