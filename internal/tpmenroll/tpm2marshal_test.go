package tpmenroll

import (
	"bytes"
	"crypto/rsa"
	"testing"
)

// goldenModulus parses one of the golden TPM2B_PUBLIC fixtures and returns its
// RSA modulus (the input to the marshaler).
func goldenModulus(t *testing.T, b64 string) *rsa.PublicKey {
	t.Helper()
	pa, err := ParsePublicArea(b64d(t, b64), true)
	if err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	pub, err := pa.PublicKey()
	if err != nil {
		t.Fatalf("golden PublicKey(): %v", err)
	}
	rk, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("golden key is %T, want RSA", pub)
	}
	return rk
}

// THE ground-truth proof: re-marshaling the golden AK's modulus + attributes
// MUST reproduce the real-TPM akPub byte-for-byte (the inverse of ParsePublicArea).
func TestBuildRSASigningPublicArea_ReproducesGoldenAK(t *testing.T) {
	g := loadGolden(t)
	rk := goldenModulus(t, g.AKPub)

	got, err := BuildRSASigningPublicArea(rk.N, AlgSHA256, AKObjectAttributes, AlgRSASSA, AlgSHA256)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := b64d(t, g.AKPub)
	if !bytes.Equal(got, want) {
		t.Fatalf("akPub marshal mismatch:\n got  %x\n want %x", got, want)
	}
}

// The device key is a non-restricted signing key with scheme=NULL — its golden
// encoding must also reproduce byte-for-byte.
func TestBuildRSASigningPublicArea_ReproducesGoldenDeviceKey(t *testing.T) {
	g := loadGolden(t)
	if g.DevkeyPub == "" {
		t.Skip("golden has no devkeyPub")
	}
	rk := goldenModulus(t, g.DevkeyPub)

	got, err := BuildRSASigningPublicArea(rk.N, AlgSHA256, DeviceKeyObjectAttributes, AlgNull, 0)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := b64d(t, g.DevkeyPub)
	if !bytes.Equal(got, want) {
		t.Fatalf("devkeyPub marshal mismatch:\n got  %x\n want %x", got, want)
	}
}

// marshal → parse → ComputeName must round-trip and reproduce the golden akName
// (ties the marshaler to the V11 Name the backend validates).
func TestBuildRSASigningPublicArea_RoundTripsToGoldenName(t *testing.T) {
	g := loadGolden(t)
	rk := goldenModulus(t, g.AKPub)

	built, err := BuildRSASigningPublicArea(rk.N, AlgSHA256, AKObjectAttributes, AlgRSASSA, AlgSHA256)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pa, err := ParsePublicArea(built, true)
	if err != nil {
		t.Fatalf("parse built: %v", err)
	}
	if !pa.IsRestrictedSigningKey() {
		t.Error("built AK must be a restricted signing key")
	}
	nameHex, err := pa.ComputeNameHex()
	if err != nil {
		t.Fatalf("compute name: %v", err)
	}
	if nameHex != g.AKNameHex {
		t.Fatalf("built akName %s != golden %s", nameHex, g.AKNameHex)
	}
}

func TestBuildRSASigningPublicArea_Rejects(t *testing.T) {
	g := loadGolden(t)
	rk := goldenModulus(t, g.AKPub)
	if _, err := BuildRSASigningPublicArea(nil, AlgSHA256, AKObjectAttributes, AlgRSASSA, AlgSHA256); err == nil {
		t.Error("nil modulus should be rejected")
	}
	if _, err := BuildRSASigningPublicArea(rk.N, 0x9999, AKObjectAttributes, AlgRSASSA, AlgSHA256); err == nil {
		t.Error("unsupported nameAlg should be rejected")
	}
	if _, err := BuildRSASigningPublicArea(rk.N, AlgSHA256, AKObjectAttributes, AlgECDSA, AlgSHA256); err == nil {
		t.Error("non-RSA scheme should be rejected")
	}
}
