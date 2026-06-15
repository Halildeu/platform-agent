package tpmenroll

import (
	"bytes"
	"testing"
)

// GROUND TRUTH: the EK storage template reproduces the swtpm golden ekPub
// byte-for-byte from its modulus (the well-known authPolicy + AES-128-CFB sym
// block + NULL scheme are the TCG default RSA EK template).
func TestBuildRSAStorageEKPublicArea_ReproducesGoldenEK(t *testing.T) {
	g := loadGolden(t)
	rk := goldenModulus(t, g.EKPub)

	got, err := BuildRSAStorageEKPublicArea(rk.N)
	if err != nil {
		t.Fatalf("marshal EK: %v", err)
	}
	want := b64d(t, g.EKPub)
	if !bytes.Equal(got, want) {
		t.Fatalf("ekPub marshal mismatch:\n got  %x\n want %x", got, want)
	}
}

func TestBuildRSAStorageEKPublicArea_ParsesAsRestrictedDecrypt(t *testing.T) {
	g := loadGolden(t)
	rk := goldenModulus(t, g.EKPub)
	ekPub, err := BuildRSAStorageEKPublicArea(rk.N)
	if err != nil {
		t.Fatal(err)
	}
	pa, err := ParsePublicArea(ekPub, true)
	if err != nil {
		t.Fatalf("parse built EK: %v", err)
	}
	if !pa.IsRestricted() || !pa.IsDecrypt() || pa.IsSign() {
		t.Errorf("EK must be restricted decrypt (not sign): restricted=%v decrypt=%v sign=%v",
			pa.IsRestricted(), pa.IsDecrypt(), pa.IsSign())
	}
}
