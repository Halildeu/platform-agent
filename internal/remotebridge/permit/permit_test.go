package permit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- cross-language vector (see testdata/README.md for provenance) ---

const (
	vectorKid      = "permit-key-2026-01"
	vectorDeviceID = "device-windows-7f3a"
	vectorNow      = int64(1780000100000) // inside [issuedAt, expiresAt)
)

func vectorPermit(t *testing.T) *Permit {
	t.Helper()
	return &Permit{
		Alg:                  "SHA256withECDSA",
		Kid:                  vectorKid,
		PermitVersion:        1,
		PolicyVersion:        "policy-v3",
		DecisionID:           "sess-0001:op-0001",
		SessionID:            "sess-0001",
		OperationID:          "op-0001",
		DeviceID:             vectorDeviceID,
		OperatorSubject:      "operator-1@example.com",
		Capability:           CapabilityConstrainedPTY,
		CommandHash:          "7063dece7cccf374d9fa1ee30ff23300fa42477e064e69be7bb6d01c0cfff682",
		IssuedAtEpochMillis:  1780000000000,
		ExpiresAtEpochMillis: 1780000300000,
		Seq:                  7,
		SignatureB64:         readTestdata(t, "vector-sig.b64"),
	}
}

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata %s: %v", name, err)
	}
	return strings.TrimSpace(string(b))
}

func vectorPublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(readTestdata(t, "broker-permit-pub.pem")))
	if block == nil {
		t.Fatal("no PEM block in broker-permit-pub.pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *ecdsa.PublicKey", pub)
	}
	return ec
}

func vectorVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(vectorPublicKey(t), vectorKid, vectorDeviceID)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// TestCanonicalPayloadMatchesJavaVector is the cross-language byte-compat
// gate: the Go layout must reproduce the EXACT bytes the real Java
// OperationPermit.canonicalPayload() produced for the same permit.
func TestCanonicalPayloadMatchesJavaVector(t *testing.T) {
	want := readTestdata(t, "vector-canonical.hex")
	got := hex.EncodeToString(vectorPermit(t).CanonicalPayload())
	if got != want {
		t.Fatalf("canonical payload diverged from the Java reference\n got=%s\nwant=%s", got, want)
	}
}

// TestVectorPermitVerifies proves the full path against broker-produced
// material: Java canonical bytes + openssl P-256 DER signature.
func TestVectorPermitVerifies(t *testing.T) {
	if !vectorVerifier(t).Verify(vectorPermit(t), vectorNow) {
		t.Fatal("known-good cross-language vector did not verify")
	}
}

// TestVerifyRejectsTamperedFields mutates every signed field (and the
// signature itself); each mutation must fail-closed.
func TestVerifyRejectsTamperedFields(t *testing.T) {
	v := vectorVerifier(t)
	mutations := map[string]func(p *Permit){
		"alg":             func(p *Permit) { p.Alg = "SHA384withECDSA" },
		"kid":             func(p *Permit) { p.Kid = "permit-key-2026-02" },
		"permitVersion":   func(p *Permit) { p.PermitVersion = 2 },
		"policyVersion":   func(p *Permit) { p.PolicyVersion = "policy-v4" },
		"decisionId":      func(p *Permit) { p.DecisionID = "sess-0001:op-0002" },
		"sessionId":       func(p *Permit) { p.SessionID = "sess-0002" },
		"operationId":     func(p *Permit) { p.OperationID = "op-0002" },
		"deviceId":        func(p *Permit) { p.DeviceID = "device-windows-0000" },
		"operatorSubject": func(p *Permit) { p.OperatorSubject = "operator-2@example.com" },
		"capability":      func(p *Permit) { p.Capability = CapabilityViewOnly },
		"commandHash": func(p *Permit) {
			p.CommandHash = "0000000000000000000000000000000000000000000000000000000000000000"
		},
		"issuedAt":  func(p *Permit) { p.IssuedAtEpochMillis++ },
		"expiresAt": func(p *Permit) { p.ExpiresAtEpochMillis-- },
		"seq":       func(p *Permit) { p.Seq++ },
		"signature": func(p *Permit) {
			sig, _ := base64.StdEncoding.DecodeString(p.SignatureB64)
			sig[len(sig)-1] ^= 0x01
			p.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
		},
	}
	for name, mutate := range mutations {
		p := vectorPermit(t)
		mutate(p)
		if v.Verify(p, vectorNow) {
			t.Errorf("tampered field %q still verified", name)
		}
	}
}

func TestFreshnessWindowHalfOpen(t *testing.T) {
	v := vectorVerifier(t)
	p := vectorPermit(t)
	cases := []struct {
		name string
		now  int64
		want bool
	}{
		{"before issuedAt", p.IssuedAtEpochMillis - 1, false},
		{"at issuedAt (inclusive)", p.IssuedAtEpochMillis, true},
		{"mid window", vectorNow, true},
		{"last valid milli", p.ExpiresAtEpochMillis - 1, true},
		{"at expiresAt (exclusive)", p.ExpiresAtEpochMillis, false},
		{"long expired", p.ExpiresAtEpochMillis + 60_000, false},
	}
	for _, c := range cases {
		if got := v.Verify(vectorPermit(t), c.now); got != c.want {
			t.Errorf("%s: Verify=%v want %v", c.name, got, c.want)
		}
	}
}

// --- self-signed (runtime keypair) invariant tests ---

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return key
}

func signPermit(t *testing.T, key *ecdsa.PrivateKey, p *Permit) *Permit {
	t.Helper()
	digest := sha256.Sum256(p.CanonicalPayload())
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	p.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
	return p
}

func basePermit(capability, commandHash string) *Permit {
	return &Permit{
		Alg:                  Alg,
		Kid:                  "kid-test",
		PermitVersion:        1,
		PolicyVersion:        "policy-v1",
		DecisionID:           "s-1:o-1",
		SessionID:            "s-1",
		OperationID:          "o-1",
		DeviceID:             "device-test",
		OperatorSubject:      "op@test",
		Capability:           capability,
		CommandHash:          commandHash,
		IssuedAtEpochMillis:  1_000,
		ExpiresAtEpochMillis: 2_000,
		Seq:                  0,
	}
}

func testVerifier(t *testing.T, key *ecdsa.PrivateKey) *Verifier {
	t.Helper()
	v, err := NewVerifier(&key.PublicKey, "kid-test", "device-test")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

const validHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestNonPilotCapabilityRejected(t *testing.T) {
	key := genKey(t)
	v := testVerifier(t, key)
	// Every non-pilot RemoteSessionCapability name, with and without a
	// command hash, even correctly broker-signed → default-deny.
	for _, capName := range []string{
		"FULL_RDP", "FILE_TRANSFER", "CLIPBOARD_SYNC", "CREDENTIAL_ENTRY",
		"ELEVATION", "PORT_FORWARD", "BACKGROUND_PERSISTENCE", "", "view_only",
	} {
		for _, hash := range []string{"", validHash} {
			p := signPermit(t, key, basePermit(capName, hash))
			if v.Verify(p, 1_500) {
				t.Errorf("non-pilot capability %q (hash=%q) verified", capName, hash)
			}
		}
	}
}

func TestCapabilityCommandHashConsistency(t *testing.T) {
	key := genKey(t)
	v := testVerifier(t, key)
	cases := []struct {
		name       string
		capability string
		hash       string
		want       bool
	}{
		{"PTY with valid hash", CapabilityConstrainedPTY, validHash, true},
		{"PTY without hash", CapabilityConstrainedPTY, "", false},
		{"PTY with UPPERCASE hash", CapabilityConstrainedPTY, strings.ToUpper(validHash), false},
		{"PTY with 63-char hash", CapabilityConstrainedPTY, validHash[:63], false},
		{"PTY with non-hex hash", CapabilityConstrainedPTY, strings.Repeat("g", 64), false},
		{"VIEW_ONLY clean", CapabilityViewOnly, "", true},
		{"VIEW_ONLY with hash", CapabilityViewOnly, validHash, false},
	}
	for _, c := range cases {
		p := signPermit(t, key, basePermit(c.capability, c.hash))
		if got := v.Verify(p, 1_500); got != c.want {
			t.Errorf("%s: Verify=%v want %v", c.name, got, c.want)
		}
	}
}

func TestDeviceBindingRejected(t *testing.T) {
	key := genKey(t)
	v := testVerifier(t, key)
	p := basePermit(CapabilityViewOnly, "")
	p.DeviceID = "some-other-device" // broker-signed for ANOTHER endpoint
	signPermit(t, key, p)
	if v.Verify(p, 1_500) {
		t.Fatal("permit bound to another device verified on this device")
	}
}

func TestStructuralRejections(t *testing.T) {
	key := genKey(t)
	v := testVerifier(t, key)
	// Mutate BEFORE signing: even a correctly broker-signed permit with the
	// structural violation must be refused.
	preSign := map[string]func(p *Permit){
		"wrong kid":         func(p *Permit) { p.Kid = "other-kid" },
		"wrong alg":         func(p *Permit) { p.Alg = "ED25519" },
		"permitVersion 0":   func(p *Permit) { p.PermitVersion = 0 },
		"permitVersion 2":   func(p *Permit) { p.PermitVersion = 2 },
		"negative seq":      func(p *Permit) { p.Seq = -1 },
		"inverted window":   func(p *Permit) { p.IssuedAtEpochMillis, p.ExpiresAtEpochMillis = 2_000, 1_000 },
		"zero-width window": func(p *Permit) { p.ExpiresAtEpochMillis = p.IssuedAtEpochMillis },
	}
	for name, mutate := range preSign {
		p := basePermit(CapabilityViewOnly, "")
		mutate(p)
		signPermit(t, key, p)
		if v.Verify(p, 1_500) {
			t.Errorf("%s: verified, want reject", name)
		}
	}
	// Mutate AFTER signing: the signature field itself degraded.
	postSign := map[string]func(p *Permit){
		"blank signature": func(p *Permit) { p.SignatureB64 = "   " },
		"invalid base64":  func(p *Permit) { p.SignatureB64 = "!!!not-base64!!!" },
	}
	for name, mutate := range postSign {
		p := signPermit(t, key, basePermit(CapabilityViewOnly, ""))
		mutate(p)
		if v.Verify(p, 1_500) {
			t.Errorf("%s: verified, want reject", name)
		}
	}
	if v.Verify(nil, 1_500) {
		t.Error("nil permit verified")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	signing := genKey(t)
	other := genKey(t)
	v, err := NewVerifier(&other.PublicKey, "kid-test", "device-test")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	p := signPermit(t, signing, basePermit(CapabilityViewOnly, ""))
	if v.Verify(p, 1_500) {
		t.Fatal("permit signed by a different key verified")
	}
}

func TestNewVerifierConstructionGuards(t *testing.T) {
	p256 := genKey(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	cases := []struct {
		name     string
		pub      *ecdsa.PublicKey
		kid, dev string
	}{
		{"nil key", nil, "kid", "dev"},
		{"P-384 key", &p384.PublicKey, "kid", "dev"},
		{"blank kid", &p256.PublicKey, "  ", "dev"},
		{"blank deviceID", &p256.PublicKey, "kid", ""},
	}
	for _, c := range cases {
		if _, err := NewVerifier(c.pub, c.kid, c.dev); err == nil {
			t.Errorf("%s: NewVerifier accepted, want error", c.name)
		}
	}
}
