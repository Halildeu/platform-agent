package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// genSelfSignedEC returns a PEM-encoded self-signed EC P-256 cert and its key. The key
// stands in for the go-tpm device-key crypto.Signer (both emit ASN.1-DER ECDSA), so the
// cross-platform wiring (PEM parse + SPKI binding + tls.Config build) is exercised
// without a real TPM.
func genSelfSignedEC(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	return genSelfSignedECValidity(t, time.Unix(0, 0), time.Unix(1<<31-1, 0))
}

func genSelfSignedECValidity(t *testing.T, notBefore, notAfter time.Time) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}

func TestBuildDeviceKeySessionTLSConfig_Success(t *testing.T) {
	certPEM, key := genSelfSignedEC(t)
	cfg, err := buildDeviceKeySessionTLSConfig(certPEM, key, "broker.example", tls.VersionTLS12)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerName != "broker.example" {
		t.Errorf("ServerName = %q, want broker.example", cfg.ServerName)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want %#x", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must be false (fail-closed)")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates len = %d, want 1", len(cfg.Certificates))
	}
	if cfg.Certificates[0].PrivateKey == nil {
		t.Error("the TLS leaf must carry the device-key signer as its private key")
	}
	if cfg.Certificates[0].Leaf == nil {
		t.Error("Leaf must be populated so the harness can fingerprint it")
	}
}

func TestBuildDeviceKeySessionTLSConfig_SPKIMismatchFailsClosed(t *testing.T) {
	certPEM, _ := genSelfSignedEC(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	_, err = buildDeviceKeySessionTLSConfig(certPEM, otherKey, "broker.example", tls.VersionTLS12)
	if err == nil {
		t.Fatal("a leaf whose key != the device key must fail closed (device-key-leaf-binding-mismatch)")
	}
	if !strings.Contains(err.Error(), "re-enroll") {
		t.Errorf("error should hint re-enroll, got: %v", err)
	}
}

func TestBuildDeviceKeySessionTLSConfig_NoCertBlockFailsClosed(t *testing.T) {
	_, key := genSelfSignedEC(t)
	_, err := buildDeviceKeySessionTLSConfig([]byte("not a pem block"), key, "broker.example", tls.VersionTLS12)
	if err == nil {
		t.Fatal("a PEM with no CERTIFICATE block must fail closed (enrollment did not issue a cert)")
	}
	if !strings.Contains(err.Error(), "CERTIFICATE block") {
		t.Errorf("error should name the missing CERTIFICATE block, got: %v", err)
	}
}

func TestBuildDeviceKeySessionTLSConfig_ExpiredCertFailsClosed(t *testing.T) {
	// A device cert that expired well beyond the clock-skew leeway must fail closed with an
	// explicit re-enroll hint (the ~24h device cert otherwise dies with an opaque handshake error).
	notBefore := time.Now().Add(-48 * time.Hour)
	notAfter := time.Now().Add(-24 * time.Hour)
	certPEM, key := genSelfSignedECValidity(t, notBefore, notAfter)
	_, err := buildDeviceKeySessionTLSConfig(certPEM, key, "broker.example", tls.VersionTLS12)
	if err == nil {
		t.Fatal("an expired device cert must fail closed")
	}
	if !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "re-enroll") {
		t.Errorf("error should name expiry + re-enroll, got: %v", err)
	}
}

func TestBuildDeviceKeySessionTLSConfig_NotYetValidFailsClosed(t *testing.T) {
	notBefore := time.Now().Add(24 * time.Hour)
	notAfter := time.Now().Add(48 * time.Hour)
	certPEM, key := genSelfSignedECValidity(t, notBefore, notAfter)
	_, err := buildDeviceKeySessionTLSConfig(certPEM, key, "broker.example", tls.VersionTLS12)
	if err == nil {
		t.Fatal("a not-yet-valid device cert must fail closed")
	}
	if !strings.Contains(err.Error(), "not yet valid") {
		t.Errorf("error should name not-yet-valid, got: %v", err)
	}
}

func TestBuildDeviceKeySessionTLSConfig_EmptyServerNameFailsClosed(t *testing.T) {
	certPEM, key := genSelfSignedEC(t)
	if _, err := buildDeviceKeySessionTLSConfig(certPEM, key, "", tls.VersionTLS12); err == nil {
		t.Fatal("an empty server name must be rejected (no SNI to verify the broker)")
	}
}

func TestBuildDeviceKeySessionTLSConfig_NilSignerFailsClosed(t *testing.T) {
	certPEM, _ := genSelfSignedEC(t)
	if _, err := buildDeviceKeySessionTLSConfig(certPEM, nil, "broker.example", tls.VersionTLS12); err == nil {
		t.Fatal("a nil signer must be rejected")
	}
}

func TestLockedSignerDelegatesAndVerifies(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	mu := &sync.Mutex{}
	ls := &lockedSigner{inner: key, mu: mu}

	if !ls.Public().(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("lockedSigner.Public must return the inner public key")
	}

	digest := sha256.Sum256([]byte("F22.6 device-key session binding context"))
	sig, err := ls.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Fatal("lockedSigner.Sign must produce a verifiable ASN.1-DER ECDSA signature")
	}
}
