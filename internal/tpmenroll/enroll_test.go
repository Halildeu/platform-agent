package tpmenroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeBackend is a faithful in-test stand-in for the endpoint-admin /nonce +
// /attest verifier: it issues a real MakeCredential challenge, then on /attest
// re-runs the checks the backend does (activation-secret match, quote-over-nonce,
// certify of the device key, the V12 DEVICE RSA-3072 floor, and the CSR PoP)
// before signing the device key with a throwaway CA. It proves the agent's
// Enroll orchestration produces a backend-acceptable envelope — the crypto itself
// is golden/NIST-verified in 3a-1..3a-5; this exercises the WIRE + sequencing.
type fakeBackend struct {
	t       *testing.T
	ca      *rsa.PrivateKey
	caCert  *x509.Certificate
	mu      sync.Mutex
	pending map[string]pendingNonce
	denials int
}

type pendingNonce struct {
	secret []byte
	nonce  []byte
}

func newFakeBackend(t *testing.T) *fakeBackend {
	ca, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-vault-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &ca.PublicKey, ca)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	return &fakeBackend{t: t, ca: ca, caCert: caCert, pending: map[string]pendingNonce{}}
}

func (b *fakeBackend) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent"+PathTPMNonce, b.nonce)
	mux.HandleFunc("/api/v1/agent"+PathTPMAttest, b.attest)
	return mux
}

func (b *fakeBackend) deny(w http.ResponseWriter, reason string) {
	b.mu.Lock()
	b.denials++
	b.mu.Unlock()
	b.t.Logf("backend deny: %s", reason)
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"status":"denied"}`))
}

func (b *fakeBackend) nonce(w http.ResponseWriter, r *http.Request) {
	var req NonceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		b.deny(w, "bad nonce request")
		return
	}
	ekRaw, _ := base64.StdEncoding.DecodeString(req.EKPub)
	ekPA, err := ParsePublicArea(ekRaw, true)
	if err != nil {
		b.deny(w, "bad ekPub")
		return
	}
	ekKey, _ := ekPA.PublicKey()
	akName, _ := base64.StdEncoding.DecodeString(req.AKName)

	secret := make([]byte, SecretBytes)
	nonce := make([]byte, 32)
	seed := make([]byte, 32)
	_, _ = rand.Read(secret)
	_, _ = rand.Read(nonce)
	_, _ = rand.Read(seed)
	cred, err := MakeCredential(ekKey.(*rsa.PublicKey), AlgSHA256, akName, secret, seed)
	if err != nil {
		b.deny(w, "make credential: "+err.Error())
		return
	}
	id := base64.StdEncoding.EncodeToString(nonce[:8])
	b.mu.Lock()
	b.pending[id] = pendingNonce{secret: secret, nonce: nonce}
	b.mu.Unlock()

	_ = json.NewEncoder(w).Encode(AttestChallenge{
		NonceID:   id,
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		CredBlob:  base64.StdEncoding.EncodeToString(cred.CredentialBlob),
		EncSecret: base64.StdEncoding.EncodeToString(cred.EncSecret),
	})
}

func (b *fakeBackend) attest(w http.ResponseWriter, r *http.Request) {
	var env AttestEnvelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		b.deny(w, "bad attest envelope")
		return
	}
	if env.Schema != SchemaV2 {
		b.deny(w, "bad schema")
		return
	}
	b.mu.Lock()
	pn, ok := b.pending[env.NonceID]
	delete(b.pending, env.NonceID) // single-use
	b.mu.Unlock()
	if !ok {
		b.deny(w, "unknown/used nonceId")
		return
	}

	dec := func(s string) []byte { v, _ := base64.StdEncoding.DecodeString(s); return v }

	// V10: recovered activation secret must equal the issued secret.
	if !bytes.Equal(dec(env.ActivatedSecret), pn.secret) {
		b.deny(w, "activation secret mismatch")
		return
	}
	akPA, err := ParsePublicArea(dec(env.AKPub), true)
	if err != nil {
		b.deny(w, "bad akPub")
		return
	}
	akKey, _ := akPA.PublicKey()
	akRSA := akKey.(*rsa.PublicKey)

	// V5: quote over the issued nonce, AK-signed.
	qInfo, err := ParseAttest(dec(env.Quote))
	if err != nil || !qInfo.IsQuote() || !bytes.Equal(qInfo.ExtraData, pn.nonce) {
		b.deny(w, "quote nonce/parse")
		return
	}
	if err := VerifyAttestSignature(akRSA, dec(env.Quote), dec(env.QuoteSig)); err != nil {
		b.deny(w, "quote sig")
		return
	}

	// V4: certify of the device key, AK-signed; certifiedName == device key Name.
	dkPA, err := ParsePublicArea(dec(env.DeviceKeyPub), true)
	if err != nil {
		b.deny(w, "bad deviceKeyPub")
		return
	}
	dkName, _ := dkPA.ComputeName()
	cInfo, err := ParseAttest(dec(env.CertifyInfo))
	if err != nil || !cInfo.IsCertify() || !bytes.Equal(cInfo.CertifiedName, dkName) {
		b.deny(w, "certify name/parse")
		return
	}
	if err := VerifyAttestSignature(akRSA, dec(env.CertifyInfo), dec(env.CertifySig)); err != nil {
		b.deny(w, "certify sig")
		return
	}

	// V12 DEVICE floor: RSA-3072+.
	dkKey, _ := dkPA.PublicKey()
	dkRSA := dkKey.(*rsa.PublicKey)
	if dkRSA.N.BitLen() < 3072 {
		b.deny(w, "device key below RSA-3072 floor")
		return
	}

	// V9: CSR PoP + CSR key == device key + requested EKU clientAuth.
	csr, err := x509.ParseCertificateRequest(dec(env.CSRDer))
	if err != nil || csr.CheckSignature() != nil {
		b.deny(w, "csr parse/pop")
		return
	}
	csrKey, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok || csrKey.N.Cmp(dkRSA.N) != 0 {
		b.deny(w, "csr key != device key")
		return
	}

	// Issue: sign the device key with the throwaway CA → clientAuth leaf.
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, b.caCert, csrKey, b.ca)
	if err != nil {
		b.deny(w, "issue: "+err.Error())
		return
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	_ = json.NewEncoder(w).Encode(AttestResponse{Certificate: string(pemCert)})
}

func TestEnroll_EndToEnd(t *testing.T) {
	backend := newFakeBackend(t)
	srv := httptest.NewServer(backend.handler())
	defer srv.Close()

	tpm, err := NewMockTPMDevice()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(srv.URL+"/api/v1/agent", srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	certPEM, err := client.Enroll(context.Background(), tpm, EnrollOptions{
		EnrollmentToken: "boot-token-xyz",
		DeviceRef:       "DESKTOP-MOCK-01",
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("issued cert is not PEM: %q", certPEM)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	// The issued cert binds the device key + clientAuth EKU.
	dkPub, _ := tpm.DeviceKey()
	dkPA, _ := ParsePublicArea(dkPub, true)
	dkKey, _ := dkPA.PublicKey()
	if leaf.PublicKey.(*rsa.PublicKey).N.Cmp(dkKey.(*rsa.PublicKey).N) != 0 {
		t.Fatal("issued cert public key != device key")
	}
	hasClientAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Error("issued cert missing clientAuth EKU")
	}
	if backend.denials != 0 {
		t.Errorf("backend denied %d times on the happy path", backend.denials)
	}
}

func TestEnroll_BackendDenySurfaces(t *testing.T) {
	// A backend that 403s every /nonce → Enroll must return an error, not panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"status":"denied"}`))
	}))
	defer srv.Close()
	tpm, _ := NewMockTPMDevice()
	client, _ := NewClient(srv.URL+"/api/v1/agent", srv.Client())
	if _, err := client.Enroll(context.Background(), tpm, EnrollOptions{EnrollmentToken: "t"}); err == nil {
		t.Fatal("expected enroll error on backend 403")
	}
}

func TestEnroll_DeviceKeyIs3072(t *testing.T) {
	tpm, _ := NewMockTPMDevice()
	dkPub, _ := tpm.DeviceKey()
	dkPA, _ := ParsePublicArea(dkPub, true)
	bits, _ := dkPA.KeyBits()
	if bits < 3072 {
		t.Fatalf("mock device key is %d bits, must be >= 3072 (V12 DEVICE floor)", bits)
	}
}

func TestNewClient_Validation(t *testing.T) {
	if _, err := NewClient("https://h/api", nil); err == nil {
		t.Error("nil http client must be rejected")
	}
	if _, err := NewClient("no-scheme", http.DefaultClient); err == nil {
		t.Error("scheme-less url must be rejected")
	}
	if _, err := NewClient("https://h/api?x=1", http.DefaultClient); err == nil {
		t.Error("url with query must be rejected")
	}
}

func TestBuildDeviceCSR(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 3072)
	der, err := buildDeviceCSR(key, "DESKTOP-X")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("CSR parse/PoP: %v", err)
	}
	if csr.Subject.CommonName != "DESKTOP-X" {
		t.Errorf("CN = %q", csr.Subject.CommonName)
	}
	foundEKU := false
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidExtKeyUsage) {
			foundEKU = true
		}
	}
	if !foundEKU {
		t.Error("CSR missing requested EKU extension")
	}
}
