package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"platform-agent/internal/config"
	"platform-agent/internal/tpmenroll"
)

// tpmBackendStub issues a real MakeCredential challenge for the agent's EK+AK
// (so the mock's ActivateCredential succeeds) and returns a canned cert. It tests
// the runTpmAutoEnroll ORCHESTRATION + persist; the full backend verification is
// covered in internal/tpmenroll's faithful-backend e2e.
func tpmBackendStub(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent"+tpmenroll.PathTPMNonce, func(w http.ResponseWriter, r *http.Request) {
		var req tpmenroll.NonceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ekRaw, _ := base64.StdEncoding.DecodeString(req.EKPub)
		ekPA, err := tpmenroll.ParsePublicArea(ekRaw, true)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		ekPub, _ := ekPA.PublicKey()
		akName, _ := base64.StdEncoding.DecodeString(req.AKName)
		secret := []byte("0123456789abcdef")
		seed := make([]byte, 32)
		cred, err := tpmenroll.MakeCredential(ekPub.(*rsa.PublicKey), tpmenroll.AlgSHA256, akName, secret, seed)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(tpmenroll.AttestChallenge{
			NonceID:   "n1",
			Nonce:     base64.StdEncoding.EncodeToString(make([]byte, 32)),
			CredBlob:  base64.StdEncoding.EncodeToString(cred.CredentialBlob),
			EncSecret: base64.StdEncoding.EncodeToString(cred.EncSecret),
		})
	})
	mux.HandleFunc("/api/v1/agent"+tpmenroll.PathTPMAttest, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(tpmenroll.AttestResponse{
			Certificate: "-----BEGIN CERTIFICATE-----\nMIIBmockissuedcert\n-----END CERTIFICATE-----\n",
		})
	})
	return mux
}

func TestRunTpmAutoEnrollWith_Success(t *testing.T) {
	srv := httptest.NewServer(tpmBackendStub(t))
	defer srv.Close()

	var captured string
	code := runTpmAutoEnrollWith(context.Background(),
		config.Config{EnrollmentToken: "boot-tok"},
		srv.URL+"/api/v1/agent",
		tpmEnrollDeps{
			newDevice:  func() (tpmenroll.TPMDevice, error) { return tpmenroll.NewMockTPMDevice() },
			httpClient: srv.Client(),
			persist:    func(certPEM string) error { captured = certPEM; return nil },
		})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(captured, "BEGIN CERTIFICATE") {
		t.Fatalf("issued cert not persisted: %q", captured)
	}
}

func TestRunTpmAutoEnrollWith_MissingAPIURL(t *testing.T) {
	code := runTpmAutoEnrollWith(context.Background(), config.Config{EnrollmentToken: "t"}, "", tpmEnrollDeps{
		newDevice: func() (tpmenroll.TPMDevice, error) { return tpmenroll.NewMockTPMDevice() },
	})
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (missing api-url)", code)
	}
}

func TestRunTpmAutoEnrollWith_MissingToken(t *testing.T) {
	code := runTpmAutoEnrollWith(context.Background(), config.Config{}, "https://h/api/v1/agent", tpmEnrollDeps{
		newDevice: func() (tpmenroll.TPMDevice, error) { return tpmenroll.NewMockTPMDevice() },
	})
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (missing token)", code)
	}
}

func TestRunTpmAutoEnrollWith_BackendDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"status":"denied"}`))
	}))
	defer srv.Close()
	code := runTpmAutoEnrollWith(context.Background(),
		config.Config{EnrollmentToken: "t"}, srv.URL+"/api/v1/agent",
		tpmEnrollDeps{
			newDevice:  func() (tpmenroll.TPMDevice, error) { return tpmenroll.NewMockTPMDevice() },
			httpClient: srv.Client(),
			persist:    func(string) error { return nil },
		})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (backend denied)", code)
	}
}
