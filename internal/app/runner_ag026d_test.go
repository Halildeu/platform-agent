package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"platform-agent/internal/config"
	"platform-agent/internal/hmacstore"
	"platform-agent/internal/protocol"
)

// fakeCredStore is a memory-backed CredentialStore used to exercise the
// hydrate → enroll → persist → re-enroll branches without touching the
// Windows DPAPI store.
type fakeCredStore struct {
	stored        hmacstore.Credential
	hasStored     bool
	readErr       error
	writeErr      error
	invalidateErr error

	reads        int32
	writes       int32
	invalidates  int32
	lastInvalid  hmacstore.Credential
	invalidIface bool
}

func (f *fakeCredStore) Read(_ context.Context) (hmacstore.Credential, error) {
	atomic.AddInt32(&f.reads, 1)
	if f.readErr != nil {
		return hmacstore.Credential{}, f.readErr
	}
	if !f.hasStored {
		return hmacstore.Credential{}, hmacstore.ErrEmpty
	}
	return f.stored, nil
}

func (f *fakeCredStore) Write(_ context.Context, c hmacstore.Credential) error {
	atomic.AddInt32(&f.writes, 1)
	if f.writeErr != nil {
		return f.writeErr
	}
	f.stored = c
	f.hasStored = true
	return nil
}

func (f *fakeCredStore) Invalidate(_ context.Context) error {
	atomic.AddInt32(&f.invalidates, 1)
	f.invalidIface = true
	f.lastInvalid = f.stored
	if f.invalidateErr != nil {
		return f.invalidateErr
	}
	return nil
}

// TestRunnerHydratesFromStoreOnColdStart verifies the AG-026D cold-start
// path: when the persisted credential is present, the runner installs it
// on the protocol client BEFORE attempting to consume the enrollment
// token, so a fresh service restart does not waste a one-shot token or
// require operator intervention.
func TestRunnerHydratesFromStoreOnColdStart(t *testing.T) {
	store := &fakeCredStore{
		stored: hmacstore.Credential{
			DeviceID:        "device-srb",
			CredentialKeyID: "edc_abc",
			Secret:          "secret-srb",
			Issued:          time.Now(),
		},
		hasStored: true,
	}

	cfg := config.Default()
	cfg.APIURL = "https://example.invalid/api/v1/endpoint-agent"
	cfg.EnrollmentToken = "should-not-be-redeemed"

	client, err := protocol.NewClient(cfg.APIURL, "", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	r := NewRunner(cfg, client, nil)
	r.CredStore = store

	r.hydrateFromStore(context.Background())

	if !client.IsEnrolled() {
		t.Fatal("client must be enrolled after hydrate")
	}
	if client.CredentialID() != "edc_abc" {
		t.Errorf("credentialID = %q, want edc_abc", client.CredentialID())
	}
	if client.DeviceID() != "device-srb" {
		t.Errorf("deviceID = %q, want device-srb", client.DeviceID())
	}
	if r.Config.Secret != "secret-srb" {
		t.Error("Config.Secret not populated from store")
	}
	if atomic.LoadInt32(&store.invalidates) != 0 {
		t.Error("Read failure on hydrate path must NOT invalidate")
	}
}

// TestRunnerHydratePreservesBlobOnInvalid checks Codex 019e7314
// constraint #4: when the persisted blob fails Validate, the runner
// hydrates nothing AND keeps the blob in place — Invalidate is only
// triggered by an explicit operator/installer flow, never silently.
func TestRunnerHydratePreservesBlobOnInvalid(t *testing.T) {
	store := &fakeCredStore{readErr: hmacstore.ErrInvalid}

	cfg := config.Default()
	cfg.APIURL = "https://example.invalid/api/v1/endpoint-agent"
	client, err := protocol.NewClient(cfg.APIURL, "", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	r := NewRunner(cfg, client, nil)
	r.CredStore = store

	r.hydrateFromStore(context.Background())

	if client.IsEnrolled() {
		t.Fatal("client must NOT be enrolled when store returns ErrInvalid")
	}
	if atomic.LoadInt32(&store.invalidates) != 0 {
		t.Error("Invalidate must not be auto-called on ErrInvalid (Codex constraint #4)")
	}
}

// TestRunnerHydrateOnEmptyStoreSilent makes sure ErrEmpty on cold start
// produces no log noise and no Invalidate calls — the empty-store case is
// the first-run path and must be silent.
func TestRunnerHydrateOnEmptyStoreSilent(t *testing.T) {
	store := &fakeCredStore{hasStored: false}

	cfg := config.Default()
	cfg.APIURL = "https://example.invalid/api/v1/endpoint-agent"
	client, err := protocol.NewClient(cfg.APIURL, "", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	r := NewRunner(cfg, client, nil)
	r.CredStore = store

	r.hydrateFromStore(context.Background())

	if client.IsEnrolled() {
		t.Fatal("ErrEmpty must not enroll the client")
	}
	if atomic.LoadInt32(&store.invalidates) != 0 {
		t.Error("ErrEmpty must not Invalidate")
	}
}

// TestRunnerEnrollPersistsCredential verifies the AG-026D acceptance
// contract: a successful enroll triggers a single Write into the
// credential store with the response fields, and the in-memory client
// gets the same credential.
func TestRunnerEnrollPersistsCredential(t *testing.T) {
	store := &fakeCredStore{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/enrollments/consume") {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(protocol.EnrollResponse{
			DeviceID:        "device-srb",
			CredentialKeyID: "edc_abc",
			Secret:          "secret-srb",
			ServerTime:      time.Now().UTC(),
		})
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.APIURL = srv.URL + "/api/v1/endpoint-agent"
	cfg.EnrollmentToken = "fresh-token"
	client, err := protocol.NewClient(cfg.APIURL, "", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	r := NewRunner(cfg, client, nil)
	r.CredStore = store

	if err := r.enroll(context.Background()); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	if atomic.LoadInt32(&store.writes) != 1 {
		t.Errorf("Write calls = %d, want 1", store.writes)
	}
	if store.stored.DeviceID != "device-srb" || store.stored.CredentialKeyID != "edc_abc" {
		t.Errorf("persisted credential mismatch: %+v", store.stored)
	}
	if store.stored.Issued.IsZero() {
		t.Error("Issued timestamp must be set by enroll")
	}
	if !client.IsEnrolled() {
		t.Fatal("client must be enrolled after enroll")
	}
}

// TestRunnerReEnrollOn401ExactlyOnce verifies the AG-026D Codex 019e7314
// iter-1 must_fix #3 acceptance: when a persisted credential triggers a
// 401 on heartbeat, the runner runs exactly one re-enrollment, the new
// credential is persisted, the second heartbeat returns 2xx, and the
// store is never auto-Invalidated.
func TestRunnerReEnrollOn401ExactlyOnce(t *testing.T) {
	store := &fakeCredStore{
		stored: hmacstore.Credential{
			DeviceID:        "device-srb",
			CredentialKeyID: "edc_old",
			Secret:          "secret-old",
			Issued:          time.Now(),
		},
		hasStored: true,
	}

	var heartbeats, enrolls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/enrollments/consume"):
			atomic.AddInt32(&enrolls, 1)
			json.NewEncoder(w).Encode(protocol.EnrollResponse{
				DeviceID:        "device-srb",
				CredentialKeyID: "edc_new",
				Secret:          "secret-new",
				ServerTime:      time.Now().UTC(),
			})
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			n := atomic.AddInt32(&heartbeats, 1)
			if n == 1 {
				http.Error(w, `{"error":"Invalid credential"}`, http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(protocol.HeartbeatResponse{
				Accepted: true,
				DeviceID: "device-srb",
				Status:   "ENROLLED",
			})
		case strings.HasSuffix(r.URL.Path, "/commands/next"):
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.APIURL = srv.URL + "/api/v1/endpoint-agent"
	cfg.EnrollmentToken = "fresh-token"
	client, err := protocol.NewClient(cfg.APIURL, "", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	r := NewRunner(cfg, client, nil)
	r.CredStore = store

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if got := atomic.LoadInt32(&enrolls); got != 1 {
		t.Errorf("enroll calls = %d, want exactly 1", got)
	}
	if got := atomic.LoadInt32(&heartbeats); got != 2 {
		t.Errorf("heartbeat calls = %d, want exactly 2 (401 + 2xx)", got)
	}
	if atomic.LoadInt32(&store.invalidates) != 0 {
		t.Error("401 re-enroll path must NOT Invalidate the store (Codex constraint #4)")
	}
	if !store.hasStored || store.stored.CredentialKeyID != "edc_new" {
		t.Errorf("store must hold the new credential, got %+v", store.stored)
	}
	if client.CredentialID() != "edc_new" {
		t.Errorf("client credentialID = %q, want edc_new", client.CredentialID())
	}
}

// TestRunnerNoReEnrollWithoutToken verifies the AG-026D Codex 019e7314
// iter-1 must_fix #3: a 401 with NO enrollment token in env must
// surface the original 401 fail-closed and not delete the persisted
// blob.
func TestRunnerNoReEnrollWithoutToken(t *testing.T) {
	store := &fakeCredStore{
		stored: hmacstore.Credential{
			DeviceID:        "device-srb",
			CredentialKeyID: "edc_old",
			Secret:          "secret-old",
			Issued:          time.Now(),
		},
		hasStored: true,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/heartbeat") {
			http.Error(w, `{"error":"Invalid credential"}`, http.StatusUnauthorized)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.APIURL = srv.URL + "/api/v1/endpoint-agent"
	// No EnrollmentToken: re-enroll path is blocked, original 401 must surface.
	client, err := protocol.NewClient(cfg.APIURL, "", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	r := NewRunner(cfg, client, nil)
	r.CredStore = store

	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce must surface the 401 when no token is available for re-enroll")
	} else if !protocol.IsUnauthorized(err) {
		t.Errorf("error must remain 401-typed (got %v)", err)
	}
	if atomic.LoadInt32(&store.invalidates) != 0 {
		t.Error("401 with no token must NOT Invalidate the store")
	}
}

// TestRunnerHeartbeatAcceptedFalseFailClosed verifies the AG-026D Codex
// 019e7314 iter-1 must_fix #2: accepted=false MUST fail-closed and
// prevent command poll.
func TestRunnerHeartbeatAcceptedFalseFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/enrollments/consume"):
			json.NewEncoder(w).Encode(protocol.EnrollResponse{
				DeviceID:        "device-srb",
				CredentialKeyID: "edc_abc",
				Secret:          "secret-srb",
				ServerTime:      time.Now().UTC(),
			})
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			json.NewEncoder(w).Encode(protocol.HeartbeatResponse{
				Accepted: false,
				DeviceID: "device-srb",
				Status:   "REJECTED",
			})
		case strings.HasSuffix(r.URL.Path, "/commands/next"):
			t.Fatal("command poll must NOT run when heartbeat accepted=false")
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.APIURL = srv.URL + "/api/v1/endpoint-agent"
	cfg.EnrollmentToken = "fresh-token"
	client, err := protocol.NewClient(cfg.APIURL, "", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	r := NewRunner(cfg, client, nil)
	r.CredStore = &fakeCredStore{}

	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce must fail-closed on accepted=false")
	} else if !strings.Contains(err.Error(), "accepted=false") {
		t.Errorf("error must mention accepted=false, got %v", err)
	}
}

// TestRunnerHeartbeatDeviceMismatchFailClosed verifies the AG-026D
// Codex 019e7314 iter-1 must_fix #2: response.DeviceID different from
// r.Config.DeviceID MUST fail-closed.
func TestRunnerHeartbeatDeviceMismatchFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/enrollments/consume"):
			json.NewEncoder(w).Encode(protocol.EnrollResponse{
				DeviceID:        "device-srb",
				CredentialKeyID: "edc_abc",
				Secret:          "secret-srb",
				ServerTime:      time.Now().UTC(),
			})
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			json.NewEncoder(w).Encode(protocol.HeartbeatResponse{
				Accepted: true,
				DeviceID: "device-other",
				Status:   "ENROLLED",
			})
		case strings.HasSuffix(r.URL.Path, "/commands/next"):
			t.Fatal("command poll must NOT run on device mismatch")
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.APIURL = srv.URL + "/api/v1/endpoint-agent"
	cfg.EnrollmentToken = "fresh-token"
	client, err := protocol.NewClient(cfg.APIURL, "", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	r := NewRunner(cfg, client, nil)
	r.CredStore = &fakeCredStore{}

	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce must fail-closed on device mismatch")
	} else if !strings.Contains(err.Error(), "device_id mismatch") {
		t.Errorf("error must mention device_id mismatch, got %v", err)
	}
}

// TestRunnerEnrollSurvivesPersistFailure ensures Codex 019e7314 constraint:
// when the credential store write fails (ErrUnsupportedOS, ACL error,
// disk full), the runner still completes the enroll path with in-memory
// credentials. The next process restart will need a fresh enrollment
// token; the operator sees the sentinel log line.
func TestRunnerEnrollSurvivesPersistFailure(t *testing.T) {
	store := &fakeCredStore{writeErr: errors.New("simulated disk error")}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(protocol.EnrollResponse{
			DeviceID:        "device-srb",
			CredentialKeyID: "edc_abc",
			Secret:          "secret-srb",
			ServerTime:      time.Now().UTC(),
		})
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.APIURL = srv.URL + "/api/v1/endpoint-agent"
	cfg.EnrollmentToken = "fresh-token"
	client, err := protocol.NewClient(cfg.APIURL, "", nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	r := NewRunner(cfg, client, nil)
	r.CredStore = store

	if err := r.enroll(context.Background()); err != nil {
		t.Fatalf("enroll must not propagate persist failure: %v", err)
	}
	if !client.IsEnrolled() {
		t.Error("client must still be enrolled after persist failure (in-memory fallback)")
	}
}
