package autoenroll

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"platform-agent/internal/commands"
	"platform-agent/internal/inventory"
	"platform-agent/internal/protocol"
	"platform-agent/internal/state"
)

// fakeCertProvider returns a CertMaterial built from the test PKI's
// client cert, with optional thumbprint override so renewal scenarios
// can simulate a fresh mint without re-issuing crypto material.
type fakeCertProvider struct {
	pki        *testPKI
	thumbprint string // overrides ThumbprintSHA256 when non-empty
	calls      atomic.Int32
}

func (f *fakeCertProvider) LoadEligibleCert(_ context.Context, _ CertFilter) (CertMaterial, error) {
	f.calls.Add(1)
	mat := CertMaterial{
		TLSCertificate:   f.pki.clientCert,
		Leaf:             f.pki.clientCert.Leaf,
		ThumbprintSHA256: ThumbprintSHA256Hex(f.pki.clientCert.Leaf),
		ThumbprintSHA1:   ThumbprintSHA1Hex(f.pki.clientCert.Leaf),
	}
	if f.thumbprint != "" {
		mat.ThumbprintSHA256 = f.thumbprint
	}
	return mat, nil
}

// fakeRegistry returns the configured values; calls are counted so tests
// can assert the runner queried the registry the right number of times.
type fakeRegistry struct {
	intMap    map[string]int
	stringMap map[string]string
	calls     atomic.Int32
}

func (r *fakeRegistry) ReadInt(key, value string, def int) int {
	r.calls.Add(1)
	if v, ok := r.intMap[key+"|"+value]; ok {
		return v
	}
	return def
}
func (r *fakeRegistry) ReadString(key, value, def string) string {
	r.calls.Add(1)
	if v, ok := r.stringMap[key+"|"+value]; ok {
		return v
	}
	return def
}

// requestRecorder captures requests by path with a mutex so concurrent
// goroutines do not race. Used to assert "AutoEnroll called N times".
type requestRecorder struct {
	mu  sync.Mutex
	hit map[string]int
}

func (r *requestRecorder) inc(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hit[path]++
}
func (r *requestRecorder) count(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hit[path]
}

// buildRunner constructs a Runner bound to the given httptest server +
// fakes. Returns the runner, the persisted store (for snapshot
// inspection), and the cert provider (to flip thumbprints between
// iterations).
func buildRunner(t *testing.T, pki *testPKI, srv *httptest.Server, registry *fakeRegistry, store ConfigStore, certProvider CertProvider) *Runner {
	t.Helper()
	cfg := Defaults()
	cfg.APIURL = srv.URL
	cfg.AgentVersion = "0.2.0-test"
	cfg.HTTPTimeout = 5 * time.Second
	cfg.CommandPollInterval = 50 * time.Millisecond
	cfg.CommandTimeout = 5 * time.Second
	cfg.TokenRefreshWindow = 2 * time.Hour
	tracker := state.NewTracker(state.StateStarting)
	executor := commands.NewLocalExecutor(inventory.RuntimeCapabilities(), cfg.AgentVersion)
	runner, err := NewRunner(cfg, certProvider, registry, store, executor, tracker, nil)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	// Replace mTLS http client with one that trusts the test CA + presents
	// the test client cert. Otherwise the runner's lazy build would call
	// loadCertWithBackoff successfully but the default mTLS pool would
	// reject the httptest server's CA.
	tlsClient, err := buildTestMTLSClient(pki)
	if err != nil {
		t.Fatalf("mtls test client: %v", err)
	}
	wire, err := NewClient(srv.URL, tlsClient)
	if err != nil {
		t.Fatalf("wire client: %v", err)
	}
	runner.httpClient = tlsClient
	runner.wireClient = wire
	// Mark the cert as already loaded so ensureCert sees no change.
	mat, _ := certProvider.LoadEligibleCert(context.Background(), cfg.CertFilter)
	runner.loadedCert = mat
	return runner
}

func buildTestMTLSClient(pki *testPKI) (*http.Client, error) {
	// Reuse the helper from client_test.go via the mtls package directly
	// is unnecessary; we replicate the small builder here.
	return testHTTPClient(pki), nil
}

// Standard handler that maps enrollment + heartbeat + commands + token
// refresh paths to configurable responses. recorder logs every hit.
type handlerConfig struct {
	autoEnroll    AutoEnrollResponse
	heartbeat     HeartbeatResponse
	heartbeatErr  int // status code, 0 == OK
	refresh       TokenRefreshResponse
	refreshErr    int
	commandStatus int // 204 default
	command       *protocol.AgentCommand
	commandResult []byte
}

func newTestServer(t *testing.T, pki *testPKI, cfg *handlerConfig, recorder *requestRecorder) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(PathAutoEnroll, func(w http.ResponseWriter, r *http.Request) {
		recorder.inc(PathAutoEnroll)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg.autoEnroll)
	})
	mux.HandleFunc(PathHeartbeat, func(w http.ResponseWriter, r *http.Request) {
		recorder.inc(PathHeartbeat)
		if cfg.heartbeatErr != 0 {
			w.WriteHeader(cfg.heartbeatErr)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg.heartbeat)
	})
	mux.HandleFunc(PathTokenRefresh, func(w http.ResponseWriter, r *http.Request) {
		recorder.inc(PathTokenRefresh)
		if cfg.refreshErr != 0 {
			w.WriteHeader(cfg.refreshErr)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg.refresh)
	})
	mux.HandleFunc(PathCommandsNext, func(w http.ResponseWriter, r *http.Request) {
		recorder.inc(PathCommandsNext)
		if cfg.command != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfg.command)
			return
		}
		status := cfg.commandStatus
		if status == 0 {
			status = http.StatusNoContent
		}
		w.WriteHeader(status)
	})
	mux.HandleFunc("/commands/", func(w http.ResponseWriter, r *http.Request) {
		recorder.inc("/commands/result")
		w.WriteHeader(http.StatusNoContent)
	})
	return startMTLSServer(t, pki, mux)
}

func TestRunner_FirstRun_EnrollsAndPersists(t *testing.T) {
	pki := setupTestPKI(t)
	recorder := &requestRecorder{hit: map[string]int{}}
	localThumb := ThumbprintSHA256Hex(pki.clientCert.Leaf)
	cfg := &handlerConfig{
		autoEnroll: AutoEnrollResponse{
			DeviceID:   "dev-1",
			Status:     StatusEnrolled,
			EnrolledAt: time.Now().UTC(),
			CertInfo:   AutoEnrollCertInfo{Thumbprint: localThumb},
		},
	}
	srv := newTestServer(t, pki, cfg, recorder)
	store := NewMemoryStore()
	provider := &fakeCertProvider{pki: pki}
	registry := &fakeRegistry{intMap: map[string]int{}, stringMap: map[string]string{}}

	runner := buildRunner(t, pki, srv, registry, store, provider)

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := recorder.count(PathAutoEnroll); got != 1 {
		t.Fatalf("AutoEnroll hits: got %d, want 1", got)
	}
	// ADR-0029 M2 tokenless: a successful enrollment must NOT fall through
	// to the token-dependent lifecycle (refresh / heartbeat / commands).
	if got := recorder.count(PathTokenRefresh); got != 0 {
		t.Fatalf("RefreshToken must not be called in tokenless mode; got %d", got)
	}
	if got := recorder.count(PathHeartbeat); got != 0 {
		t.Fatalf("Heartbeat must not be called in tokenless mode; got %d", got)
	}
	if got := recorder.count(PathCommandsNext); got != 0 {
		t.Fatalf("NextCommand must not be called in tokenless mode; got %d", got)
	}
	persisted, ok := store.Snapshot()
	if !ok {
		t.Fatal("expected persisted snapshot")
	}
	if persisted.DeviceID != "dev-1" {
		t.Fatalf("persisted device id mismatch: %+v", persisted)
	}
	if persisted.ServiceToken != "" {
		t.Fatalf("tokenless enrollment must persist NO service token; got %q", persisted.ServiceToken)
	}
	if !persisted.IsTokenlessEnrollment() {
		t.Fatalf("expected a tokenless enrollment record; got %+v", persisted)
	}
	if persisted.CertThumbprintSHA256 != localThumb {
		t.Fatalf("persisted thumbprint should bind the presented cert; got %q want %q", persisted.CertThumbprintSHA256, localThumb)
	}
}

func TestRunner_CertThumbprintChange_TriggersReissue(t *testing.T) {
	pki := setupTestPKI(t)
	recorder := &requestRecorder{hit: map[string]int{}}
	cfg := &handlerConfig{
		autoEnroll: AutoEnrollResponse{
			DeviceID:   "dev-1",
			Status:     StatusAlreadyEnrolled,
			EnrolledAt: time.Now().UTC(),
			CertInfo:   AutoEnrollCertInfo{Thumbprint: "new-thumbprint"},
		},
	}
	srv := newTestServer(t, pki, cfg, recorder)
	store := NewMemoryStore()
	// Prior tokenless enrollment whose AD CS cert has since rotated.
	_ = store.Write(context.Background(), PersistedConfig{
		DeviceID:             "dev-1",
		CertThumbprintSHA256: "old-thumbprint",
	})
	provider := &fakeCertProvider{pki: pki, thumbprint: "new-thumbprint"}
	registry := &fakeRegistry{intMap: map[string]int{}, stringMap: map[string]string{}}

	runner := buildRunner(t, pki, srv, registry, store, provider)
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := recorder.count(PathAutoEnroll); got != 1 {
		t.Fatalf("expected one AutoEnroll reissue, got %d", got)
	}
	if got := recorder.count(PathTokenRefresh); got != 0 {
		t.Fatalf("expected zero RefreshToken calls (reissue path), got %d", got)
	}
	persisted, _ := store.Snapshot()
	if persisted.CertThumbprintSHA256 != "new-thumbprint" {
		t.Fatalf("expected thumbprint rebind, got %q", persisted.CertThumbprintSHA256)
	}
	if persisted.ServiceToken != "" {
		t.Fatalf("tokenless reissue must persist NO service token, got %q", persisted.ServiceToken)
	}
}

func TestRunner_TokenExpiringTriggersRefresh(t *testing.T) {
	pki := setupTestPKI(t)
	recorder := &requestRecorder{hit: map[string]int{}}
	cfg := &handlerConfig{
		refresh: TokenRefreshResponse{
			ServiceToken:   "tok-2",
			TokenExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
		},
		heartbeat: HeartbeatResponse{Accepted: true, Status: "active", ServerTime: time.Now().UTC()},
	}
	srv := newTestServer(t, pki, cfg, recorder)
	store := NewMemoryStore()
	provider := &fakeCertProvider{pki: pki}
	// Pre-load the persisted snapshot with a token that expires in 30m
	// (inside the 2h refresh window) and the cert thumbprint matching the
	// provider, so reconcileEnrollment does NOT take the reissue path.
	mat, _ := provider.LoadEligibleCert(context.Background(), DefaultCertFilter())
	_ = store.Write(context.Background(), PersistedConfig{
		DeviceID:             "dev-1",
		ServiceToken:         "tok-1",
		TokenExpiresAt:       time.Now().Add(30 * time.Minute).UTC(),
		CertThumbprintSHA256: mat.ThumbprintSHA256,
	})
	registry := &fakeRegistry{intMap: map[string]int{}, stringMap: map[string]string{}}

	runner := buildRunner(t, pki, srv, registry, store, provider)
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := recorder.count(PathTokenRefresh); got != 1 {
		t.Fatalf("expected one RefreshToken call, got %d", got)
	}
	if got := recorder.count(PathAutoEnroll); got != 0 {
		t.Fatalf("expected zero AutoEnroll calls (refresh path), got %d", got)
	}
	persisted, _ := store.Snapshot()
	if persisted.ServiceToken != "tok-2" {
		t.Fatalf("expected token swap to tok-2, got %q", persisted.ServiceToken)
	}
}

func TestRunner_TokenExpired_TriggersReissue(t *testing.T) {
	pki := setupTestPKI(t)
	recorder := &requestRecorder{hit: map[string]int{}}
	localThumb := ThumbprintSHA256Hex(pki.clientCert.Leaf)
	cfg := &handlerConfig{
		autoEnroll: AutoEnrollResponse{
			DeviceID:   "dev-1",
			Status:     StatusAlreadyEnrolled,
			EnrolledAt: time.Now().UTC(),
			CertInfo:   AutoEnrollCertInfo{Thumbprint: localThumb},
		},
	}
	srv := newTestServer(t, pki, cfg, recorder)
	store := NewMemoryStore()
	provider := &fakeCertProvider{pki: pki}
	mat, _ := provider.LoadEligibleCert(context.Background(), DefaultCertFilter())
	// Legacy token-backed record (pre-tokenless migration) whose bearer has
	// already expired — reconcile must reissue (not refresh) and rewrite it
	// as a tokenless enrollment record.
	_ = store.Write(context.Background(), PersistedConfig{
		DeviceID:             "dev-1",
		ServiceToken:         "tok-1",
		TokenExpiresAt:       time.Now().Add(-time.Hour).UTC(), // already expired
		CertThumbprintSHA256: mat.ThumbprintSHA256,
	})
	registry := &fakeRegistry{intMap: map[string]int{}, stringMap: map[string]string{}}

	runner := buildRunner(t, pki, srv, registry, store, provider)
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := recorder.count(PathAutoEnroll); got != 1 {
		t.Fatalf("expected AutoEnroll reissue for expired token, got %d", got)
	}
	if got := recorder.count(PathTokenRefresh); got != 0 {
		t.Fatalf("expected zero RefreshToken calls (refresh on expired token is unsafe), got %d", got)
	}
	persisted, _ := store.Snapshot()
	if persisted.ServiceToken != "" || !persisted.IsTokenlessEnrollment() {
		t.Fatalf("expired legacy record should be rewritten tokenless; got %+v", persisted)
	}
}

func TestRunner_GraceWindowActive_LogsAndContinues(t *testing.T) {
	pki := setupTestPKI(t)
	recorder := &requestRecorder{hit: map[string]int{}}
	graceUntil := time.Now().Add(2 * time.Hour).UTC()
	cfg := &handlerConfig{
		heartbeat: HeartbeatResponse{
			Accepted:    true,
			Status:      "active",
			ServerTime:  time.Now().UTC(),
			GraceWindow: true,
			GraceUntil:  &graceUntil,
		},
	}
	srv := newTestServer(t, pki, cfg, recorder)
	store := NewMemoryStore()
	provider := &fakeCertProvider{pki: pki}
	mat, _ := provider.LoadEligibleCert(context.Background(), DefaultCertFilter())
	_ = store.Write(context.Background(), PersistedConfig{
		DeviceID:             "dev-1",
		ServiceToken:         "tok-1",
		TokenExpiresAt:       time.Now().Add(24 * time.Hour).UTC(),
		CertThumbprintSHA256: mat.ThumbprintSHA256,
	})
	registry := &fakeRegistry{intMap: map[string]int{}, stringMap: map[string]string{}}

	runner := buildRunner(t, pki, srv, registry, store, provider)
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
}

func TestRunner_GraceWindowExpired_FailsClosed(t *testing.T) {
	pki := setupTestPKI(t)
	recorder := &requestRecorder{hit: map[string]int{}}
	graceUntil := time.Now().Add(-time.Hour).UTC()
	cfg := &handlerConfig{
		heartbeat: HeartbeatResponse{
			Accepted:    true,
			Status:      "active",
			ServerTime:  time.Now().UTC(),
			GraceWindow: true,
			GraceUntil:  &graceUntil,
		},
	}
	srv := newTestServer(t, pki, cfg, recorder)
	store := NewMemoryStore()
	provider := &fakeCertProvider{pki: pki}
	mat, _ := provider.LoadEligibleCert(context.Background(), DefaultCertFilter())
	_ = store.Write(context.Background(), PersistedConfig{
		DeviceID:             "dev-1",
		ServiceToken:         "tok-1",
		TokenExpiresAt:       time.Now().Add(24 * time.Hour).UTC(),
		CertThumbprintSHA256: mat.ThumbprintSHA256,
	})
	registry := &fakeRegistry{intMap: map[string]int{}, stringMap: map[string]string{}}

	runner := buildRunner(t, pki, srv, registry, store, provider)
	err := runner.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected fail-closed error when grace window has expired")
	}
	if !runner.isFatal(err) {
		t.Fatalf("expected fatal error, got %v", err)
	}
}

func TestRunner_CorruptPersistedConfig_FailsClosed(t *testing.T) {
	pki := setupTestPKI(t)
	recorder := &requestRecorder{hit: map[string]int{}}
	cfg := &handlerConfig{
		heartbeat: HeartbeatResponse{Accepted: true, Status: "active", ServerTime: time.Now().UTC()},
	}
	srv := newTestServer(t, pki, cfg, recorder)
	store := NewMemoryStore()
	provider := &fakeCertProvider{pki: pki}
	// Pre-load persisted state that looks plausible (device_id + token
	// set) but is missing cert_thumbprint_sha256 — Codex F11 absorb: a
	// stale or hand-corrupted blob that would otherwise sail past
	// IsZero() and skip the renewal-rebind path.
	_ = store.Write(context.Background(), PersistedConfig{
		DeviceID:       "dev-1",
		ServiceToken:   "tok-1",
		TokenExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
		// CertThumbprintSHA256 deliberately empty.
	})
	registry := &fakeRegistry{intMap: map[string]int{}, stringMap: map[string]string{}}

	runner := buildRunner(t, pki, srv, registry, store, provider)
	err := runner.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected error from corrupted persisted config")
	}
	if !errors.Is(err, ErrInvalidPersistedConfig) {
		t.Fatalf("expected ErrInvalidPersistedConfig, got %v", err)
	}
	if got := recorder.count(PathCommandsNext); got != 0 {
		t.Fatalf("commands/next must NOT be polled when persisted is corrupt; got %d calls", got)
	}
	if got := recorder.count(PathHeartbeat); got != 0 {
		t.Fatalf("heartbeat must NOT be sent when persisted is corrupt; got %d calls", got)
	}
}

func TestRunner_AuthFailure_PropagatesAsFatal(t *testing.T) {
	pki := setupTestPKI(t)
	recorder := &requestRecorder{hit: map[string]int{}}
	cfg := &handlerConfig{
		heartbeatErr: http.StatusUnauthorized,
	}
	srv := newTestServer(t, pki, cfg, recorder)
	store := NewMemoryStore()
	provider := &fakeCertProvider{pki: pki}
	mat, _ := provider.LoadEligibleCert(context.Background(), DefaultCertFilter())
	_ = store.Write(context.Background(), PersistedConfig{
		DeviceID:             "dev-1",
		ServiceToken:         "tok-1",
		TokenExpiresAt:       time.Now().Add(24 * time.Hour).UTC(),
		CertThumbprintSHA256: mat.ThumbprintSHA256,
	})
	registry := &fakeRegistry{intMap: map[string]int{}, stringMap: map[string]string{}}

	runner := buildRunner(t, pki, srv, registry, store, provider)
	err := runner.RunOnce(context.Background())
	if !errors.Is(err, ErrAuthFailure) {
		t.Fatalf("expected ErrAuthFailure, got %v", err)
	}
	if !runner.isFatal(err) {
		t.Fatalf("expected fatal classification, got %v", err)
	}
}

// testHTTPClient builds the mTLS *http.Client used by the runner under
// test. It mirrors buildTestMTLSClient but lives here to keep the helper
// reachable from both client_test.go and runner_test.go without
// re-importing the mtls package alias in two places.
func testHTTPClient(pki *testPKI) *http.Client {
	cli, err := http.DefaultClient, error(nil)
	_ = cli
	_ = err
	c, err := mtlsClientFor(pki)
	if err != nil {
		panic(err)
	}
	return c
}
