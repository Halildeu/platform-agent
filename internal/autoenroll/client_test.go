package autoenroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/mtls"
	"platform-agent/internal/protocol"
)

// testPKI bundles the artefacts every wire test needs: a CA the server
// uses to verify the client cert, a server tls.Certificate matching the
// test server's hostname, and a client tls.Certificate the agent uses to
// authenticate.
type testPKI struct {
	caCertDER  []byte
	caCert     *x509.Certificate
	clientCert tls.Certificate
	serverCert tls.Certificate
	caPool     *x509.CertPool
}

func setupTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ca parse: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// Server cert binds to 127.0.0.1 so httptest's loopback listener
	// passes SNI verification.
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("srv key: %v", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("srv cert: %v", err)
	}
	srvLeaf, err := x509.ParseCertificate(srvDER)
	if err != nil {
		t.Fatalf("srv parse: %v", err)
	}

	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cli key: %v", err)
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "agent.acik.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("cli cert: %v", err)
	}
	cliLeaf, err := x509.ParseCertificate(cliDER)
	if err != nil {
		t.Fatalf("cli parse: %v", err)
	}

	return &testPKI{
		caCertDER:  caDER,
		caCert:     caCert,
		caPool:     pool,
		serverCert: tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey, Leaf: srvLeaf},
		clientCert: tls.Certificate{Certificate: [][]byte{cliDER}, PrivateKey: cliKey, Leaf: cliLeaf},
	}
}

func startMTLSServer(t *testing.T, pki *testPKI, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientCAs:    pki.caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newWireClient(t *testing.T, pki *testPKI, srv *httptest.Server) *Client {
	t.Helper()
	httpClient, err := mtls.NewClient(mtls.Options{
		Cert:       pki.clientCert,
		RootCAs:    pki.caPool,
		ServerName: "127.0.0.1",
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("mtls client: %v", err)
	}
	wire, err := NewClient(srv.URL, httpClient)
	if err != nil {
		t.Fatalf("wire client: %v", err)
	}
	return wire
}

// route is a lightweight handler builder that returns the configured
// JSON body for the matching path and inspects request headers via opt.
type route struct {
	statusCode int
	body       interface{}
	expectAuth string
	method     string
	captured   *http.Request
}

func mountRoutes(routes map[string]*route) http.Handler {
	mux := http.NewServeMux()
	for path, r := range routes {
		p, rt := path, r
		mux.HandleFunc(p, func(w http.ResponseWriter, req *http.Request) {
			if rt.method != "" && req.Method != rt.method {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if rt.expectAuth != "" {
				if got := req.Header.Get("Authorization"); got != rt.expectAuth {
					http.Error(w, "auth mismatch: got "+got, http.StatusUnauthorized)
					return
				}
			}
			if rt.captured != nil {
				// Copy headers — body is consumed below for JSON decode.
				*rt.captured = *req
			}
			w.Header().Set("Content-Type", "application/json")
			if rt.statusCode != 0 {
				w.WriteHeader(rt.statusCode)
			}
			if rt.statusCode == http.StatusNoContent || rt.body == nil {
				return
			}
			_ = json.NewEncoder(w).Encode(rt.body)
		})
	}
	return mux
}

func TestClient_AutoEnroll_Success(t *testing.T) {
	pki := setupTestPKI(t)
	resp := AutoEnrollResponse{
		DeviceID:   "dev-1",
		Status:     StatusEnrolled,
		EnrolledAt: time.Now().UTC(),
		CertInfo: AutoEnrollCertInfo{
			SANURI:     "adcomputer:11111111-1111-1111-1111-111111111111",
			Thumbprint: "abc123",
		},
	}
	routes := map[string]*route{
		PathAutoEnroll: {method: http.MethodPost, body: resp},
	}
	srv := startMTLSServer(t, pki, mountRoutes(routes))
	wire := newWireClient(t, pki, srv)

	got, err := wire.AutoEnroll(context.Background(), AutoEnrollRequest{
		MachineFingerprint: "fp-1",
		Hostname:           "host-1",
		OSName:             "windows",
		Architecture:       "amd64",
		AgentVersion:       "0.2.0",
	})
	if err != nil {
		t.Fatalf("AutoEnroll: %v", err)
	}
	if got.DeviceID != resp.DeviceID || got.Status != resp.Status || got.CertInfo.Thumbprint != resp.CertInfo.Thumbprint {
		t.Fatalf("response decode mismatch: %+v vs %+v", got, resp)
	}
}

func TestClient_Heartbeat_GraceWindowField(t *testing.T) {
	pki := setupTestPKI(t)
	graceUntil := time.Now().Add(2 * time.Hour).UTC()
	hbResp := HeartbeatResponse{
		Accepted:    true,
		Status:      "active",
		ServerTime:  time.Now().UTC(),
		GraceWindow: true,
		GraceUntil:  &graceUntil,
	}
	routes := map[string]*route{
		PathHeartbeat: {method: http.MethodPost, body: hbResp, expectAuth: "Bearer tok-1"},
	}
	srv := startMTLSServer(t, pki, mountRoutes(routes))
	wire := newWireClient(t, pki, srv)

	got, err := wire.Heartbeat(context.Background(), "tok-1", HeartbeatRequest{
		Hostname: "h", OSType: "WINDOWS", Architecture: "amd64", AgentVersion: "0.2.0", State: "STARTING",
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if !got.GraceWindow || got.GraceUntil == nil {
		t.Fatalf("expected grace window fields present, got %+v", got)
	}
}

func TestClient_HeartbeatCert_DoesNotSendAuthorization(t *testing.T) {
	pki := setupTestPKI(t)
	captured := &http.Request{}
	routes := map[string]*route{
		PathHeartbeat: {
			method:   http.MethodPost,
			body:     HeartbeatResponse{Accepted: true, Status: "active", ServerTime: time.Now().UTC()},
			captured: captured,
		},
	}
	srv := startMTLSServer(t, pki, mountRoutes(routes))
	wire := newWireClient(t, pki, srv)

	if _, err := wire.HeartbeatCert(context.Background(), HeartbeatRequest{
		Hostname: "h", OSType: "WINDOWS", Architecture: "amd64", AgentVersion: "0.2.0", State: "STARTING",
	}); err != nil {
		t.Fatalf("HeartbeatCert: %v", err)
	}
	if got := captured.Header.Get("Authorization"); got != "" {
		t.Fatalf("HeartbeatCert must not send Authorization header, got %q", got)
	}
}

func TestClient_NextCommand_204_ReturnsErrNoCommand(t *testing.T) {
	pki := setupTestPKI(t)
	routes := map[string]*route{
		PathCommandsNext: {method: http.MethodGet, statusCode: http.StatusNoContent, expectAuth: "Bearer tok-1"},
	}
	srv := startMTLSServer(t, pki, mountRoutes(routes))
	wire := newWireClient(t, pki, srv)

	_, err := wire.NextCommand(context.Background(), "tok-1")
	if !errors.Is(err, ErrNoCommand) {
		t.Fatalf("expected ErrNoCommand, got %v", err)
	}
}

func TestClient_NextCommand_200_DecodesPayload(t *testing.T) {
	pki := setupTestPKI(t)
	cmd := protocol.AgentCommand{
		CommandID: "cmd-1",
		ClaimID:   "claim-1",
		Type:      protocol.CommandCollectInventory,
	}
	routes := map[string]*route{
		PathCommandsNext: {method: http.MethodGet, body: cmd, expectAuth: "Bearer tok-1"},
	}
	srv := startMTLSServer(t, pki, mountRoutes(routes))
	wire := newWireClient(t, pki, srv)

	got, err := wire.NextCommand(context.Background(), "tok-1")
	if err != nil {
		t.Fatalf("NextCommand: %v", err)
	}
	if got.CommandID != cmd.CommandID || got.ClaimID != cmd.ClaimID {
		t.Fatalf("decode mismatch: %+v", got)
	}
}

func TestClient_AuthFailure_401MapsToErrAuthFailure(t *testing.T) {
	pki := setupTestPKI(t)
	routes := map[string]*route{
		PathHeartbeat: {method: http.MethodPost, statusCode: http.StatusUnauthorized, expectAuth: ""},
	}
	srv := startMTLSServer(t, pki, mountRoutes(routes))
	wire := newWireClient(t, pki, srv)

	_, err := wire.Heartbeat(context.Background(), "tok-1", HeartbeatRequest{State: "STARTING"})
	if !errors.Is(err, ErrAuthFailure) {
		t.Fatalf("expected ErrAuthFailure, got %v", err)
	}
}

func TestClient_AuthFailure_403MapsToErrAuthFailure(t *testing.T) {
	pki := setupTestPKI(t)
	routes := map[string]*route{
		PathTokenRefresh: {method: http.MethodPost, statusCode: http.StatusForbidden, expectAuth: ""},
	}
	srv := startMTLSServer(t, pki, mountRoutes(routes))
	wire := newWireClient(t, pki, srv)

	_, err := wire.RefreshToken(context.Background(), "tok-1")
	if !errors.Is(err, ErrAuthFailure) {
		t.Fatalf("expected ErrAuthFailure, got %v", err)
	}
}

func TestClient_SubmitResult_RequiresIDs(t *testing.T) {
	pki := setupTestPKI(t)
	srv := startMTLSServer(t, pki, mountRoutes(nil))
	wire := newWireClient(t, pki, srv)

	if err := wire.SubmitResult(context.Background(), "tok-1", protocol.CommandResult{}); err == nil {
		t.Fatal("expected error for empty command/claim ids")
	}
	if err := wire.SubmitResult(context.Background(), "tok-1", protocol.CommandResult{CommandID: "x"}); err == nil {
		t.Fatal("expected error for empty claim id")
	}
}

func TestClient_RefreshToken_SwapsToken(t *testing.T) {
	pki := setupTestPKI(t)
	resp := TokenRefreshResponse{
		ServiceToken:   "tok-2",
		TokenExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
	}
	routes := map[string]*route{
		PathTokenRefresh: {method: http.MethodPost, body: resp, expectAuth: "Bearer tok-1"},
	}
	srv := startMTLSServer(t, pki, mountRoutes(routes))
	wire := newWireClient(t, pki, srv)

	got, err := wire.RefreshToken(context.Background(), "tok-1")
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if got.ServiceToken != "tok-2" {
		t.Fatalf("token swap: got %q, want tok-2", got.ServiceToken)
	}
}

func TestClient_BaseURL_TrimsTrailingSlash(t *testing.T) {
	pki := setupTestPKI(t)
	srv := startMTLSServer(t, pki, mountRoutes(nil))
	wire, err := NewClient(srv.URL+"/", nil)
	if err == nil {
		t.Fatal("expected nil client error for nil http")
	}
	// Confirm via positive path that trailing slash is stripped.
	httpClient, _ := mtls.NewClient(mtls.Options{Cert: pki.clientCert, RootCAs: pki.caPool, ServerName: "127.0.0.1"})
	wire, err = NewClient(srv.URL+"/", httpClient)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if !strings.HasSuffix(wire.BaseURL(), srv.URL) {
		t.Fatalf("trailing slash not trimmed: %q", wire.BaseURL())
	}
}

func TestClient_NewClient_RejectsQueryOrFragment(t *testing.T) {
	pki := setupTestPKI(t)
	httpClient, _ := mtls.NewClient(mtls.Options{Cert: pki.clientCert, RootCAs: pki.caPool, ServerName: "127.0.0.1"})
	for _, raw := range []string{
		"https://host/api?x=1",
		"https://host/api#frag",
	} {
		if _, err := NewClient(raw, httpClient); err == nil {
			t.Fatalf("expected NewClient(%q) to reject query/fragment", raw)
		}
	}
}

func TestRunner_HeartbeatAcceptedFalse_FailsClosed(t *testing.T) {
	pki := setupTestPKI(t)
	recorder := &requestRecorder{hit: map[string]int{}}
	cfg := &handlerConfig{
		heartbeat: HeartbeatResponse{
			Accepted:   false,
			Status:     "device_disabled",
			ServerTime: time.Now().UTC(),
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
	if !errors.Is(err, ErrAuthFailure) {
		t.Fatalf("expected ErrAuthFailure on accepted=false, got %v", err)
	}
	if !runner.isFatal(err) {
		t.Fatalf("expected fatal classification, got %v", err)
	}
	if got := recorder.count(PathCommandsNext); got != 0 {
		t.Fatalf("commands/next should NOT be polled after accepted=false; got %d calls", got)
	}
}
