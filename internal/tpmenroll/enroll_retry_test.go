package tpmenroll

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func noSleep(time.Duration) {}

func fastClient(t *testing.T, url string, srv *httptest.Server, maxAttempts int) *Client {
	t.Helper()
	c, err := NewClient(url, srv.Client(),
		WithSleep(noSleep),
		WithNonceRetry(RetryPolicy{MaxAttempts: maxAttempts, BaseBackoff: time.Millisecond, MaxBackoff: time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// /nonce is retried on transient 5xx and succeeds once the backend recovers.
func TestPostNonce_RetriesTransientThenSucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"nonceId":"n","nonce":"AA==","credBlob":"AA==","encSecret":"AA=="}`))
	}))
	defer srv.Close()
	c := fastClient(t, srv.URL+"/api/v1/agent", srv, 5)

	ch, err := c.postNonce(context.Background(), NonceRequest{EnrollmentToken: "t"})
	if err != nil {
		t.Fatalf("postNonce: %v", err)
	}
	if ch.NonceID != "n" {
		t.Fatalf("nonceId=%q", ch.NonceID)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("calls=%d, want 3 (2 transient + 1 success)", got)
	}
}

// Persistent 5xx exhausts the bounded attempts and returns an error.
func TestPostNonce_ExhaustsRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := fastClient(t, srv.URL+"/api/v1/agent", srv, 4)

	if _, err := c.postNonce(context.Background(), NonceRequest{EnrollmentToken: "t"}); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Errorf("calls=%d, want 4 (MaxAttempts)", got)
	}
}

// A terminal 4xx (the uniform-403 deny) is NOT retried.
func TestPostNonce_TerminalNoRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"status":"denied"}`))
	}))
	defer srv.Close()
	c := fastClient(t, srv.URL+"/api/v1/agent", srv, 5)

	if _, err := c.postNonce(context.Background(), NonceRequest{EnrollmentToken: "t"}); err == nil {
		t.Fatal("expected error on 403")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("calls=%d, want 1 (4xx is terminal, no retry)", got)
	}
}

// /attest is NEVER retried — the nonce is single-use.
func TestPostAttest_NoRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := fastClient(t, srv.URL+"/api/v1/agent", srv, 5) // generous /nonce policy must NOT affect /attest

	if _, err := c.postAttest(context.Background(), AttestEnvelope{Schema: SchemaV2}); err == nil {
		t.Fatal("expected error on 503")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("calls=%d, want 1 (/attest never retries)", got)
	}
}

func TestBackoffDelay_CappedExponential(t *testing.T) {
	p := RetryPolicy{MaxAttempts: 10, BaseBackoff: 100 * time.Millisecond, MaxBackoff: time.Second}
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{5, time.Second}, // capped
		{9, time.Second}, // capped
	}
	for _, tc := range cases {
		if got := backoffDelay(p, tc.attempt); got != tc.want {
			t.Errorf("backoffDelay(attempt=%d)=%v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestNewClient_DefaultRetryApplied(t *testing.T) {
	c, err := NewClient("https://h/api/v1/agent", http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if c.nonceRetry.MaxAttempts < 1 || c.sleep == nil {
		t.Fatalf("defaults not applied: %+v sleep=%v", c.nonceRetry, c.sleep != nil)
	}
}
