package selfupdate

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// aliasClient returns an http.Client whose transport dials `target` for EVERY
// request regardless of the request host, so a download against a non-IP
// allowlisted hostname (e.g. https://release.test/...) actually reaches the
// httptest server. This keeps the REAL URLPolicy host-allowlist gate live in
// the test (httptest's own 127.0.0.1 host would be rejected as an IP literal).
func aliasClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	addr := u.Host
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test alias host
		},
	}
}

const aliasHost = "release.test"

func aliasURL(path string) string { return "https://" + aliasHost + path }

func policyAllowing(hosts ...string) URLPolicy {
	return URLPolicy{AllowedHosts: hosts, MaxRedirects: 5}
}

func TestHTTPDownloader_Success(t *testing.T) {
	body := bytes.Repeat([]byte("A"), 8192)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	d := &HTTPDownloader{Client: aliasClient(t, srv)}
	var buf bytes.Buffer
	n, code, reason := d.Download(context.Background(), aliasURL("/agent.exe"), policyAllowing(aliasHost), 1<<20, &buf)
	if code != "" {
		t.Fatalf("clean download failed: code=%q reason=%q", code, reason)
	}
	if n != int64(len(body)) || !bytes.Equal(buf.Bytes(), body) {
		t.Fatalf("downloaded %d bytes, want %d (equal=%v)", n, len(body), bytes.Equal(buf.Bytes(), body))
	}
}

func TestHTTPDownloader_OverCap(t *testing.T) {
	body := bytes.Repeat([]byte("B"), 5000)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	d := &HTTPDownloader{Client: aliasClient(t, srv)}
	var buf bytes.Buffer
	_, code, _ := d.Download(context.Background(), aliasURL("/big.exe"), policyAllowing(aliasHost), 1000, &buf)
	if code != ErrDownloadTooLarge {
		t.Fatalf("over-cap body must be DOWNLOAD_TOO_LARGE, got %q", code)
	}
}

func TestHTTPDownloader_ExactlyAtCap(t *testing.T) {
	body := bytes.Repeat([]byte("C"), 1000)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	d := &HTTPDownloader{Client: aliasClient(t, srv)}
	var buf bytes.Buffer
	n, code, _ := d.Download(context.Background(), aliasURL("/exact.exe"), policyAllowing(aliasHost), 1000, &buf)
	if code != "" || n != 1000 {
		t.Fatalf("body exactly at cap should succeed, got n=%d code=%q", n, code)
	}
}

func TestHTTPDownloader_Non200(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	d := &HTTPDownloader{Client: aliasClient(t, srv)}
	var buf bytes.Buffer
	_, code, _ := d.Download(context.Background(), aliasURL("/missing.exe"), policyAllowing(aliasHost), 1<<20, &buf)
	if code != ErrDownloadFailed {
		t.Fatalf("404 must be DOWNLOAD_FAILED, got %q", code)
	}
}

func TestHTTPDownloader_URLPolicyRejectsBeforeTransport(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("should-not-be-reached"))
	}))
	defer srv.Close()
	d := &HTTPDownloader{Client: aliasClient(t, srv)}
	var buf bytes.Buffer

	t.Run("non-allowlisted host", func(t *testing.T) {
		_, code, _ := d.Download(context.Background(), aliasURL("/x.exe"), policyAllowing("other.test"), 1<<20, &buf)
		if code != ErrURLRejected {
			t.Fatalf("host not in allowlist must be POLICY_URL_REJECTED, got %q", code)
		}
	})
	t.Run("http scheme downgrade", func(t *testing.T) {
		_, code, _ := d.Download(context.Background(), "http://"+aliasHost+"/x.exe", policyAllowing(aliasHost), 1<<20, &buf)
		if code != ErrURLRejected {
			t.Fatalf("http scheme must be POLICY_URL_REJECTED, got %q", code)
		}
	})
	t.Run("negative redirect cap (direct primitive use)", func(t *testing.T) {
		pol := policyAllowing(aliasHost)
		pol.MaxRedirects = -1
		_, code, _ := d.Download(context.Background(), aliasURL("/x.exe"), pol, 1<<20, &buf)
		if code != ErrURLRejected {
			t.Fatalf("negative redirect cap must be POLICY_URL_REJECTED, got %q", code)
		}
	})
}

func TestHTTPDownloader_RedirectToDisallowedHostRejected(t *testing.T) {
	// final server is on a different alias host that the policy does NOT allow.
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("redirected-payload"))
	}))
	defer final.Close()
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.test/agent.exe", http.StatusFound)
	}))
	defer redir.Close()

	// One client that dials the redirect server for the initial request.
	d := &HTTPDownloader{Client: aliasClient(t, redir)}
	var buf bytes.Buffer
	// allow only the initial host; the redirect Location (evil.test) is not allowed.
	_, code, _ := d.Download(context.Background(), aliasURL("/agent.exe"), policyAllowing(aliasHost), 1<<20, &buf)
	if code != ErrURLRejected {
		t.Fatalf("redirect to a disallowed host must be POLICY_URL_REJECTED, got %q", code)
	}
}

// CapReader unit coverage (the streaming guard) independent of the network.
func TestCapReader(t *testing.T) {
	cases := []struct {
		name    string
		bodyLen int
		cap     int64
		wantErr bool
	}{
		{"under cap", 500, 1000, false},
		{"exactly at cap", 1000, 1000, false},
		{"one over cap", 1001, 1000, true},
		{"far over cap", 100000, 1000, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := bytes.NewReader(bytes.Repeat([]byte("x"), c.bodyLen))
			cr := &capReader{r: src, remaining: c.cap + 1}
			var buf bytes.Buffer
			_, err := buf.ReadFrom(cr)
			if (err != nil) != c.wantErr {
				t.Fatalf("bodyLen=%d cap=%d => err=%v, wantErr=%v", c.bodyLen, c.cap, err, c.wantErr)
			}
		})
	}
}
