package protocol

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"platform-agent/internal/security"
)

const testAssetSha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// assetServer serves body for the asset path and verifies the request the way
// the backend's DeviceCredentialAuthenticationFilter does: the HMAC covers the
// backend-visible /api/v1/agent path, not the dialed /api/v1/endpoint-agent one.
func assetServer(t *testing.T, secret string, status int, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantDial := "/api/v1/endpoint-agent/display-policy-assets/" + testAssetSha
		if r.Method != http.MethodGet || r.URL.Path != wantDial {
			t.Errorf("request = %s %s, want GET %s", r.Method, r.URL.Path, wantDial)
		}
		if accept := r.Header.Get("Accept"); !strings.Contains(accept, "image/png") || strings.Contains(accept, "json") {
			t.Errorf("Accept = %q, want the image types only", accept)
		}
		canonical := security.CanonicalRequest(http.MethodGet,
			"/api/v1/agent/display-policy-assets/"+testAssetSha, "",
			r.Header.Get("X-Request-Timestamp"), r.Header.Get("X-Request-Nonce"), security.BodyHashHex(nil))
		if got, want := r.Header.Get("X-Signature"), security.Sign(secret, canonical); got != want {
			t.Errorf("signature does not cover the backend-visible path")
		}
		if r.Header.Get("X-Device-Credential-Id") != "cred-1" {
			t.Errorf("credential id header missing")
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
}

func enrolledClient(t *testing.T, base string) *Client {
	t.Helper()
	client, err := NewClient(base+"/api/v1/endpoint-agent", "", nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.SetIdentity("cred-1", "device-secret", "device-1")
	return client
}

func TestFetchDisplayPolicyAssetReturnsTheSignedDownload(t *testing.T) {
	image := append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, bytes.Repeat([]byte{0xFF}, 64)...)
	srv := assetServer(t, "device-secret", http.StatusOK, image)
	defer srv.Close()

	got, err := enrolledClient(t, srv.URL).FetchDisplayPolicyAsset(context.Background(), testAssetSha, 1024)
	if err != nil {
		t.Fatalf("FetchDisplayPolicyAsset: %v", err)
	}
	if !bytes.Equal(got, image) {
		t.Fatalf("downloaded %d bytes, want the %d served", len(got), len(image))
	}
}

func TestFetchDisplayPolicyAssetRefusesAnOversizedBody(t *testing.T) {
	srv := assetServer(t, "device-secret", http.StatusOK, bytes.Repeat([]byte{1}, 101))
	defer srv.Close()

	_, err := enrolledClient(t, srv.URL).FetchDisplayPolicyAsset(context.Background(), testAssetSha, 100)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v, want a size-limit error", err)
	}
}

func TestFetchDisplayPolicyAssetSurfacesARefusalAsHTTPError(t *testing.T) {
	srv := assetServer(t, "device-secret", http.StatusNotFound, []byte(`{"message":"Asset not found."}`))
	defer srv.Close()

	_, err := enrolledClient(t, srv.URL).FetchDisplayPolicyAsset(context.Background(), testAssetSha, 1024)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound {
		t.Fatalf("err = %v, want HTTPError 404", err)
	}
}

func TestFetchDisplayPolicyAssetRequiresAnEnrolledIdentity(t *testing.T) {
	client, err := NewClient("https://testai.example/api/v1/endpoint-agent", "", nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.FetchDisplayPolicyAsset(context.Background(), testAssetSha, 1024)
	if err == nil || !strings.Contains(err.Error(), "device credential") {
		t.Fatalf("err = %v, want a device-credential error", err)
	}
}
