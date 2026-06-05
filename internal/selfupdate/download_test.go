package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestOpenDownloadDirectOK(t *testing.T) {
	transport := fakeDownloadTransport(map[string]fakeDownloadResponse{
		"https://updates.example.com/agent.exe": {status: http.StatusOK, body: "agent"},
	})
	dl, code, reason := OpenDownload(context.Background(), "https://updates.example.com/agent.exe", testDownloadPolicy(), transport)
	if code != "" || reason != "" {
		t.Fatalf("OpenDownload: code=%q reason=%q", code, reason)
	}
	defer dl.Body.Close()
	body, _ := io.ReadAll(dl.Body)
	if string(body) != "agent" || dl.FinalURL != "https://updates.example.com/agent.exe" || len(dl.Redirects) != 0 {
		t.Fatalf("download result wrong: body=%q result=%+v", body, dl)
	}
}

func TestOpenDownloadAllowlistedRedirect(t *testing.T) {
	transport := fakeDownloadTransport(map[string]fakeDownloadResponse{
		"https://updates.example.com/agent.exe": {status: http.StatusFound, location: "https://objects.example.com/agent.exe"},
		"https://objects.example.com/agent.exe": {status: http.StatusOK, body: "agent"},
	})
	dl, code, reason := OpenDownload(context.Background(), "https://updates.example.com/agent.exe", testDownloadPolicy(), transport)
	if code != "" || reason != "" {
		t.Fatalf("OpenDownload: code=%q reason=%q", code, reason)
	}
	defer dl.Body.Close()
	if dl.FinalURL != "https://objects.example.com/agent.exe" || len(dl.Redirects) != 1 || dl.Redirects[0] != dl.FinalURL {
		t.Fatalf("redirect result wrong: %+v", dl)
	}
}

func TestOpenDownloadRelativeRedirect(t *testing.T) {
	transport := fakeDownloadTransport(map[string]fakeDownloadResponse{
		"https://updates.example.com/releases/latest":       {status: http.StatusFound, location: "/releases/v1/agent.exe"},
		"https://updates.example.com/releases/v1/agent.exe": {status: http.StatusOK, body: "agent"},
	})
	dl, code, reason := OpenDownload(context.Background(), "https://updates.example.com/releases/latest", testDownloadPolicy(), transport)
	if code != "" || reason != "" {
		t.Fatalf("OpenDownload: code=%q reason=%q", code, reason)
	}
	defer dl.Body.Close()
	if dl.FinalURL != "https://updates.example.com/releases/v1/agent.exe" {
		t.Fatalf("relative redirect final=%q", dl.FinalURL)
	}
}

func TestOpenDownloadRejectsRedirectEscape(t *testing.T) {
	transport := fakeDownloadTransport(map[string]fakeDownloadResponse{
		"https://updates.example.com/agent.exe": {status: http.StatusFound, location: "https://evil.example.com/agent.exe"},
	})
	if _, code, _ := OpenDownload(context.Background(), "https://updates.example.com/agent.exe", testDownloadPolicy(), transport); code != ErrURLRejected {
		t.Fatalf("code=%q, want POLICY_URL_REJECTED", code)
	}
}

func TestOpenDownloadRejectsSchemeDowngradeRedirect(t *testing.T) {
	transport := fakeDownloadTransport(map[string]fakeDownloadResponse{
		"https://updates.example.com/agent.exe": {status: http.StatusFound, location: "http://updates.example.com/agent.exe"},
	})
	if _, code, _ := OpenDownload(context.Background(), "https://updates.example.com/agent.exe", testDownloadPolicy(), transport); code != ErrURLRejected {
		t.Fatalf("code=%q, want POLICY_URL_REJECTED", code)
	}
}

func TestOpenDownloadRejectsTooManyRedirects(t *testing.T) {
	policy := testDownloadPolicy()
	policy.MaxRedirects = 0
	transport := fakeDownloadTransport(map[string]fakeDownloadResponse{
		"https://updates.example.com/agent.exe": {status: http.StatusFound, location: "https://objects.example.com/agent.exe"},
	})
	if _, code, reason := OpenDownload(context.Background(), "https://updates.example.com/agent.exe", policy, transport); code != ErrURLRejected || !strings.Contains(reason, "too many redirects") {
		t.Fatalf("code=%q reason=%q, want too-many redirect rejection", code, reason)
	}
}

func TestOpenDownloadRejectsNon200(t *testing.T) {
	transport := fakeDownloadTransport(map[string]fakeDownloadResponse{
		"https://updates.example.com/agent.exe": {status: http.StatusNotFound, body: "missing"},
	})
	if _, code, _ := OpenDownload(context.Background(), "https://updates.example.com/agent.exe", testDownloadPolicy(), transport); code != ErrDownloadFailed {
		t.Fatalf("code=%q, want DOWNLOAD_FAILED", code)
	}
}

func TestOpenDownloadTransportError(t *testing.T) {
	transport := fakeDownloadTransport(map[string]fakeDownloadResponse{})
	if _, code, _ := OpenDownload(context.Background(), "https://updates.example.com/agent.exe", testDownloadPolicy(), transport); code != ErrDownloadFailed {
		t.Fatalf("code=%q, want DOWNLOAD_FAILED", code)
	}
}

func TestStageCandidateFromDownload(t *testing.T) {
	withTestStagingHooks(t)
	payload := []byte("downloaded signed agent")
	sum := sha256.Sum256(payload)
	in := testStageCandidateInput(t.TempDir(), nil, hex.EncodeToString(sum[:]), AuthenticodeEvidence{
		ChainValid:        true,
		HasCodeSigningEKU: true,
		SignerThumbprint:  "AABBCC",
		Timestamped:       true,
		SigningTimeValid:  true,
	})
	in.Preflight.Payload.BinaryURL = "https://updates.example.com/agent.exe"
	in.Preflight.URLPolicy = testDownloadPolicy()
	transport := fakeDownloadTransport(map[string]fakeDownloadResponse{
		"https://updates.example.com/agent.exe": {status: http.StatusOK, body: string(payload)},
	})

	result, plan := StageCandidateFromDownload(context.Background(), in, transport)
	if result.StageStatus != StageReady {
		t.Fatalf("result=%+v", result)
	}
	if plan.StagedBinaryPath == "" {
		t.Fatalf("missing activation plan: %+v", plan)
	}
}

func testDownloadPolicy() URLPolicy {
	return URLPolicy{AllowedHosts: []string{"updates.example.com", "objects.example.com"}, MaxRedirects: 2}
}

type fakeDownloadResponse struct {
	status   int
	location string
	body     string
}

type fakeDownloadTransport map[string]fakeDownloadResponse

func (f fakeDownloadTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r, ok := f[req.URL.String()]
	if !ok {
		return nil, errFakeDownloadMissing
	}
	resp := &http.Response{
		StatusCode: r.status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Request:    req,
	}
	if r.location != "" {
		resp.Header.Set("Location", r.location)
	}
	return resp, nil
}

var errFakeDownloadMissing = fakeDownloadMissingError{}

type fakeDownloadMissingError struct{}

func (fakeDownloadMissingError) Error() string { return "fake download response missing" }
