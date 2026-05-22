package security

import (
	"strings"
	"testing"
)

// sha256 of the empty byte string — a stable golden vector.
const emptyBodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestBodyHashHexEmptyBody(t *testing.T) {
	if got := BodyHashHex(nil); got != emptyBodyHash {
		t.Fatalf("empty body hash = %q, want %q", got, emptyBodyHash)
	}
	if got := BodyHashHex([]byte{}); got != emptyBodyHash {
		t.Fatalf("empty slice hash = %q, want %q", got, emptyBodyHash)
	}
}

func TestBodyHashHexIsLowerHex(t *testing.T) {
	got := BodyHashHex([]byte(`{"status":"SUCCEEDED"}`))
	if len(got) != 64 {
		t.Fatalf("body hash length = %d, want 64", len(got))
	}
	if got != strings.ToLower(got) {
		t.Fatalf("body hash %q is not lower-case", got)
	}
}

func TestCanonicalRequestSixLinesUpperMethodLowerHash(t *testing.T) {
	// BE-011: must byte-match HmacSignatureSupport.canonicalPayload — six
	// newline-joined lines, method upper-cased, body hash lower-cased, and an
	// empty (but present) query line when there is no query string.
	got := CanonicalRequest("post", "/api/v1/agent/heartbeat", "", "2026-05-22T13:00:00Z", "nonce-1", "ABCDEF")
	want := "POST\n/api/v1/agent/heartbeat\n\n2026-05-22T13:00:00Z\nnonce-1\nabcdef"
	if got != want {
		t.Fatalf("canonical =\n%q\nwant\n%q", got, want)
	}
	if lines := strings.Count(got, "\n"); lines != 5 {
		t.Fatalf("canonical has %d separators, want 5 (six lines)", lines)
	}
}

func TestCanonicalRequestWithQuery(t *testing.T) {
	got := CanonicalRequest("GET", "/api/v1/agent/commands/next", "since=1", "2026-05-22T13:00:00Z", "n2", emptyBodyHash)
	want := "GET\n/api/v1/agent/commands/next\nsince=1\n2026-05-22T13:00:00Z\nn2\n" + emptyBodyHash
	if got != want {
		t.Fatalf("canonical with query =\n%q\nwant\n%q", got, want)
	}
}

func TestSignIsDeterministicBase64URL(t *testing.T) {
	canonical := CanonicalRequest("POST", "/api/v1/agent/heartbeat", "", "2026-05-22T13:00:00Z", "nonce-1", emptyBodyHash)
	first := Sign("device-secret", canonical)
	second := Sign("device-secret", canonical)
	if first != second {
		t.Fatalf("Sign not deterministic: %q != %q", first, second)
	}
	if first == "" {
		t.Fatal("Sign returned empty signature")
	}
	// base64url-no-padding: no '+', '/', or '=' characters.
	if strings.ContainsAny(first, "+/=") {
		t.Fatalf("signature %q is not base64url-no-padding", first)
	}
}

func TestVerifyAcceptsMatchingRejectsTampered(t *testing.T) {
	canonical := CanonicalRequest("POST", "/api/v1/agent/heartbeat", "", "2026-05-22T13:00:00Z", "nonce-1",
		BodyHashHex([]byte(`{"status":"SUCCEEDED"}`)))
	signature := Sign("device-secret", canonical)

	if !Verify("device-secret", canonical, signature) {
		t.Fatal("Verify rejected a matching signature")
	}
	tampered := CanonicalRequest("POST", "/api/v1/agent/heartbeat", "", "2026-05-22T13:00:00Z", "nonce-1",
		BodyHashHex([]byte(`{"status":"FAILED"}`)))
	if Verify("device-secret", tampered, signature) {
		t.Fatal("Verify accepted a tampered canonical string")
	}
	if Verify("wrong-secret", canonical, signature) {
		t.Fatal("Verify accepted a wrong secret")
	}
	if Verify("device-secret", canonical, "") {
		t.Fatal("Verify accepted an empty signature")
	}
}
