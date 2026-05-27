package autoenroll

import (
	"crypto/x509"
	"strings"
	"testing"
)

func TestThumbprintSHA256Hex_DeterministicAndLowercase(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("hello")}
	got := ThumbprintSHA256Hex(cert)
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Fatalf("ThumbprintSHA256Hex(%q) = %q, want %q", cert.Raw, got, want)
	}
	if got != strings.ToLower(got) {
		t.Fatalf("thumbprint must be lowercase, got %q", got)
	}
}

func TestThumbprintSHA1Hex_DeterministicAndLowercase(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("hello")}
	got := ThumbprintSHA1Hex(cert)
	want := "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
	if got != want {
		t.Fatalf("ThumbprintSHA1Hex(%q) = %q, want %q", cert.Raw, got, want)
	}
	if got != strings.ToLower(got) {
		t.Fatalf("thumbprint must be lowercase, got %q", got)
	}
}

func TestThumbprintSHA256Hex_EmptyOnNilOrZeroRaw(t *testing.T) {
	if got := ThumbprintSHA256Hex(nil); got != "" {
		t.Fatalf("nil cert: got %q, want \"\"", got)
	}
	if got := ThumbprintSHA256Hex(&x509.Certificate{}); got != "" {
		t.Fatalf("empty raw: got %q, want \"\"", got)
	}
}
