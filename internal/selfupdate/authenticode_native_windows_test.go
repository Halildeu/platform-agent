//go:build windows

package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeAuthenticodeVerifierUnsignedFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint-agent.exe")
	if err := os.WriteFile(path, []byte("not a signed PE file"), 0o600); err != nil {
		t.Fatal(err)
	}

	ev, code, reason := NewNativeAuthenticodeVerifier().VerifyAuthenticode(path)
	if code != ErrSignatureInvalid {
		t.Fatalf("code=%q reason=%q ev=%+v, want signature invalid", code, reason, ev)
	}
}
