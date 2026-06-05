//go:build !windows

package selfupdate

import "testing"

func TestNativeAuthenticodeVerifierNonWindowsFailsClosed(t *testing.T) {
	ev, code, reason := NewNativeAuthenticodeVerifier().VerifyAuthenticode("candidate.exe")
	if code != ErrUnsupportedPlatform {
		t.Fatalf("code=%q reason=%q ev=%+v, want unsupported-platform", code, reason, ev)
	}
}
