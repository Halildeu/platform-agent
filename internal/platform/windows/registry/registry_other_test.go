//go:build !windows

package registry

import "testing"

func TestReader_NonWindowsReturnsDefaults(t *testing.T) {
	r := New()
	if got := r.ReadInt(`HKLM:\X`, "Y", 42); got != 42 {
		t.Fatalf("ReadInt non-Windows: got %d, want 42 (default)", got)
	}
	if got := r.ReadString(`HKLM:\X`, "Y", "fallback"); got != "fallback" {
		t.Fatalf("ReadString non-Windows: got %q, want fallback", got)
	}
}
