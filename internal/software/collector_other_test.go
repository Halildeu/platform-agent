//go:build !windows

package software

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCollectNonWindowsReturnsUnsupported(t *testing.T) {
	snap := Collect(time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC), CollectOptions{})
	if snap.Supported {
		t.Fatalf("non-Windows build should report Supported=false")
	}
	if snap.Reason != "unsupported_os" {
		t.Fatalf("Reason = %q, want unsupported_os", snap.Reason)
	}
	if snap.AppCount != 0 {
		t.Fatalf("AppCount = %d, want 0", snap.AppCount)
	}
	if snap.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", snap.SchemaVersion, SchemaVersion)
	}
	// JSON must serialise even on the empty path so the inventory
	// wire payload stays uniform across platforms.
	if _, err := json.Marshal(snap); err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
}
