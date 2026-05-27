//go:build !windows

package winget

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDetectNonWindowsReturnsUnsupported(t *testing.T) {
	r := Detect(time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))
	if r.Supported {
		t.Fatalf("non-Windows Detect should report Supported=false")
	}
	if r.AvailableInCurrentContext || r.SystemContextReady {
		t.Fatalf("non-Windows readiness flags must be false")
	}
	if r.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", r.SchemaVersion, SchemaVersion)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
}
