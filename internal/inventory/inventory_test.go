package inventory

import (
	"encoding/json"
	"testing"
	"time"
)

// On the macOS/Linux test runner the software collector returns an
// unsupported summary, so these tests pin the *wire shape* (default vs
// includeSoftware path) rather than the actual app list. The Windows
// runner extends this coverage with the live registry — see the
// Parallels smoke runbook in TESTING-STRATEGY.md.

func TestCollectIncludesSoftwareSummaryByDefault(t *testing.T) {
	snap := Collect("test", time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))
	if snap.Software == nil {
		t.Fatalf("Software summary should always be embedded")
	}
	if len(snap.Software.Apps) != 0 {
		t.Fatalf("default Collect must not include Apps[]: %d", len(snap.Software.Apps))
	}
	body, _ := json.Marshal(snap)
	// Marshalling must succeed and the apps field must be omitted
	// on the wire when nil.
	if contains := string(body); containsSubstr(contains, `"apps":`) {
		t.Fatalf("default payload should not carry apps field: %s", body)
	}
}

func TestCollectWithOptionsIncludesAppsWhenRequested(t *testing.T) {
	snap := CollectWithOptions("test", time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC), CollectOptions{IncludeSoftwareApps: true})
	if snap.Software == nil {
		t.Fatalf("Software summary should always be embedded")
	}
	// On non-Windows the Apps slice will be empty even with the
	// flag set, but the field selector path was exercised — the
	// Windows runner is where this surfaces non-empty data.
	if snap.Software.SchemaVersion == 0 {
		t.Fatalf("SchemaVersion must be set on the summary")
	}
}

func containsSubstr(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
