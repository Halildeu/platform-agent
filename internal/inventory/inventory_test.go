package inventory

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"platform-agent/internal/software"
	"platform-agent/internal/winget"
)

// AG-025H — lightweight inventory guard tests.
//
// The default Collect() / CollectWithOptions(opts.IncludeSoftwareApps=false)
// path MUST NOT touch the software registry enumerator or the WinGet
// probe; the wire payload MUST omit the software block entirely. The
// explicit IncludeSoftwareApps=true path is the single COLLECT_INVENTORY
// opt-in for the full software inventory + WinGet readiness block.
//
// The package-level collectSoftware / detectWinget function variables are
// the test seam: tests override them with t.Cleanup-restored counters /
// stubs so the assertion is "lightweight default does not call these"
// (not just "Software field happens to be nil on this build").

func TestCollectLightweightDefaultOmitsSoftwareBlock(t *testing.T) {
	softwareCalls, wingetCalls := installProbeCounters(t)

	snap := Collect("test", time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))

	if snap.Software != nil {
		t.Fatalf("AG-025H: default Collect() must leave Snapshot.Software nil (got %+v)", snap.Software)
	}
	if got := atomic.LoadInt32(softwareCalls); got != 0 {
		t.Fatalf("AG-025H: default Collect() must not invoke software.Collect (got %d calls)", got)
	}
	if got := atomic.LoadInt32(wingetCalls); got != 0 {
		t.Fatalf("AG-025H: default Collect() must not invoke winget.Detect (got %d calls)", got)
	}

	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if strings.Contains(string(body), `"software":`) {
		t.Fatalf("AG-025H: lightweight payload must not carry software field: %s", body)
	}
	if strings.Contains(string(body), `"apps":`) {
		t.Fatalf("AG-025H: lightweight payload must not carry apps field: %s", body)
	}
}

func TestCollectWithOptionsIncludeSoftwareFalseOmitsSoftwareBlock(t *testing.T) {
	softwareCalls, wingetCalls := installProbeCounters(t)

	snap := CollectWithOptions(
		"test",
		time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		CollectOptions{IncludeSoftwareApps: false},
	)

	if snap.Software != nil {
		t.Fatalf("AG-025H: IncludeSoftwareApps=false must leave Snapshot.Software nil")
	}
	if atomic.LoadInt32(softwareCalls)+atomic.LoadInt32(wingetCalls) != 0 {
		t.Fatalf("AG-025H: explicit IncludeSoftwareApps=false must not invoke probes")
	}
}

func TestCollectWithOptionsIncludeSoftwareTrueRunsProbesAndAttachesApps(t *testing.T) {
	softwareCalls, wingetCalls := installProbeStubs(t,
		software.SoftwareSnapshot{
			SchemaVersion: software.SchemaVersion,
			Supported:     true,
			CollectedAt:   time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
			Apps: []software.InstalledApp{
				{
					DisplayName:    "7-Zip",
					DisplayVersion: "24.07",
					Publisher:      "Igor Pavlov",
					InstallSource:  software.SourceHKLM64,
				},
			},
			AppCount: 1,
		},
		winget.Readiness{
			Supported:          true,
			SystemContextReady: true,
			Version:            "v1.7.10861",
		},
	)

	snap := CollectWithOptions(
		"test",
		time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		CollectOptions{IncludeSoftwareApps: true},
	)

	if snap.Software == nil {
		t.Fatalf("AG-025H: IncludeSoftwareApps=true must attach Software summary")
	}
	if got := atomic.LoadInt32(softwareCalls); got != 1 {
		t.Fatalf("AG-025H: IncludeSoftwareApps=true must invoke software.Collect exactly once (got %d)", got)
	}
	if got := atomic.LoadInt32(wingetCalls); got != 1 {
		t.Fatalf("AG-025H: IncludeSoftwareApps=true must invoke winget.Detect exactly once (got %d)", got)
	}
	if snap.Software.SchemaVersion == 0 {
		t.Fatalf("Summary.SchemaVersion must be set on the wire payload")
	}
	if len(snap.Software.Apps) != 1 {
		t.Fatalf("IncludeSoftwareApps=true must propagate the Apps list (got %d)", len(snap.Software.Apps))
	}

	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if !strings.Contains(string(body), `"software":`) {
		t.Fatalf("AG-025H: IncludeSoftwareApps=true wire payload must carry software field")
	}
	if !strings.Contains(string(body), `"apps":`) {
		t.Fatalf("AG-025H: IncludeSoftwareApps=true wire payload must carry apps field")
	}
}

// installProbeCounters swaps both probes for stubs that increment atomic
// counters but never produce data. Used by the lightweight-path tests
// that assert "no probe call".
func installProbeCounters(t *testing.T) (*int32, *int32) {
	t.Helper()
	var softwareCalls int32
	var wingetCalls int32
	prevSoftware := collectSoftware
	prevWinget := detectWinget
	collectSoftware = func(now time.Time, opts software.CollectOptions) software.SoftwareSnapshot {
		atomic.AddInt32(&softwareCalls, 1)
		return software.SoftwareSnapshot{}
	}
	detectWinget = func(now time.Time) winget.Readiness {
		atomic.AddInt32(&wingetCalls, 1)
		return winget.Readiness{}
	}
	t.Cleanup(func() {
		collectSoftware = prevSoftware
		detectWinget = prevWinget
	})
	return &softwareCalls, &wingetCalls
}

// installProbeStubs wires fake fixtures into the probes so the full
// IncludeSoftwareApps=true path produces a deterministic Summary without
// touching the real registry / winget binary. Counters track invocation
// (full path expects exactly 1 of each).
func installProbeStubs(
	t *testing.T,
	softwareFixture software.SoftwareSnapshot,
	wingetFixture winget.Readiness,
) (*int32, *int32) {
	t.Helper()
	var softwareCalls int32
	var wingetCalls int32
	prevSoftware := collectSoftware
	prevWinget := detectWinget
	collectSoftware = func(now time.Time, opts software.CollectOptions) software.SoftwareSnapshot {
		atomic.AddInt32(&softwareCalls, 1)
		return softwareFixture
	}
	detectWinget = func(now time.Time) winget.Readiness {
		atomic.AddInt32(&wingetCalls, 1)
		return wingetFixture
	}
	t.Cleanup(func() {
		collectSoftware = prevSoftware
		detectWinget = prevWinget
	})
	return &softwareCalls, &wingetCalls
}
