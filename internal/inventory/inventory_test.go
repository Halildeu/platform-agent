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
// that assert "no probe call". The AG-026A source/egress probe is also
// installed so the same lightweight assertions cover IncludeWinGetEgress
// default-false behavior.
func installProbeCounters(t *testing.T) (*int32, *int32) {
	t.Helper()
	var softwareCalls int32
	var wingetCalls int32
	var sourceEgressCalls int32
	prevSoftware := collectSoftware
	prevWinget := detectWinget
	prevSourceEgress := detectSourceEgress
	collectSoftware = func(now time.Time, opts software.CollectOptions) software.SoftwareSnapshot {
		atomic.AddInt32(&softwareCalls, 1)
		return software.SoftwareSnapshot{}
	}
	detectWinget = func(now time.Time) winget.Readiness {
		atomic.AddInt32(&wingetCalls, 1)
		return winget.Readiness{}
	}
	detectSourceEgress = func(now time.Time) winget.SourceEgressReadiness {
		atomic.AddInt32(&sourceEgressCalls, 1)
		return winget.SourceEgressReadiness{}
	}
	t.Cleanup(func() {
		collectSoftware = prevSoftware
		detectWinget = prevWinget
		detectSourceEgress = prevSourceEgress
	})
	// Tests that need the source-egress counter can use
	// installSourceEgressCounter; the AG-025H-era callers ignore the
	// third counter (Go discards unused returns).
	_ = sourceEgressCalls
	return &softwareCalls, &wingetCalls
}

// installSourceEgressCounter swaps detectSourceEgress for a counter
// stub and returns the counter so AG-026A tests can assert "0 calls"
// for IncludeWinGetEgress=false and "exactly 1 call" for true.
func installSourceEgressCounter(t *testing.T, fixture winget.SourceEgressReadiness) *int32 {
	t.Helper()
	var calls int32
	prev := detectSourceEgress
	detectSourceEgress = func(now time.Time) winget.SourceEgressReadiness {
		atomic.AddInt32(&calls, 1)
		return fixture
	}
	t.Cleanup(func() {
		detectSourceEgress = prev
	})
	return &calls
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

// AG-026A — IncludeWinGetEgress wire-up tests.
//
// Codex 019e6b5d acceptance criteria #4:
//   - includeWinGetEgress=false (default) MUST NOT invoke
//     winget.DetectSourceEgress; Snapshot.WinGetEgress stays nil.
//   - includeWinGetEgress=true MUST invoke DetectSourceEgress exactly
//     once and attach the result to Snapshot.WinGetEgress.

func TestCollectWithOptionsIncludeWinGetEgressFalseSkipsPreflight(t *testing.T) {
	// installProbeCounters sets all three probes (software, winget,
	// source-egress) to no-op counters; installSourceEgressCounter
	// then overrides the source-egress stub with a fixture-returning
	// one. Order matters: the later override wins, the earlier
	// t.Cleanup restores it. For the "must NOT call" assertion we
	// keep the counter-only stub from installProbeCounters.
	installProbeCounters(t)
	calls := installSourceEgressCounter(t, winget.SourceEgressReadiness{
		Supported:     true,
		SchemaVersion: winget.SourceEgressSchemaVersion,
	})

	snap := CollectWithOptions(
		"test",
		time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		CollectOptions{}, // both flags default false
	)

	if snap.WinGetEgress != nil {
		t.Fatalf("AG-026A: IncludeWinGetEgress=false must leave Snapshot.WinGetEgress nil (got %+v)", snap.WinGetEgress)
	}
	if got := atomic.LoadInt32(calls); got != 0 {
		t.Fatalf("AG-026A: IncludeWinGetEgress=false must not invoke DetectSourceEgress (got %d calls)", got)
	}

	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if strings.Contains(string(body), `"wingetEgress":`) {
		t.Fatalf("AG-026A: lightweight payload must not carry wingetEgress field: %s", body)
	}
}

func TestCollectWithOptionsIncludeWinGetEgressTrueRunsPreflightExactlyOnce(t *testing.T) {
	fixture := winget.SourceEgressReadiness{
		Supported:     true,
		SchemaVersion: winget.SourceEgressSchemaVersion,
		Sources: []winget.SourceInfo{
			{Name: "winget", Argument: "https://cdn.winget.microsoft.com/cache", Type: "Microsoft.PreIndexed.Package", TrustLevel: "Trusted"},
		},
		PackageQuery: winget.PackageQueryResult{
			PackageID:  winget.FixedPackageQueryID,
			Found:      true,
			ExitCode:   0,
			DurationMs: 42,
		},
	}
	installProbeCounters(t)
	calls := installSourceEgressCounter(t, fixture)

	snap := CollectWithOptions(
		"test",
		time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		CollectOptions{IncludeWinGetEgress: true},
	)

	if snap.WinGetEgress == nil {
		t.Fatalf("AG-026A: IncludeWinGetEgress=true must attach Snapshot.WinGetEgress")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("AG-026A: IncludeWinGetEgress=true must invoke DetectSourceEgress exactly once (got %d)", got)
	}
	if snap.WinGetEgress.PackageQuery.PackageID != winget.FixedPackageQueryID {
		t.Fatalf("AG-026A: payload PackageID = %q, want %q", snap.WinGetEgress.PackageQuery.PackageID, winget.FixedPackageQueryID)
	}

	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if !strings.Contains(string(body), `"wingetEgress":`) {
		t.Fatalf("AG-026A: IncludeWinGetEgress=true wire payload must carry wingetEgress field")
	}
	if !strings.Contains(string(body), `"packageId":"`+winget.FixedPackageQueryID+`"`) {
		t.Fatalf("AG-026A: wire payload must carry pinned packageId %q", winget.FixedPackageQueryID)
	}
}
