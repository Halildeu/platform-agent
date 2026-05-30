//go:build windows

package inventory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestProbeOutdatedSoftwareWinGetNotFound(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return nil, errors.New("exec: not found")
	}

	result := ProbeOutdatedSoftware(context.Background(), time.Now)
	if len(result.ProbeErrors) == 0 {
		t.Fatal("Should have probe errors when winget not found")
	}
	if result.ProbeErrors[0].Code != OutdatedSoftwareErrWinGetNotFound {
		t.Errorf("Code = %q; want %q", result.ProbeErrors[0].Code, OutdatedSoftwareErrWinGetNotFound)
	}
}

func TestProbeOutdatedSoftwareEmptyOutput(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return []byte("   "), nil
	}

	result := ProbeOutdatedSoftware(context.Background(), time.Now)
	if len(result.ProbeErrors) == 0 {
		t.Fatal("Should have probe errors on empty output")
	}
	if result.ProbeErrors[0].Code != OutdatedSoftwareErrWinGetEmptyOutput {
		t.Errorf("Code = %q; want %q", result.ProbeErrors[0].Code, OutdatedSoftwareErrWinGetEmptyOutput)
	}
}

func TestProbeOutdatedSoftwareNoUpgrades(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return []byte("No applicable upgrade packages found."), nil
	}

	result := ProbeOutdatedSoftware(context.Background(), time.Now)
	if result.SourceUsed != OutdatedSoftwareSourceWinGet {
		t.Errorf("SourceUsed = %v; want winget", result.SourceUsed)
	}
	if len(result.Upgrade) != 0 {
		t.Errorf("len(Upgrade) = %d; want 0", len(result.Upgrade))
	}
}

func TestProbeOutdatedSoftwareWithPackages(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	// Column-aligned single-package table. The data row sits
	// immediately after the dashed separator — the off-by-one
	// regression dropped exactly this row.
	output := "Name                 Id                       Version  Available  Source\n" +
		"-------------------- ------------------------ -------- ---------- -------\n" +
		"7-Zip                7zip.7zip                24.09    25.01      winget\n"
	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return []byte(output), nil
	}

	result := ProbeOutdatedSoftware(context.Background(), time.Now)
	if result.SourceUsed != OutdatedSoftwareSourceWinGet {
		t.Errorf("SourceUsed = %v; want winget", result.SourceUsed)
	}
	if len(result.Upgrade) != 1 {
		t.Fatalf("len(Upgrade) = %d; want 1 (first row must NOT be dropped)", len(result.Upgrade))
	}
	if result.Upgrade[0].PackageID != "7zip.7zip" {
		t.Errorf("PackageID = %q; want %q", result.Upgrade[0].PackageID, "7zip.7zip")
	}
	if result.Upgrade[0].InstalledVersion != "24.09" || result.Upgrade[0].AvailableVersion != "25.01" {
		t.Errorf("versions = (%q,%q); want (24.09,25.01)", result.Upgrade[0].InstalledVersion, result.Upgrade[0].AvailableVersion)
	}
	if result.UpgradeCount != 1 {
		t.Errorf("UpgradeCount = %d; want 1", result.UpgradeCount)
	}
}

func TestProbeOutdatedSoftwareTimeout(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	// Simulate the 60s budget elapsing: the exec error wraps
	// context.DeadlineExceeded. Must be classified WINGET_TIMEOUT (not
	// the generic WINGET_FAILED) so the backend can degrade/retry
	// distinctly.
	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return nil, fmt.Errorf("winget killed: %w", context.DeadlineExceeded)
	}

	result := ProbeOutdatedSoftware(context.Background(), time.Now)
	if len(result.ProbeErrors) == 0 {
		t.Fatal("Should have probe errors on timeout")
	}
	if result.ProbeErrors[0].Code != OutdatedSoftwareErrWinGetTimeout {
		t.Errorf("Code = %q; want %q", result.ProbeErrors[0].Code, OutdatedSoftwareErrWinGetTimeout)
	}
	if result.ProbeComplete {
		t.Error("ProbeComplete must be false on timeout (fail-closed)")
	}
}

func TestProbeOutdatedSoftwareParseFailure(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return []byte("some random text without table markers"), nil
	}

	result := ProbeOutdatedSoftware(context.Background(), time.Now)
	if len(result.ProbeErrors) == 0 {
		t.Fatal("Should have probe errors on parse failure")
	}
	if result.ProbeErrors[0].Code != OutdatedSoftwareErrWinGetParseError {
		t.Errorf("Code = %q; want %q", result.ProbeErrors[0].Code, OutdatedSoftwareErrWinGetParseError)
	}
}

func TestProbeOutdatedSoftwareDuration(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return []byte("No applicable upgrade packages found."), nil
	}

	// Deterministic monotonic clock: each call advances 5ms so the
	// elapsed (finalize now() - start) is fixed and positive — avoids a
	// sub-millisecond real-clock flake on a fast CI runner.
	var ticks int64
	clock := func() time.Time {
		ticks++
		return time.Unix(0, ticks*int64(5*time.Millisecond))
	}

	result := ProbeOutdatedSoftware(context.Background(), clock)
	if result.ProbeDurationMs <= 0 {
		t.Errorf("ProbeDurationMs = %d; want > 0", result.ProbeDurationMs)
	}
}

func TestProbeOutdatedSoftwareNilCtxWindows(t *testing.T) {
	result := ProbeOutdatedSoftware(nil, time.Now)
	if result.SchemaVersion == 0 {
		t.Errorf("SchemaVersion should be set; got %d", result.SchemaVersion)
	}
}
