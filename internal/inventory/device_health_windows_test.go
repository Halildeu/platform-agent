//go:build windows

package inventory

import (
	"context"
	"errors"
	"testing"
	"time"
)

// AG-033 Windows-only tests. The disk + uptime syscalls run against
// the real host (the CI Windows runner has real fixed volumes and a
// real boot time), so those are exercised end-to-end by
// ProbeDeviceHealth. The memory path is stubbable so we can lock the
// degenerate-value fail-closed behavior (Codex iter-1 MF-5) and the
// commit-charge derivation without depending on host RAM values.

func stubDeviceHealthMemory(t *testing.T, m memoryStatusEx, err error) {
	t.Helper()
	prev := runDeviceHealthMemory
	runDeviceHealthMemory = func() (memoryStatusEx, error) { return m, err }
	t.Cleanup(func() { runDeviceHealthMemory = prev })
}

// MF-5: GlobalMemoryStatusEx failure must produce MEMORY_QUERY_FAILED
// + probeComplete=false, NOT a healthy usedPercent=0 row.
func TestProbeDeviceHealth_MemoryFailure_FailsClosed(t *testing.T) {
	stubDeviceHealthMemory(t, memoryStatusEx{}, errors.New("boom"))
	got := ProbeDeviceHealth(context.Background(), time.Now)
	foundMemErr := false
	for _, e := range got.ProbeErrors {
		if e.Code == DeviceHealthErrMemoryQueryFailed {
			foundMemErr = true
		}
	}
	if !foundMemErr {
		t.Fatalf("expected MEMORY_QUERY_FAILED in probeErrors, got %#v", got.ProbeErrors)
	}
	if got.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false after memory failure")
	}
	if got.Memory.UsedPercent != 0 || got.Memory.TotalPhysicalBytes != 0 {
		t.Fatalf("expected zero memory struct on failure (not emitted as healthy), got %#v", got.Memory)
	}
}

// MF-5: ullTotalPhys==0 is also a failure (degenerate readout).
func TestProbeDeviceHealth_ZeroTotalPhys_FailsClosed(t *testing.T) {
	stubDeviceHealthMemory(t, memoryStatusEx{dwMemoryLoad: 0, ullTotalPhys: 0}, nil)
	got := ProbeDeviceHealth(context.Background(), time.Now)
	foundMemErr := false
	for _, e := range got.ProbeErrors {
		if e.Code == DeviceHealthErrMemoryQueryFailed {
			foundMemErr = true
		}
	}
	if !foundMemErr {
		t.Fatalf("expected MEMORY_QUERY_FAILED when ullTotalPhys=0, got %#v", got.ProbeErrors)
	}
}

// Successful memory readout: usedPercent reflects dwMemoryLoad,
// commit derived correctly, high-pressure warning honors threshold.
func TestProbeDeviceHealth_MemorySuccess(t *testing.T) {
	const giB = uint64(1024 * 1024 * 1024)
	stubDeviceHealthMemory(t, memoryStatusEx{
		dwMemoryLoad:     95, // > 90 → high pressure
		ullTotalPhys:     16 * giB,
		ullAvailPhys:     1 * giB,
		ullTotalPageFile: 32 * giB,
		ullAvailPageFile: 8 * giB,
	}, nil)
	got := ProbeDeviceHealth(context.Background(), time.Now)
	if got.Memory.TotalPhysicalBytes != int64(16*giB) {
		t.Errorf("TotalPhysicalBytes = %d, want %d", got.Memory.TotalPhysicalBytes, 16*giB)
	}
	if got.Memory.UsedPercent != 95 {
		t.Errorf("UsedPercent = %d, want 95", got.Memory.UsedPercent)
	}
	if !got.Memory.HighPressureWarning {
		t.Errorf("expected HighPressureWarning=true at 95%%")
	}
	if got.Memory.CommitLimitBytes != int64(32*giB) {
		t.Errorf("CommitLimitBytes = %d, want %d", got.Memory.CommitLimitBytes, 32*giB)
	}
	// commitUsed = total(32) - avail(8) = 24 GiB
	if got.Memory.CommitUsedBytes != int64(24*giB) {
		t.Errorf("CommitUsedBytes = %d, want %d", got.Memory.CommitUsedBytes, 24*giB)
	}
}

func TestProbeDeviceHealth_MemoryLowPressureNoWarning(t *testing.T) {
	const giB = uint64(1024 * 1024 * 1024)
	stubDeviceHealthMemory(t, memoryStatusEx{
		dwMemoryLoad:     40,
		ullTotalPhys:     16 * giB,
		ullAvailPhys:     10 * giB,
		ullTotalPageFile: 32 * giB,
		ullAvailPageFile: 20 * giB,
	}, nil)
	got := ProbeDeviceHealth(context.Background(), time.Now)
	if got.Memory.HighPressureWarning {
		t.Errorf("expected HighPressureWarning=false at 40%%")
	}
}

// Disk + uptime run against the real host. We assert the shape is
// sane (at least one fixed disk on a CI Windows runner, drive
// letters normalized, uptime positive) without asserting exact
// values.
func TestProbeDeviceHealth_RealHost_DiskAndUptimeSane(t *testing.T) {
	const giB = uint64(1024 * 1024 * 1024)
	stubDeviceHealthMemory(t, memoryStatusEx{
		dwMemoryLoad: 30, ullTotalPhys: 8 * giB, ullAvailPhys: 4 * giB,
		ullTotalPageFile: 16 * giB, ullAvailPageFile: 10 * giB,
	}, nil)
	got := ProbeDeviceHealth(context.Background(), time.Now)

	if got.SchemaVersion != DeviceHealthSchemaVersion {
		t.Errorf("schemaVersion = %d", got.SchemaVersion)
	}
	if !got.Supported {
		t.Errorf("expected Supported=true on Windows")
	}
	// CI runner has at least C:.
	if got.FixedDiskCount < 1 {
		t.Errorf("expected at least 1 fixed disk on Windows runner, got %d", got.FixedDiskCount)
	}
	for _, d := range got.FixedDisks {
		if normalizeDriveLetter(d.DriveLetter) != d.DriveLetter {
			t.Errorf("drive letter %q not normalized", d.DriveLetter)
		}
		if d.FreePercent < 0 || d.FreePercent > 100 {
			t.Errorf("freePercent out of range: %d", d.FreePercent)
		}
		if d.TotalBytes <= 0 {
			t.Errorf("totalBytes must be positive for an emitted disk: %d", d.TotalBytes)
		}
	}
	// Uptime should be positive on a running host.
	if got.Uptime.UptimeSeconds <= 0 {
		t.Errorf("expected positive uptime, got %d", got.Uptime.UptimeSeconds)
	}
	if got.Uptime.LastBootEpochSec <= 0 {
		t.Errorf("expected positive last-boot epoch, got %d", got.Uptime.LastBootEpochSec)
	}
}

// normalizeDriveLetter unit tests (validation defense-in-depth).
func TestNormalizeDriveLetter(t *testing.T) {
	cases := map[string]string{
		"C:":    "C:",
		"c:":    "C:",
		"  D: ": "D:",
		"Z:":    "Z:",
		"":      "",
		"C":     "",
		"C:\\":  "",
		"CC:":   "",
		"1:":    "",
		"::":    "",
	}
	for in, want := range cases {
		if got := normalizeDriveLetter(in); got != want {
			t.Errorf("normalizeDriveLetter(%q) = %q, want %q", in, got, want)
		}
	}
}

// clampInt64 overflow guard.
func TestClampInt64(t *testing.T) {
	if got := clampInt64(0); got != 0 {
		t.Errorf("clampInt64(0) = %d", got)
	}
	if got := clampInt64(12345); got != 12345 {
		t.Errorf("clampInt64(12345) = %d", got)
	}
	// uint64 max → clamped to int64 max, never negative.
	maxU := ^uint64(0)
	got := clampInt64(maxU)
	if got < 0 {
		t.Errorf("clampInt64(maxUint64) must not be negative, got %d", got)
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	if got != maxInt64 {
		t.Errorf("clampInt64(maxUint64) = %d, want %d", got, maxInt64)
	}
}
