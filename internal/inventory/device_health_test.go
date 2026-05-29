package inventory

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

// AG-033 — cross-platform tests for the device health probe.
// Windows syscall path has its own //go:build windows test file;
// these lock the wire shape, derive helper, enum stability,
// threshold helpers, and opt-in / opt-out behavior.

// ────────────────────────────────────────────────────────────────
// deriveDeviceHealthSummary

func TestDeriveDeviceHealthSummary_EmptyErrorsProbeComplete(t *testing.T) {
	result := DeviceHealthResult{}
	deriveDeviceHealthSummary(&result)
	if !result.ProbeComplete {
		t.Fatalf("expected ProbeComplete=true with no errors")
	}
	if result.FixedDisks == nil {
		t.Fatalf("expected non-nil FixedDisks after derive")
	}
	if result.MaxFixedDisks != MaxFixedDisks {
		t.Fatalf("expected MaxFixedDisks=%d, got %d", MaxFixedDisks, result.MaxFixedDisks)
	}
}

func TestDeriveDeviceHealthSummary_AnyErrorFlipsProbeComplete(t *testing.T) {
	result := DeviceHealthResult{
		ProbeErrors: []DeviceHealthProbeError{
			{Source: DeviceHealthSourceWin32, Code: DeviceHealthErrMemoryQueryFailed},
		},
	}
	deriveDeviceHealthSummary(&result)
	if result.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false with probe errors")
	}
}

// ────────────────────────────────────────────────────────────────
// clampPercent

func TestDeviceHealthClampPercent(t *testing.T) {
	cases := map[int]int{-5: 0, 0: 0, 50: 50, 100: 100, 101: 100, 250: 100}
	for in, want := range cases {
		if got := deviceHealthClampPercent(in); got != want {
			t.Errorf("clampPercent(%d) = %d, want %d", in, got, want)
		}
	}
}

// ────────────────────────────────────────────────────────────────
// lowDiskWarning thresholds

func TestLowDiskWarning(t *testing.T) {
	const giB = 1024 * 1024 * 1024
	cases := []struct {
		name       string
		freeBytes  int64
		freePct    int
		wantWarn   bool
	}{
		{"healthy", 100 * giB, 50, false},
		{"low-percent", 5 * giB, 5, true},                // <10%
		{"low-bytes", 1 * giB, 50, true},                 // <2GiB even at 50%
		{"boundary-percent-10", 100 * giB, 10, false},    // exactly 10% not <10
		{"boundary-percent-9", 100 * giB, 9, true},       // <10
		{"boundary-bytes-2giB", 2 * giB, 50, false},      // exactly 2GiB not <2GiB
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lowDiskWarning(tc.freeBytes, tc.freePct); got != tc.wantWarn {
				t.Errorf("lowDiskWarning(%d, %d) = %v, want %v", tc.freeBytes, tc.freePct, got, tc.wantWarn)
			}
		})
	}
}

// ────────────────────────────────────────────────────────────────
// JSON contract — no leaked identifier fields, fixedDisks always [].

func TestDeviceHealthResult_JSONContract_NoLeakedFields(t *testing.T) {
	result := DeviceHealthResult{
		SchemaVersion: DeviceHealthSchemaVersion,
		Supported:     true,
		FixedDisks: []FixedDiskHealth{
			{DriveLetter: "C:", TotalBytes: 500 * 1024 * 1024 * 1024, FreeBytes: 250 * 1024 * 1024 * 1024, FreePercent: 50, LowDiskWarning: false},
		},
		FixedDiskCount: 1,
		Memory:         MemoryHealth{TotalPhysicalBytes: 16 * 1024 * 1024 * 1024, UsedPercent: 42},
		Uptime:         UptimeHealth{UptimeDays: 3, UptimeSeconds: 3 * 86400},
		SourceUsed:     DeviceHealthSourceWin32,
	}
	deriveDeviceHealthSummary(&result)
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	s := string(raw)

	// Forbidden: volume identifiers / paths must never appear.
	forbidden := []string{
		`"volumeSerial"`, `"serialNumber"`, `"volumeLabel"`, `"label"`,
		`"fileSystem"`, `"fileSystemType"`,
		`"mountPath"`, `"mountPoint"`, `"path"`, `"rootPath"`,
		`"volumeGuid"`, `"volumeGUID"`, `"volumeId"`,
		`"lastBootLocalTime"`, `"lastBootString"`, `"timezone"`,
	}
	for _, frag := range forbidden {
		if strings.Contains(s, frag) {
			t.Errorf("forbidden field %q leaked to JSON: %s", frag, s)
		}
	}

	// Required structural fields.
	required := []string{
		`"fixedDisks":[`,
		`"driveLetter":"C:"`,
		`"freePercent":50`,
		`"fixedDiskCount":1`,
		`"maxFixedDisks":64`,
		`"usedPercent":42`,
		`"lastBootEpochSec":`,
		`"sourceUsed":"win32"`,
		`"schemaVersion":1`,
	}
	for _, frag := range required {
		if !strings.Contains(s, frag) {
			t.Errorf("expected required field %q in JSON, got %s", frag, s)
		}
	}
}

func TestDeviceHealthResult_JSONContract_FixedDisksEmptyArray(t *testing.T) {
	result := DeviceHealthResult{
		SchemaVersion: DeviceHealthSchemaVersion,
		Supported:     true,
		SourceUsed:    DeviceHealthSourceNone,
	}
	deriveDeviceHealthSummary(&result)
	raw, _ := json.Marshal(result)
	s := string(raw)
	if !strings.Contains(s, `"fixedDisks":[]`) {
		t.Fatalf(`expected "fixedDisks":[] in output, got %s`, s)
	}
	if strings.Contains(s, `"fixedDisks":null`) {
		t.Fatalf(`fixedDisks MUST NOT serialize as null, got %s`, s)
	}
}

// ────────────────────────────────────────────────────────────────
// enum stability

func TestDeviceHealthProbeSource_Values(t *testing.T) {
	if string(DeviceHealthSourceWin32) != "win32" {
		t.Errorf("DeviceHealthSourceWin32 != win32")
	}
	if string(DeviceHealthSourceNone) != "none" {
		t.Errorf("DeviceHealthSourceNone != none")
	}
}

func TestDeviceHealthProbeError_Codes(t *testing.T) {
	wanted := map[string]string{
		"UNSUPPORTED_PLATFORM": DeviceHealthErrUnsupportedPlatform,
		"DISK_ENUM_FAILED":     DeviceHealthErrDiskEnumFailed,
		"MEMORY_QUERY_FAILED":  DeviceHealthErrMemoryQueryFailed,
		"UPTIME_QUERY_FAILED":  DeviceHealthErrUptimeQueryFailed,
		"BOOT_TIME_FAILED":     DeviceHealthErrBootTimeFailed,
		"NO_EVIDENCE":          DeviceHealthErrNoEvidence,
	}
	for want, got := range wanted {
		if got != want {
			t.Errorf("expected code %q, got %q", want, got)
		}
	}
}

func TestDeviceHealthThresholds(t *testing.T) {
	if LowDiskPercentThreshold != 10 {
		t.Errorf("LowDiskPercentThreshold = %d, want 10", LowDiskPercentThreshold)
	}
	if LowDiskBytesThreshold != 2*1024*1024*1024 {
		t.Errorf("LowDiskBytesThreshold = %d, want 2GiB", LowDiskBytesThreshold)
	}
	if HighMemoryUsedPercentThreshold != 90 {
		t.Errorf("HighMemoryUsedPercentThreshold = %d, want 90", HighMemoryUsedPercentThreshold)
	}
	if LongUptimeDaysThreshold != 30 {
		t.Errorf("LongUptimeDaysThreshold = %d, want 30", LongUptimeDaysThreshold)
	}
	if MaxFixedDisks != 64 {
		t.Errorf("MaxFixedDisks = %d, want 64", MaxFixedDisks)
	}
}

// ────────────────────────────────────────────────────────────────
// non-Windows stub

func TestProbeDeviceHealth_NonWindowsStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses the live runner")
	}
	t0 := time.Unix(1700000000, 0)
	calls := 0
	clock := func() time.Time {
		calls++
		return t0.Add(time.Duration(calls-1) * 2 * time.Millisecond)
	}
	got := ProbeDeviceHealth(nil, clock)
	if got.Supported {
		t.Fatalf("expected Supported=false on %s", runtime.GOOS)
	}
	if got.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false on stub")
	}
	if got.SchemaVersion != DeviceHealthSchemaVersion {
		t.Fatalf("schemaVersion = %d, want %d", got.SchemaVersion, DeviceHealthSchemaVersion)
	}
	if got.SourceUsed != DeviceHealthSourceNone {
		t.Fatalf("expected SourceUsed=none, got %q", got.SourceUsed)
	}
	if got.FixedDisks == nil || len(got.FixedDisks) != 0 {
		t.Fatalf("expected empty non-nil FixedDisks, got %#v", got.FixedDisks)
	}
	if got.MaxFixedDisks != MaxFixedDisks {
		t.Fatalf("expected MaxFixedDisks=%d, got %d", MaxFixedDisks, got.MaxFixedDisks)
	}
	if len(got.ProbeErrors) != 1 || got.ProbeErrors[0].Code != DeviceHealthErrUnsupportedPlatform {
		t.Fatalf("expected single UNSUPPORTED_PLATFORM error, got %#v", got.ProbeErrors)
	}
	if !strings.Contains(got.ProbeErrors[0].Summary, runtime.GOOS) {
		t.Fatalf("expected summary to mention runtime %q", runtime.GOOS)
	}
}

// ────────────────────────────────────────────────────────────────
// CollectWithOptions opt-in / opt-out

func TestCollectWithOptions_DeviceHealthOptOut(t *testing.T) {
	invoked := false
	restore := withCollectDeviceHealthForSnapshot(func(_ time.Time) DeviceHealthResult {
		invoked = true
		return DeviceHealthResult{}
	})
	defer restore()
	snap := CollectWithOptions("test", time.Unix(1700000000, 0), CollectOptions{})
	if invoked {
		t.Fatalf("device health probe must not run when opt-out")
	}
	if snap.DeviceHealth != nil {
		t.Fatalf("snapshot.DeviceHealth must be nil when opt-out")
	}
}

func TestCollectWithOptions_DeviceHealthOptIn(t *testing.T) {
	sentinel := DeviceHealthResult{
		SchemaVersion: DeviceHealthSchemaVersion,
		Supported:     true,
		ProbeComplete: true,
		SourceUsed:    DeviceHealthSourceWin32,
	}
	calls := 0
	restore := withCollectDeviceHealthForSnapshot(func(_ time.Time) DeviceHealthResult {
		calls++
		return sentinel
	})
	defer restore()
	snap := CollectWithOptions("test", time.Unix(1700000000, 0),
		CollectOptions{IncludeDeviceHealth: true})
	if calls != 1 {
		t.Fatalf("expected probe invocation count = 1, got %d", calls)
	}
	if snap.DeviceHealth == nil {
		t.Fatalf("snapshot.DeviceHealth must be set when opt-in")
	}
	if snap.DeviceHealth.SchemaVersion != DeviceHealthSchemaVersion {
		t.Fatalf("schemaVersion mismatch")
	}
}

// ────────────────────────────────────────────────────────────────
// helpers

func withCollectDeviceHealthForSnapshot(stub func(time.Time) DeviceHealthResult) func() {
	prev := collectDeviceHealthForSnapshot
	collectDeviceHealthForSnapshot = stub
	return func() { collectDeviceHealthForSnapshot = prev }
}
