package inventory

import "time"

// AG-033 — Device Health Snapshot (Faz 22.5.2 posture quartet, final item).
//
// Read-only deployment-readiness health DERIVATION snapshot: fixed
// disk free %, physical memory utilization %, system uptime + last
// boot epoch, and commit/page-file summary. Answers "is this
// endpoint healthy enough to receive a software deployment right
// now?".
//
// Relationship to AG-035 (Codex 019e7500 iter-0 framing absorbed):
//   - AG-035 = raw hardware INVENTORY snapshot (static facts:
//     total RAM, disk free bytes, last boot timestamp).
//   - AG-033 = deployment-readiness health DERIVATION snapshot
//     (percentages, warning booleans, uptime duration).
//   AG-033 has NO runtime dependency on AG-035; the backend can
//   request includeDeviceHealth=true with includeHardware=false.
//
// "No performance-counter spam" boundary (faz-22 plan): point-in-time
// Win32 syscalls only — GetLogicalDrives / GetDriveTypeW /
// GetDiskFreeSpaceExW / GlobalMemoryStatusEx / DurationSinceBoot
// (GetTickCount64). NO Get-Counter, NO continuous sampling, NO
// per-process enumeration, NO WMI perfcounter polling.
//
// Codex 019e7500 cross-AI peer-review chain: iter-0 PARTIAL (6
// contract must_fix) → iter-1 AGREE / ready_for_impl=true.

const DeviceHealthSchemaVersion = 1

// MaxFixedDisks bounds the FixedDisks wire slice. The drive-letter
// namespace is only A-Z (26) but the cap guards against odd or
// malicious enumeration (Codex iter-0 MF-1).
const MaxFixedDisks = 64

// Health thresholds — const, NOT payload-configurable (Codex iter-0
// MF-6). The backend can re-derive different thresholds from the
// raw bytes/days it also receives.
const (
	// LowDiskPercentThreshold: freePercent below this flips
	// lowDiskWarning.
	LowDiskPercentThreshold = 10
	// LowDiskBytesThreshold: freeBytes below this (2 GiB) flips
	// lowDiskWarning regardless of percent (large disks can be
	// <10% but still have plenty; small disks can be >10% but
	// critically low in absolute terms).
	LowDiskBytesThreshold = 2 * 1024 * 1024 * 1024
	// HighMemoryUsedPercentThreshold: usedPercent above this flips
	// highPressureWarning.
	HighMemoryUsedPercentThreshold = 90
	// LongUptimeDaysThreshold: uptimeDays above this flips
	// longUptimeWarning (reboot-hygiene signal; correlates with
	// AG-030 pending-reboot).
	LongUptimeDaysThreshold = 30
)

// DeviceHealthProbeSource is win32/none only (Codex iter-0 MF-4):
// the probe reads exclusively via direct Win32 syscalls, so there
// is no transport-vs-datasource ambiguity.
type DeviceHealthProbeSource string

const (
	DeviceHealthSourceWin32 DeviceHealthProbeSource = "win32"
	DeviceHealthSourceNone  DeviceHealthProbeSource = "none"
)

// DeviceHealthProbeError code constants. Stable enum; expansion
// additive.
const (
	DeviceHealthErrUnsupportedPlatform = "UNSUPPORTED_PLATFORM"
	DeviceHealthErrDiskEnumFailed      = "DISK_ENUM_FAILED"
	DeviceHealthErrMemoryQueryFailed   = "MEMORY_QUERY_FAILED"
	DeviceHealthErrUptimeQueryFailed   = "UPTIME_QUERY_FAILED"
	DeviceHealthErrBootTimeFailed      = "BOOT_TIME_FAILED"
	DeviceHealthErrNoEvidence          = "NO_EVIDENCE"
)

// DeviceHealthProbeError is the per-source structured failure
// carrier. Summary is bounded operator-facing text (capped 200
// chars, control-char normalized, static phrasing — never a raw
// syscall errno dump or a full filesystem path).
type DeviceHealthProbeError struct {
	Source  DeviceHealthProbeSource `json:"source,omitempty"`
	Code    string                  `json:"code"`
	Summary string                  `json:"summary,omitempty"`
}

// FixedDiskHealth is one fixed (DRIVE_FIXED) logical volume's
// health. DriveLetter is validated to ^[A-Z]:$ uppercase (Codex
// iter-0 MF-3). Volume labels, serial numbers, file-system types,
// mount paths, and volume GUIDs are NEVER surfaced — only the
// drive letter (needed so the operator knows WHICH volume is low)
// plus byte totals + derived percent/warning.
//
// FreeBytes is freeBytesAvailableToCaller (Codex iter-1
// nice-to-have): the bytes the agent's run context (LocalSystem)
// can actually write, which is the right denominator for a
// "can this install succeed?" gate — not the raw physical free
// which quota/job limits may not reflect.
type FixedDiskHealth struct {
	DriveLetter    string `json:"driveLetter"`
	TotalBytes     int64  `json:"totalBytes"`
	FreeBytes      int64  `json:"freeBytes"`
	FreePercent    int    `json:"freePercent"`
	LowDiskWarning bool   `json:"lowDiskWarning"`
}

// MemoryHealth carries physical memory utilization + a
// commit/page-file summary derived from MEMORYSTATUSEX. The commit
// fields are an approximation from MEMORYSTATUSEX
// (ullTotalPageFile / ullAvailPageFile), NOT an exact per-pagefile
// or per-process accounting (Codex iter-1 nice-to-have).
type MemoryHealth struct {
	TotalPhysicalBytes  int64 `json:"totalPhysicalBytes"`
	AvailableBytes      int64 `json:"availableBytes"`
	UsedPercent         int   `json:"usedPercent"`
	HighPressureWarning bool  `json:"highPressureWarning"`
	CommitLimitBytes    int64 `json:"commitLimitBytes"`
	CommitUsedBytes     int64 `json:"commitUsedBytes"`
}

// UptimeHealth carries system uptime + last-boot epoch.
// LastBootEpochSec is unix seconds (NOT a local-time string) to
// avoid leaking timezone/locale (Codex iter-0 concern).
type UptimeHealth struct {
	LastBootEpochSec  int64 `json:"lastBootEpochSec"`
	UptimeSeconds     int64 `json:"uptimeSeconds"`
	UptimeDays        int   `json:"uptimeDays"`
	LongUptimeWarning bool  `json:"longUptimeWarning"`
}

// DeviceHealthResult is the wire-safe outcome. Snapshot includes it
// via *DeviceHealthResult json:"deviceHealth,omitempty"; pointer is
// nil when the caller did not opt in.
//
// FixedDisks ALWAYS serializes as `[]` (never null). FixedDiskCount
// is the pre-truncation observed count; AnyLowDisk is OR'd over the
// full pre-truncation enumeration (Codex iter-0 MF-1 + MF-2).
type DeviceHealthResult struct {
	SchemaVersion       int                      `json:"schemaVersion"`
	Supported           bool                     `json:"supported"`
	ProbeComplete       bool                     `json:"probeComplete"`
	FixedDisks          []FixedDiskHealth        `json:"fixedDisks"`
	FixedDiskCount      int                      `json:"fixedDiskCount"`
	FixedDisksTruncated bool                     `json:"fixedDisksTruncated"`
	MaxFixedDisks       int                      `json:"maxFixedDisks"`
	Memory              MemoryHealth             `json:"memory"`
	Uptime              UptimeHealth             `json:"uptime"`
	AnyLowDisk          bool                     `json:"anyLowDisk"`
	SourceUsed          DeviceHealthProbeSource  `json:"sourceUsed"`
	ProbeErrors         []DeviceHealthProbeError `json:"probeErrors,omitempty"`
	ProbeDurationMs     int                      `json:"probeDurationMs"`
}

// deviceHealthClampPercent clamps an integer percent to 0..100
// (Codex iter-1 nice-to-have). Used for both disk free% and memory
// used%.
func deviceHealthClampPercent(n int) int {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

// deriveDeviceHealthSummary fills ProbeComplete + AnyLowDisk +
// the warning booleans, and normalizes FixedDisks to non-nil so
// the `fixedDisks:[]` JSON contract holds on every path.
func deriveDeviceHealthSummary(result *DeviceHealthResult) {
	if result.FixedDisks == nil {
		result.FixedDisks = make([]FixedDiskHealth, 0)
	}
	if result.MaxFixedDisks == 0 {
		result.MaxFixedDisks = MaxFixedDisks
	}
	result.ProbeComplete = len(result.ProbeErrors) == 0
}

// deviceHealthElapsedMs is the monotonic-duration helper.
func deviceHealthElapsedMs(start time.Time, now func() time.Time) int {
	if now == nil {
		now = time.Now
	}
	return int(now().Sub(start) / time.Millisecond)
}

// lowDiskWarning applies the LowDisk thresholds.
func lowDiskWarning(freeBytes int64, freePercent int) bool {
	return freePercent < LowDiskPercentThreshold || freeBytes < LowDiskBytesThreshold
}
