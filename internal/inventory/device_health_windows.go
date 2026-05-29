//go:build windows

package inventory

import (
	"context"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// AG-033 Windows live runner — device health snapshot via direct
// Win32 syscalls. No PowerShell process, no JSON parse, no WMI
// provider dependency (Codex 019e7500 iter-1 AGREE: syscall path is
// the right call for this lean deployment-readiness probe).
//
// Sources:
//   - Disk: GetLogicalDrives + GetDriveType (filter DRIVE_FIXED) +
//     GetDiskFreeSpaceEx (freeBytesAvailableToCaller)
//   - Memory: GlobalMemoryStatusEx (custom proc; dwLength set)
//   - Uptime: DurationSinceBoot (GetTickCount64 under the hood;
//     uint64, no 49.7-day rollover)

// kernel32 + GlobalMemoryStatusEx binding. x/sys/windows provides
// GetLogicalDrives / GetDriveType / GetDiskFreeSpaceEx /
// DurationSinceBoot directly; only GlobalMemoryStatusEx needs a
// custom proc + struct.
var (
	modkernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX structure.
// dwLength MUST be set to sizeof(MEMORYSTATUSEX) before the call or
// the API fails (Codex iter-1 nice-to-have: most common bug).
type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

// runDeviceHealthMemory is a package var so tests can stub it.
var runDeviceHealthMemory = readMemoryStatusReal

func readMemoryStatusReal() (memoryStatusEx, error) {
	var m memoryStatusEx
	m.dwLength = uint32(unsafe.Sizeof(m))
	r1, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if r1 == 0 {
		return memoryStatusEx{}, err
	}
	return m, nil
}

// ProbeDeviceHealth is the Windows live runner entrypoint.
func ProbeDeviceHealth(ctx context.Context, now func() time.Time) DeviceHealthResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if now == nil {
		now = time.Now
	}
	start := now()
	result := DeviceHealthResult{
		SchemaVersion: DeviceHealthSchemaVersion,
		Supported:     true,
		SourceUsed:    DeviceHealthSourceWin32,
		MaxFixedDisks: MaxFixedDisks,
	}

	collectDeviceHealthDisks(&result)
	collectDeviceHealthMemory(&result)
	collectDeviceHealthUptime(now, &result)

	// Aggregate NO_EVIDENCE sentinel (Codex 019e7500 post-impl
	// clarification): fires ONLY when ALL THREE sources came back
	// empty together. A zero-fixed-disk host with valid memory +
	// uptime does NOT trip this — that gate is a backend-side
	// policy (fixedDiskCount==0 is not install-ready), NOT an agent
	// NO_EVIDENCE. See COMMAND-CONTRACT.md §15.5.
	if result.FixedDiskCount == 0 &&
		result.Memory.TotalPhysicalBytes == 0 &&
		result.Uptime.UptimeSeconds == 0 {
		result.ProbeErrors = append(result.ProbeErrors, DeviceHealthProbeError{
			Source:  DeviceHealthSourceNone,
			Code:    DeviceHealthErrNoEvidence,
			Summary: "device health probe produced no usable evidence",
		})
	}

	// If every source failed, downgrade SourceUsed to none.
	if len(result.ProbeErrors) > 0 &&
		result.FixedDiskCount == 0 &&
		result.Memory.TotalPhysicalBytes == 0 &&
		result.Uptime.UptimeSeconds == 0 {
		result.SourceUsed = DeviceHealthSourceNone
	}

	deriveDeviceHealthSummary(&result)
	result.ProbeDurationMs = deviceHealthElapsedMs(start, now)
	return result
}

// collectDeviceHealthDisks enumerates fixed volumes, computes
// per-volume health, applies the AnyLowDisk-before-truncation rule
// and the MaxFixedDisks cap.
func collectDeviceHealthDisks(result *DeviceHealthResult) {
	bitmask, err := windows.GetLogicalDrives()
	if err != nil {
		result.ProbeErrors = append(result.ProbeErrors, DeviceHealthProbeError{
			Source:  DeviceHealthSourceWin32,
			Code:    DeviceHealthErrDiskEnumFailed,
			Summary: "GetLogicalDrives failed",
		})
		return
	}

	var disks []FixedDiskHealth
	anyLow := false
	for i := 0; i < 26; i++ {
		if bitmask&(1<<uint(i)) == 0 {
			continue
		}
		letter := string(rune('A'+i)) + ":"
		rootPath := letter + `\`
		rootPtr, perr := windows.UTF16PtrFromString(rootPath)
		if perr != nil {
			continue
		}
		if windows.GetDriveType(rootPtr) != windows.DRIVE_FIXED {
			continue
		}
		var freeToCaller, totalBytes, totalFree uint64
		if derr := windows.GetDiskFreeSpaceEx(rootPtr, &freeToCaller, &totalBytes, &totalFree); derr != nil {
			// Per-volume failure: record a probe error, skip the
			// volume (do NOT emit a zero-byte "healthy" row —
			// Codex iter-1 MF-5).
			result.ProbeErrors = append(result.ProbeErrors, DeviceHealthProbeError{
				Source:  DeviceHealthSourceWin32,
				Code:    DeviceHealthErrDiskEnumFailed,
				Summary: "GetDiskFreeSpaceEx failed for a fixed volume",
			})
			continue
		}
		if totalBytes == 0 {
			// Degenerate; skip rather than emit free%=0/healthy.
			continue
		}
		freePercent := deviceHealthClampPercent(int(freeToCaller * 100 / totalBytes))
		free := clampInt64(freeToCaller)
		total := clampInt64(totalBytes)
		low := lowDiskWarning(free, freePercent)
		if low {
			anyLow = true
		}
		dl := normalizeDriveLetter(letter)
		if dl == "" {
			continue
		}
		disks = append(disks, FixedDiskHealth{
			DriveLetter:    dl,
			TotalBytes:     total,
			FreeBytes:      free,
			FreePercent:    freePercent,
			LowDiskWarning: low,
		})
	}

	// FixedDiskCount = full observed count (pre-truncation).
	result.FixedDiskCount = len(disks)
	// AnyLowDisk OR'd over ALL observed disks (Codex iter-0 MF-2).
	result.AnyLowDisk = anyLow

	// Stable sort by drive letter, then apply the cap.
	sort.SliceStable(disks, func(a, b int) bool {
		return disks[a].DriveLetter < disks[b].DriveLetter
	})
	if len(disks) > MaxFixedDisks {
		result.FixedDisks = disks[:MaxFixedDisks]
		result.FixedDisksTruncated = true
	} else {
		result.FixedDisks = disks
		result.FixedDisksTruncated = false
	}
}

// collectDeviceHealthMemory reads physical + commit memory.
func collectDeviceHealthMemory(result *DeviceHealthResult) {
	m, err := runDeviceHealthMemory()
	if err != nil || m.ullTotalPhys == 0 {
		result.ProbeErrors = append(result.ProbeErrors, DeviceHealthProbeError{
			Source:  DeviceHealthSourceWin32,
			Code:    DeviceHealthErrMemoryQueryFailed,
			Summary: "GlobalMemoryStatusEx failed or returned zero physical memory",
		})
		return
	}
	used := deviceHealthClampPercent(int(m.dwMemoryLoad))
	commitUsed := int64(0)
	if m.ullTotalPageFile >= m.ullAvailPageFile {
		commitUsed = clampInt64(m.ullTotalPageFile - m.ullAvailPageFile)
	}
	result.Memory = MemoryHealth{
		TotalPhysicalBytes:  clampInt64(m.ullTotalPhys),
		AvailableBytes:      clampInt64(m.ullAvailPhys),
		UsedPercent:         used,
		HighPressureWarning: used > HighMemoryUsedPercentThreshold,
		CommitLimitBytes:    clampInt64(m.ullTotalPageFile),
		CommitUsedBytes:     commitUsed,
	}
}

// collectDeviceHealthUptime derives uptime + last-boot epoch.
func collectDeviceHealthUptime(now func() time.Time, result *DeviceHealthResult) {
	d := windows.DurationSinceBoot()
	uptimeSec := int64(d / time.Second)
	if uptimeSec <= 0 {
		result.ProbeErrors = append(result.ProbeErrors, DeviceHealthProbeError{
			Source:  DeviceHealthSourceWin32,
			Code:    DeviceHealthErrUptimeQueryFailed,
			Summary: "system uptime query returned a non-positive duration",
		})
		return
	}
	nowSec := now().Unix()
	bootEpoch := nowSec - uptimeSec
	if bootEpoch <= 0 || bootEpoch > nowSec {
		// Clock skew / impossible boot time — fail closed rather
		// than emit a misleading healthy uptime (Codex iter-1 MF-5).
		result.ProbeErrors = append(result.ProbeErrors, DeviceHealthProbeError{
			Source:  DeviceHealthSourceWin32,
			Code:    DeviceHealthErrBootTimeFailed,
			Summary: "derived last-boot epoch is implausible",
		})
		return
	}
	days := int(uptimeSec / 86400)
	result.Uptime = UptimeHealth{
		LastBootEpochSec:  bootEpoch,
		UptimeSeconds:     uptimeSec,
		UptimeDays:        days,
		LongUptimeWarning: days > LongUptimeDaysThreshold,
	}
}

// normalizeDriveLetter validates a drive-letter string against
// ^[A-Z]:$ uppercase (Codex iter-0 MF-3). Returns "" if invalid.
func normalizeDriveLetter(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 2 || s[1] != ':' || s[0] < 'A' || s[0] > 'Z' {
		return ""
	}
	return s
}

// clampInt64 converts a uint64 byte count to int64, clamping at
// MaxInt64 to avoid a negative-on-overflow wrap (Codex iter-1
// nice-to-have: overflow guard before cast). Endpoint disks never
// approach 8 EiB, but the guard is cheap.
func clampInt64(v uint64) int64 {
	const maxInt64 = int64(^uint64(0) >> 1)
	if v > uint64(maxInt64) {
		return maxInt64
	}
	return int64(v)
}
