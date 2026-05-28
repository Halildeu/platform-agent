//go:build windows

package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// AG-035 — Windows hardware probe via PowerShell + Get-CimInstance.
//
// Wire model: a single PowerShell process executes a fixed,
// inline-embedded script that runs read-only CIM queries
// (Win32_ComputerSystem / Win32_OperatingSystem / Win32_Processor /
// Win32_BIOS / Win32_LogicalDisk / Win32_NetworkAdapterConfiguration)
// and emits one compact JSON document. The Go side decodes the
// document (see wmiPayload in hardware_mapping.go) and folds it into
// the canonical Hardware shape declared in hardware.go.
//
// Why single-shot vs per-class exec:
//
//   - Each PowerShell invocation pays a 200-800ms startup penalty for
//     the CLR / module load. Six classes would cost ~1.5-5s of pure
//     startup before any CIM work begins.
//   - LocalSystem (the SCM service account the production agent runs
//     under) can serialise CIM access; six separate invocations
//     amplify any contention.
//   - A single ConvertTo-Json roundtrip gives us one fail-closed
//     parse path; per-class would multiply the parser / partial-state
//     surface.
//
// What we don't emit (BE-022 V14 sanitiser parity):
//
//   - Disk serials, BIOS serials, system serials, system UUID.
//   - Machine SID / GUID strings.
//   - User home paths.
//
// The backend HardwareInventoryPayloadPolicy still strips these as a
// defence-in-depth, but keeping the agent payload narrow turns the
// policy into a precise check rather than a wide net.
//
// Timeout: a hung WMI provider (notably classic disk drivers on
// virtualised hosts) can stall well past the default agent command
// timeout. The collector uses a context with a fixed 30s deadline so
// COLLECT_INVENTORY runs that would otherwise wedge an attempt slot
// surface a CIM_TIMEOUT probe error and a Supported=false snapshot
// instead of failing the whole command.
const hardwareWMITimeout = 30 * time.Second

// Embedded PowerShell. Kept as a raw string so the lexer does not eat
// the embedded `$` characters. The script is deliberately minimal: no
// loops over potentially-unbounded enumerations, no string
// concatenation of CIM scalars (every leak vector the backend strip /
// reject keys cover is a scalar at this layer).
//
// Note: we ask for ConvertTo-Json with -Depth 5 so the nested
// IPAddress arrays survive. Compress so the wire stays compact.
const hardwareProbeScript = `
$ErrorActionPreference = 'Continue'

function SafeCim {
    param([string]$class, [string]$filter)
    try {
        if ($filter) {
            return Get-CimInstance -ClassName $class -Filter $filter -ErrorAction Stop
        }
        return Get-CimInstance -ClassName $class -ErrorAction Stop
    } catch {
        return $null
    }
}

$cs = SafeCim 'Win32_ComputerSystem' ''
$os = SafeCim 'Win32_OperatingSystem' ''
$cpuRaw = SafeCim 'Win32_Processor' ''
$cpu = if ($cpuRaw) { $cpuRaw | Select-Object -First 1 } else { $null }
$bios = SafeCim 'Win32_BIOS' ''
$disks = SafeCim 'Win32_LogicalDisk' 'DriveType=3'
$nics = SafeCim 'Win32_NetworkAdapterConfiguration' 'IPEnabled=True'

$diskOut = @()
if ($disks) {
    foreach ($d in $disks) {
        $diskOut += [PSCustomObject]@{
            devicePath    = $d.DeviceID
            fileSystem    = $d.FileSystem
            capacityBytes = $d.Size
            freeBytes     = $d.FreeSpace
        }
    }
}

$nicOut = @()
if ($nics) {
    foreach ($n in $nics) {
        $ips = @()
        if ($n.IPAddress) {
            foreach ($ip in $n.IPAddress) {
                if ($ip -and ($ip -notlike '*:*')) { $ips += $ip }
            }
        }
        $nicOut += [PSCustomObject]@{
            description = $n.Description
            mac         = $n.MACAddress
            ipAddresses = $ips
        }
    }
}

$lastBoot = $null
if ($os -and $os.LastBootUpTime) {
    try { $lastBoot = $os.LastBootUpTime.ToString('o') } catch { $lastBoot = $null }
}

$out = [PSCustomObject]@{
    cs   = if ($cs)   { [PSCustomObject]@{ manufacturer=$cs.Manufacturer; model=$cs.Model; domain=$cs.Domain; partOfDomain=$cs.PartOfDomain; totalPhysicalMemory=$cs.TotalPhysicalMemory } } else { $null }
    os   = if ($os)   { [PSCustomObject]@{ caption=$os.Caption; version=$os.Version; osArch=$os.OSArchitecture; lastBootUpTime=$lastBoot; totalVisibleMemoryKiB=$os.TotalVisibleMemorySize; freePhysicalMemoryKiB=$os.FreePhysicalMemory } } else { $null }
    cpu  = if ($cpu)  { [PSCustomObject]@{ name=$cpu.Name; numberOfCores=$cpu.NumberOfCores; maxClockSpeed=$cpu.MaxClockSpeed } } else { $null }
    bios = if ($bios) { [PSCustomObject]@{ manufacturer=$bios.Manufacturer; smbiosBiosVersion=$bios.SMBIOSBIOSVersion } } else { $null }
    disks = $diskOut
    networkInterfaces = $nicOut
}

$out | ConvertTo-Json -Depth 5 -Compress
`

// runHardwareProbe shells out to powershell.exe with a fixed-deadline
// context. Kept as a package variable so unit tests can override it
// with a deterministic stub (no real powershell needed in the test
// runner).
var runHardwareProbe = runHardwareProbeReal

func runHardwareProbeReal(ctx context.Context) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", hardwareProbeScript)
	return cmd.Output()
}

// collectHardwareWindows is the production hardware collector. It is
// installed into collectHardwareImpl via the build-tagged init() so
// the cross-platform CollectHardware entry point routes here without
// per-call OS branching.
func collectHardwareWindows(now time.Time) Hardware {
	hw := Hardware{
		SchemaVersion: HardwareSchemaVersion,
		OSName:        runtime.GOOS,
		OSArch:        runtime.GOARCH,
		CollectedAt:   now,
	}

	ctx, cancel := context.WithTimeout(context.Background(), hardwareWMITimeout)
	defer cancel()

	raw, err := runHardwareProbe(ctx)
	if err != nil {
		hw.Supported = false
		hw.ProbeErrors = append(hw.ProbeErrors, HardwareProbeError{
			Code:    classifyProbeError(ctx, err),
			Summary: bound256(fmt.Sprintf("powershell hardware probe failed: %v", err)),
		})
		return hw
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		hw.Supported = false
		hw.ProbeErrors = append(hw.ProbeErrors, HardwareProbeError{
			Code:    "CIM_EMPTY_OUTPUT",
			Summary: "powershell hardware probe produced no output",
		})
		return hw
	}

	var payload wmiPayload
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		hw.Supported = false
		hw.ProbeErrors = append(hw.ProbeErrors, HardwareProbeError{
			Code:    "CIM_PARSE_ERROR",
			Summary: bound256(fmt.Sprintf("hardware probe JSON decode failed: %v", err)),
		})
		return hw
	}

	// Codex 019e709c post-impl iter-1 must-fix #2 — guard against an
	// all-null WMI document. SafeCim in the PowerShell script swallows
	// per-class failures and returns $null, so a degraded runtime
	// (WMI service stopped, security policy blocks CIM, every class
	// errored) still parses cleanly. We treat "no class produced
	// evidence" as a CIM_NO_DATA failure rather than letting the
	// snapshot ship Supported=true with zero CPU cores and zero RAM —
	// a quietly false "I succeeded" signal that the backend has no
	// principled way to distinguish from a real probe.
	if !payloadHasEvidence(payload) {
		hw.Supported = false
		hw.ProbeErrors = append(hw.ProbeErrors, HardwareProbeError{
			Code:    "CIM_NO_DATA",
			Summary: "powershell hardware probe returned no evidence (every WMI class was null or empty)",
		})
		return hw
	}

	hw.Supported = true
	mapWMIPayload(&hw, payload)
	return hw
}

func init() {
	collectHardwareImpl = collectHardwareWindows
}
