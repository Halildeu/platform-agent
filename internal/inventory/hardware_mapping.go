package inventory

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// wmiPayload is the intermediate decoded shape produced by the
// PowerShell hardware probe (hardware_windows.go). It is kept in a
// cross-platform file so mapWMIPayload can be unit-tested against a
// fixture without depending on the build-tagged Windows entry point.
//
// Field tags are lowerCamelCase to match the PowerShell ConvertTo-Json
// output the probe emits. Any new probe data point should be added here
// first (so the test suite can assert mapping), then surfaced through
// the canonical Hardware shape in hardware.go.
type wmiPayload struct {
	CS                *wmiCS    `json:"cs"`
	OS                *wmiOS    `json:"os"`
	CPU               *wmiCPU   `json:"cpu"`
	BIOS              *wmiBIOS  `json:"bios"`
	Disks             []wmiDisk `json:"disks"`
	NetworkInterfaces []wmiNIC  `json:"networkInterfaces"`
}

type wmiCS struct {
	Manufacturer        string `json:"manufacturer"`
	Model               string `json:"model"`
	Domain              string `json:"domain"`
	PartOfDomain        bool   `json:"partOfDomain"`
	TotalPhysicalMemory uint64 `json:"totalPhysicalMemory"`
}

type wmiOS struct {
	Caption               string `json:"caption"`
	Version               string `json:"version"`
	OSArch                string `json:"osArch"`
	LastBootUpTime        string `json:"lastBootUpTime"`
	TotalVisibleMemoryKiB uint64 `json:"totalVisibleMemoryKiB"`
	FreePhysicalMemoryKiB uint64 `json:"freePhysicalMemoryKiB"`
}

type wmiCPU struct {
	Name          string `json:"name"`
	NumberOfCores int    `json:"numberOfCores"`
	MaxClockSpeed int    `json:"maxClockSpeed"`
}

type wmiBIOS struct {
	Manufacturer      string `json:"manufacturer"`
	SMBIOSBIOSVersion string `json:"smbiosBiosVersion"`
}

type wmiDisk struct {
	DevicePath    string `json:"devicePath"`
	FileSystem    string `json:"fileSystem"`
	CapacityBytes int64  `json:"capacityBytes"`
	FreeBytes     int64  `json:"freeBytes"`
}

type wmiNIC struct {
	Description string   `json:"description"`
	MAC         string   `json:"mac"`
	IPAddresses []string `json:"ipAddresses"`
}

// mapWMIPayload folds a decoded PowerShell document into the canonical
// Hardware shape. The mapping is deterministic and side-effect free so
// it is safe to unit-test on every platform — only the upstream
// PowerShell exec lives behind a Windows build tag.
//
// Conventions:
//
//   - Memory: CS.TotalPhysicalMemory is already in bytes; OS.*MemoryKiB
//     is in KiB. CS takes precedence when both are present so the
//     value is the BIOS-reported physical install (closest to the
//     procurement record).
//   - Domain: WORKGROUP membership is not a domain join — we only emit
//     DomainName when PartOfDomain is true so a workgroup label does
//     not look like an enrolment.
//   - MAC normalisation: lowercase canonical aa:bb:cc:dd:ee:ff. Drop
//     anything else (empty string) so the backend regex CHECK never
//     rejects an otherwise valid interface row.
//   - Range guards: clamp negative WMI sentinels to zero. The
//     backend has non-negative CHECK constraints on every byte / Hz /
//     core column.
//   - MediaType / BusType / InterfaceType / LinkState default to
//     "UNKNOWN". The probe does not yet enumerate Win32_DiskDrive or
//     Win32_NetworkAdapter for the underlying enum — the backend
//     accepts UNKNOWN as the agent's "I cannot tell" signal.
func mapWMIPayload(hw *Hardware, p wmiPayload) {
	if hw == nil {
		return
	}
	if p.CPU != nil {
		hw.CPUModel = strings.TrimSpace(p.CPU.Name)
		hw.CPUCores = clampNonNegative(p.CPU.NumberOfCores)
		hw.CPUFrequencyMHz = clampNonNegative(p.CPU.MaxClockSpeed)
	}
	if p.CS != nil {
		hw.Manufacturer = strings.TrimSpace(p.CS.Manufacturer)
		hw.SystemModel = strings.TrimSpace(p.CS.Model)
		hw.DomainJoined = p.CS.PartOfDomain
		if p.CS.PartOfDomain {
			hw.DomainName = strings.TrimSpace(p.CS.Domain)
		}
		if p.CS.TotalPhysicalMemory > 0 {
			hw.RAMTotalBytes = int64(p.CS.TotalPhysicalMemory)
		}
	}
	if p.OS != nil {
		hw.OSName = strings.TrimSpace(p.OS.Caption)
		hw.OSVersion = strings.TrimSpace(p.OS.Version)
		hw.OSArch = strings.TrimSpace(p.OS.OSArch)
		// Win32_OperatingSystem.TotalVisibleMemorySize is in KiB.
		if hw.RAMTotalBytes == 0 && p.OS.TotalVisibleMemoryKiB > 0 {
			hw.RAMTotalBytes = int64(p.OS.TotalVisibleMemoryKiB) * 1024
		}
		if p.OS.FreePhysicalMemoryKiB > 0 {
			hw.RAMAvailableBytes = int64(p.OS.FreePhysicalMemoryKiB) * 1024
		}
		if p.OS.LastBootUpTime != "" {
			if t, err := time.Parse(time.RFC3339Nano, p.OS.LastBootUpTime); err == nil {
				lb := t.UTC()
				hw.LastBootAt = &lb
			}
		}
	}
	if p.BIOS != nil {
		hw.BIOSVendor = strings.TrimSpace(p.BIOS.Manufacturer)
		hw.BIOSVersion = strings.TrimSpace(p.BIOS.SMBIOSBIOSVersion)
	}
	for _, d := range p.Disks {
		hw.Disks = append(hw.Disks, HardwareDisk{
			DevicePath:    strings.TrimSpace(d.DevicePath),
			FileSystem:    strings.TrimSpace(d.FileSystem),
			MediaType:     "UNKNOWN",
			BusType:       "UNKNOWN",
			CapacityBytes: clampNonNegative64(d.CapacityBytes),
			FreeBytes:     clampNonNegative64(d.FreeBytes),
		})
	}
	for _, n := range p.NetworkInterfaces {
		nic := HardwareNetworkIface{
			Name:          strings.TrimSpace(n.Description),
			MAC:           normalizeMAC(n.MAC),
			InterfaceType: "UNKNOWN",
			LinkState:     "UNKNOWN",
		}
		for _, ip := range n.IPAddresses {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if len(nic.IPAddresses) >= HardwareIPAddressCapPerIface {
				break
			}
			nic.IPAddresses = append(nic.IPAddresses, ip)
		}
		hw.NetworkInterfaces = append(hw.NetworkInterfaces, nic)
	}
}

// payloadHasEvidence reports whether the decoded WMI document carries
// any meaningful hardware fact. The PowerShell script's SafeCim helper
// swallows per-class failures and returns $null, so a runtime where
// every CIM class fails (e.g. WMI service disabled, security policy
// block, severely corrupted driver state) still produces a successful
// JSON parse with every field nil/empty. mapWMIPayload would happily
// fold that into a Supported=true snapshot with zero CPU cores and
// zero RAM — a kanıtsız "I succeeded" signal that contradicts the
// AG-035 contract (Codex 019e709c post-impl iter-1 must-fix #2).
//
// Returning false here lets collectHardwareWindows downgrade the
// snapshot to Supported=false with a CIM_NO_DATA probe error so the
// backend / operator can distinguish "we asked but got nothing" from
// "we actually observed an Intel/Contoso/...".
func payloadHasEvidence(p wmiPayload) bool {
	return p.CS != nil || p.OS != nil || p.CPU != nil || p.BIOS != nil ||
		len(p.Disks) > 0 || len(p.NetworkInterfaces) > 0
}

// classifyProbeError converts an exec error into a structured code so
// the backend / operator can distinguish a CIM_TIMEOUT (hung WMI
// provider) from a CIM_EXEC_FAILED (binary not installed, security
// policy block) without parsing the human-readable summary.
func classifyProbeError(ctx context.Context, err error) string {
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "CIM_TIMEOUT"
	}
	if errors.Is(err, exec.ErrNotFound) {
		return "CIM_BINARY_MISSING"
	}
	return "CIM_EXEC_FAILED"
}

// bound256 mirrors the backend ProbeError.summary <= 256 cap so a
// noisy Get-CimInstance error trace does not blow the column limit on
// persist.
func bound256(s string) string {
	if len(s) <= 256 {
		return s
	}
	return s[:256]
}

// normalizeMAC enforces the lowercase canonical aa:bb:cc:dd:ee:ff form
// the backend regex CHECK demands. Anything that does not match the
// six-octet shape is dropped (empty string returned); a malformed MAC
// on a live interface is rare and the backend would reject it anyway,
// so we drop the value and keep the rest of the interface visible.
func normalizeMAC(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.ReplaceAll(raw, "-", ":")
	raw = strings.ToLower(raw)
	parts := strings.Split(raw, ":")
	if len(parts) != 6 {
		return ""
	}
	for _, p := range parts {
		if len(p) != 2 {
			return ""
		}
		if _, err := strconv.ParseUint(p, 16, 16); err != nil {
			return ""
		}
	}
	return raw
}

// clampNonNegative protects the backend non-negative CHECK constraints
// from a defective WMI provider that surfaces a signed -1 sentinel.
func clampNonNegative(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func clampNonNegative64(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}
