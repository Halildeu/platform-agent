package inventory

import (
	"runtime"
	"time"
)

// HardwareSchemaVersion is the canonical version of the hardware
// sub-snapshot that the agent emits. The backend
// HardwareInventoryPayloadPolicy.ACCEPTED_SCHEMA_VERSIONS set must
// include this value, or COLLECT_INVENTORY results carrying a
// hardware block will be fail-closed rejected before persist (BE-022
// V14 pre-persist hook). Bump only with a coordinated backend rollout
// that widens the accepted set first.
const HardwareSchemaVersion = 1

// Hardware is the canonical wire shape for the hardware sub-snapshot
// emitted under details.inventory.hardware when COLLECT_INVENTORY's
// includeHardware payload bit is true (AG-035 / Faz 22.5.2).
//
// Sensitive fields (BIOS / disk serials, machine GUIDs, Windows SIDs,
// user paths) are NOT placed on this struct. The backend
// HardwareInventoryPayloadPolicy pre-persist sanitizer strips any
// strip-keys (biosserial, diskserial, uuid, sid, userpath, ...) it
// finds, and rejects key-level or value-level secrets
// (token/password/jwt/bearer/secret + Bearer/JWT/password= patterns)
// fail-closed. To make that policy a tight check rather than a wide
// net, the agent omits the strip-keys from its output entirely — the
// audit story is "the BIOS exposed a serial" not "this is the serial".
//
// Supported=false signals that the agent does not have a hardware
// probe for the current runtime (non-Windows v1, or a Windows runtime
// where every WMI/CIM probe failed). The snapshot is still emitted so
// the backend can observe and the operator can troubleshoot via
// ProbeErrors; downstream consumers (preflight gate, WEB-013 view)
// should treat Supported=false as an evidence gap, not an absence of
// hardware.
type Hardware struct {
	SchemaVersion     int                    `json:"schemaVersion"`
	Supported         bool                   `json:"supported"`
	CPUModel          string                 `json:"cpuModel,omitempty"`
	CPUCores          int                    `json:"cpuCores,omitempty"`
	CPUFrequencyMHz   int                    `json:"cpuFrequencyMhz,omitempty"`
	RAMTotalBytes     int64                  `json:"ramTotalBytes,omitempty"`
	RAMAvailableBytes int64                  `json:"ramAvailableBytes,omitempty"`
	OSName            string                 `json:"osName,omitempty"`
	OSVersion         string                 `json:"osVersion,omitempty"`
	OSKernel          string                 `json:"osKernel,omitempty"`
	OSArch            string                 `json:"osArch,omitempty"`
	BIOSVendor        string                 `json:"biosVendor,omitempty"`
	BIOSVersion       string                 `json:"biosVersion,omitempty"`
	Manufacturer      string                 `json:"manufacturer,omitempty"`
	SystemModel       string                 `json:"systemModel,omitempty"`
	DomainJoined      bool                   `json:"domainJoined"`
	DomainName        string                 `json:"domainName,omitempty"`
	LastBootAt        *time.Time             `json:"lastBootAt,omitempty"`
	Disks             []HardwareDisk         `json:"disks,omitempty"`
	NetworkInterfaces []HardwareNetworkIface `json:"networkInterfaces,omitempty"`
	CollectedAt       time.Time              `json:"collectedAt"`
	ProbeErrors       []HardwareProbeError   `json:"probeErrors,omitempty"`
}

// HardwareDisk mirrors the V13 endpoint_hardware_inventory_disks row
// shape (Codex 019e7007 iter-4 absorb). The disk serial is intentionally
// not emitted — the backend strip-keys it anyway and we keep the agent
// payload narrow to keep the pre-persist policy a precise check.
type HardwareDisk struct {
	DevicePath    string `json:"devicePath,omitempty"`
	FileSystem    string `json:"fileSystem,omitempty"`
	// MediaType: SSD / HDD / NVME / UNKNOWN.
	MediaType string `json:"mediaType,omitempty"`
	// BusType: SATA / NVME / USB / SCSI / IDE / UNKNOWN.
	BusType       string `json:"busType,omitempty"`
	CapacityBytes int64  `json:"capacityBytes,omitempty"`
	FreeBytes     int64  `json:"freeBytes,omitempty"`
}

// HardwareNetworkIface mirrors the V13
// endpoint_hardware_inventory_network_interfaces row. The MAC field
// is serialised under the JSON key `macAddress` (NOT `mac`) so the
// backend EndpointHardwareInventoryService ingest hook can populate
// the `mac_address` child column directly — emitting under `mac`
// leaves the persisted column NULL even though the redacted payload
// shows the value (Codex 019e709c post-impl iter-1 must-fix #1).
//
// MAC is emitted in lowercase canonical aa:bb:cc:dd:ee:ff form; the
// backend also normalises but doing the conversion here keeps a
// malformed driver report from tripping the backend regex CHECK
// before the pre-persist normaliser runs. IPAddresses is bounded to
// HardwareIPAddressCapPerIface per interface so a runaway adapter or
// driver glitch cannot inflate the payload (Codex 019e709c post-impl
// iter-1 non-blocking absorb).
type HardwareNetworkIface struct {
	Name        string   `json:"name,omitempty"`
	MAC         string   `json:"macAddress,omitempty"`
	IPAddresses []string `json:"ipAddresses,omitempty"`
	// InterfaceType: ETHERNET / WIFI / LOOPBACK / VIRTUAL / UNKNOWN.
	InterfaceType string `json:"interfaceType,omitempty"`
	// LinkState: UP / DOWN / UNKNOWN.
	LinkState string `json:"linkState,omitempty"`
}

// HardwareIPAddressCapPerIface bounds how many IP addresses the
// agent emits per network interface. A 16-address cap (chosen to
// cover dual-stack with several VLANs / loopback aliases) is well
// above the 1-3 a typical device exposes and well below any wire-size
// concern. Driver glitches that surface dozens or hundreds of
// repeated entries are clipped to keep persist stable.
const HardwareIPAddressCapPerIface = 16

// HardwareProbeError mirrors the bounded shape the backend ingest
// service accepts (code + summary <= 256 chars). The agent fills this
// when an individual WMI/CIM probe fails so a partial snapshot is still
// observable rather than fail-closing the whole COLLECT_INVENTORY run.
type HardwareProbeError struct {
	Code    string `json:"code"`
	Summary string `json:"summary"`
}

// CollectHardware is the entry point for the AG-035 hardware probe.
// COLLECT_INVENTORY in CollectWithOptions calls this when the
// includeHardware payload bit is true; the lightweight heartbeat /
// auto-enroll path never reaches it.
//
// The implementation is wired via a package-level function variable
// (collectHardwareImpl) so tests can install a deterministic stub via
// t.Cleanup without depending on the runtime's WMI surface.
// Production code on Windows wires collectHardwareImpl to the
// PowerShell + Get-CimInstance probe (hardware_windows.go); all
// other platforms wire the unsupported stub (hardware_other.go).
func CollectHardware(now time.Time) Hardware {
	return collectHardwareImpl(now)
}

// collectHardwareImpl is the test seam. Build-tagged init() in
// hardware_windows.go / hardware_other.go binds the real
// implementation; tests can override and restore with t.Cleanup.
var collectHardwareImpl = collectHardwareUnsupported

// collectHardwareUnsupported is the safe default for any runtime
// without a build-tagged probe wired in. It returns Supported=false
// with the canonical OS metadata so the backend sanitizer still has a
// schemaVersion to validate.
func collectHardwareUnsupported(now time.Time) Hardware {
	return Hardware{
		SchemaVersion: HardwareSchemaVersion,
		Supported:     false,
		OSName:        runtime.GOOS,
		OSArch:        runtime.GOARCH,
		CollectedAt:   now,
		ProbeErrors: []HardwareProbeError{{
			Code:    "UNSUPPORTED_PLATFORM",
			Summary: "Hardware probe is not implemented for runtime " + runtime.GOOS,
		}},
	}
}
