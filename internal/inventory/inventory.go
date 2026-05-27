package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"time"

	"platform-agent/internal/identity"
	"platform-agent/internal/protocol"
	"platform-agent/internal/software"
	"platform-agent/internal/winget"
)

type Snapshot struct {
	Hostname     string             `json:"hostname"`
	OSFamily     protocol.OSFamily  `json:"osFamily"`
	OSName       string             `json:"osName"`
	Architecture string             `json:"architecture"`
	AgentVersion string             `json:"agentVersion"`
	CollectedAt  time.Time          `json:"collectedAt"`
	Identity     identity.Inventory `json:"identity"`
	// Software is intentionally nil unless the caller opted into the full
	// software/WinGet block via CollectOptions.IncludeSoftwareApps. The
	// JSON tag omitempty hides the field from the heartbeat / auto-enroll
	// wire payload when the lightweight default applies (AG-025H).
	Software *software.Summary `json:"software,omitempty"`
}

// CollectOptions controls which optional inventory blocks COLLECT_INVENTORY
// asks for. Zero value is the AG-025H lightweight contract: host / os /
// identity only — no software registry enumeration, no WinGet probe. The
// heartbeat and auto-enroll loops keep the zero default and therefore
// never pay the registry / probe cost.
type CollectOptions struct {
	// IncludeSoftwareApps gates the entire software block. When true,
	// CollectWithOptions enumerates HKLM + HKLM\WOW6432Node, runs the
	// WinGet --version readiness probe, and emits a Summary that includes
	// the full Apps list. When false (the default), the software registry
	// enumeration and the WinGet probe are not invoked at all — the
	// resulting Snapshot.Software stays nil and the wire payload omits it.
	// The backend uses true for explicit COLLECT_INVENTORY scans
	// (includeSoftware=true on the command payload); heartbeat /
	// auto-enroll never opt in.
	IncludeSoftwareApps bool
}

// Collect returns the AG-025H lightweight default snapshot: host / os /
// identity only, no software registry enumeration, no WinGet probe. It is
// equivalent to CollectWithOptions(agentVersion, now, CollectOptions{}).
// Heartbeat and auto-enroll call this; the registry / probe cost is paid
// only when COLLECT_INVENTORY explicitly opts into full software via
// CollectWithOptions(... IncludeSoftwareApps: true ...).
func Collect(agentVersion string, now time.Time) Snapshot {
	return CollectWithOptions(agentVersion, now, CollectOptions{})
}

// CollectWithOptions is the COLLECT_INVENTORY entry point. When
// opts.IncludeSoftwareApps is true, the software registry enumeration and
// the WinGet --version readiness probe run and a full Summary (including
// the Apps list under the package's size caps) is attached. When false
// (the heartbeat / auto-enroll default), neither probe runs and
// Snapshot.Software stays nil.
func CollectWithOptions(agentVersion string, now time.Time, opts CollectOptions) Snapshot {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	snapshot := Snapshot{
		Hostname:     hostname,
		OSFamily:     RuntimeOSFamily(),
		OSName:       runtime.GOOS,
		Architecture: runtime.GOARCH,
		AgentVersion: agentVersion,
		CollectedAt:  now,
		Identity:     identity.Collect(now),
	}
	if opts.IncludeSoftwareApps {
		snapshot.Software = collectSoftwareSummary(now, true)
	}
	return snapshot
}

// collectSoftwareSummary runs the software inventory + winget readiness
// probes and folds their results into a single Summary. It is invoked ONLY
// from the explicit IncludeSoftwareApps=true path in CollectWithOptions —
// the AG-025H heartbeat / auto-enroll lightweight contract never reaches
// it. On non-Windows builds both probes return Supported=false so the
// Summary is a no-op rollup rather than missing entirely.
//
// The package-level collectSoftware / detectWinget function variables are
// the test seam: tests override them with t.Cleanup to assert lightweight
// paths never invoke the probes, and to inject fake snapshots when
// asserting full-mode output shape.
func collectSoftwareSummary(now time.Time, includeApps bool) *software.Summary {
	softwareSnapshot := collectSoftware(now, software.CollectOptions{})
	wingetReadiness := detectWinget(now)
	summary := software.Summarize(softwareSnapshot, wingetReadiness.SystemContextReady, wingetReadiness.Version, includeApps)
	return &summary
}

// collectSoftware and detectWinget are package-level function variables
// so tests can override them with t.Cleanup-restored stubs (AG-025H test
// seam). Production code always wires them to the real software.Collect /
// winget.Detect implementations.
var (
	collectSoftware = software.Collect
	detectWinget    = winget.Detect
)

func RuntimeCapabilityReport() protocol.CapabilityReport {
	return protocol.CapabilityReport{
		OSFamily:     RuntimeOSFamily(),
		Architecture: runtime.GOARCH,
		Capabilities: RuntimeCapabilities(),
	}
}

func RuntimeCapabilities() []protocol.CommandType {
	capabilities := []protocol.CommandType{
		protocol.CommandCollectInventory,
		protocol.CommandGetLoggedInUser,
		protocol.CommandGetUserHomePaths,
	}
	if runtime.GOOS == "windows" {
		// DisableLocalUser/EnableLocalUser intentionally omitted: adapter not implemented in executor.
		// Re-add when internal/users gains a Windows local-user disable/enable adapter.
		capabilities = append(capabilities,
			protocol.CommandListLocalUsers,
		)
	}
	return capabilities
}

func RuntimeOSFamily() protocol.OSFamily {
	switch runtime.GOOS {
	case "windows":
		return protocol.OSFamilyWindows
	case "darwin":
		return protocol.OSFamilyMacOS
	default:
		return protocol.OSFamilyLinux
	}
}

// MachineFingerprint returns a stable, non-empty identifier for this machine.
// BE-011: the backend enrollment contract (ConsumeEnrollmentRequest
// .machineFingerprint, @NotBlank, max 512) requires it. The value is derived
// deterministically from the hostname and the OS/architecture so it is stable
// across agent restarts and distinct across machines with different hostnames.
// A hardware-bound fingerprint (machine-id / SMBIOS UUID) is a future
// enhancement; this derivation is sufficient to identify the device across the
// enroll → heartbeat → command lifecycle.
func MachineFingerprint() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	seed := strings.ToLower(strings.TrimSpace(hostname)) + "|" + runtime.GOOS + "|" + runtime.GOARCH
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}
