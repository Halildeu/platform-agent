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
	Software     *software.Summary  `json:"software,omitempty"`
}

// CollectOptions controls which optional inventory blocks COLLECT_INVENTORY
// asks for. Zero value gives the historical behaviour plus the default
// software summary (count + WinGet readiness, no Apps list).
type CollectOptions struct {
	// IncludeSoftwareApps switches the Software block from "summary only"
	// (count + winget readiness) to "summary + full Apps list with size
	// caps applied". The backend uses this for compliance scans; the
	// heartbeat / default poll loop never sets it.
	IncludeSoftwareApps bool
}

// Collect keeps the historical signature so the heartbeat loop and the
// existing tests stay untouched. It is equivalent to CollectWithOptions
// with a zero CollectOptions value.
func Collect(agentVersion string, now time.Time) Snapshot {
	return CollectWithOptions(agentVersion, now, CollectOptions{})
}

// CollectWithOptions is the new entry point COLLECT_INVENTORY uses
// when it needs to honour an includeSoftware=true payload arg. The
// software + winget probes are run unconditionally on Windows (their
// result is cheap and ships as a summary by default); the opts flag
// controls only whether the Apps list rides along.
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
	snapshot.Software = collectSoftwareSummary(now, opts.IncludeSoftwareApps)
	return snapshot
}

// collectSoftwareSummary runs the software inventory + winget readiness
// probes and folds their results into a single Summary. On non-Windows
// builds both probes return Supported=false so the Summary is a
// no-op rollup rather than missing entirely — that keeps the wire
// payload shape identical across platforms.
func collectSoftwareSummary(now time.Time, includeApps bool) *software.Summary {
	softwareSnapshot := software.Collect(now, software.CollectOptions{})
	wingetReadiness := winget.Detect(now)
	summary := software.Summarize(softwareSnapshot, wingetReadiness.SystemContextReady, wingetReadiness.Version, includeApps)
	return &summary
}

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
