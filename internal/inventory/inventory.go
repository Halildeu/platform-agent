package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"time"

	"platform-agent/internal/protocol"
)

type Snapshot struct {
	Hostname     string            `json:"hostname"`
	OSFamily     protocol.OSFamily `json:"osFamily"`
	OSName       string            `json:"osName"`
	Architecture string            `json:"architecture"`
	AgentVersion string            `json:"agentVersion"`
	CollectedAt  time.Time         `json:"collectedAt"`
}

func Collect(agentVersion string, now time.Time) Snapshot {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	return Snapshot{
		Hostname:     hostname,
		OSFamily:     RuntimeOSFamily(),
		OSName:       runtime.GOOS,
		Architecture: runtime.GOARCH,
		AgentVersion: agentVersion,
		CollectedAt:  now,
	}
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
