package inventory

import (
	"os"
	"runtime"
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
