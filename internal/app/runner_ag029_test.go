package app

import (
	"runtime"
	"testing"

	"platform-agent/internal/config"
	"platform-agent/internal/protocol"
)

func TestNewRunnerWiresUpdateAgentCapabilityWhenConfiguredOnWindows(t *testing.T) {
	cfg := config.Config{
		AgentVersion:                "1.0.0",
		SelfUpdateEnabled:           true,
		SelfUpdateStagingRoot:       `C:\ProgramData\EndpointAgent\updates`,
		SelfUpdateCurrentBinaryPath: `C:\Program Files\EndpointAgent\endpoint-agent.exe`,
		SelfUpdateServiceName:       "EndpointAgent",
		SelfUpdateAllowedHosts:      []string{"updates.example.com"},
		SelfUpdateSignerThumbprints: []string{"AABBCC"},
		SelfUpdateMaxRedirects:      1,
	}
	runner := NewRunner(cfg, nil, nil)

	found := false
	for _, c := range runner.Executor.Capabilities {
		if c == protocol.CommandUpdateAgent {
			found = true
			break
		}
	}
	if runtime.GOOS == "windows" && !found {
		t.Fatalf("expected UPDATE_AGENT capability in configured Windows runner; caps=%v", runner.Executor.Capabilities)
	}
	if runtime.GOOS != "windows" && found {
		t.Fatalf("UPDATE_AGENT must not be advertised on non-Windows; caps=%v", runner.Executor.Capabilities)
	}
}
