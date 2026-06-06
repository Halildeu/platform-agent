package app

import (
	"testing"

	"platform-agent/internal/config"
	"platform-agent/internal/protocol"
)

func TestNewRunner_UpdateAgentCapabilityRequiresCompleteLocalPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.AgentVersion = "0.1.0-test"
	cfg.SelfUpdateEnabled = true

	runner := NewRunner(cfg, nil, nil)

	if hasRunnerCapability(runner, protocol.CommandUpdateAgent) {
		t.Fatal("enabled=true without local trust policy must not advertise UPDATE_AGENT")
	}
	if runner.Executor.UpdateAgentStager != nil {
		t.Fatal("incomplete local self-update policy must not wire an update stager")
	}
}

func TestNewRunner_UpdateAgentCapabilityWaitsForRuntimeCollaborators(t *testing.T) {
	cfg := config.Default()
	cfg.AgentVersion = "0.1.0-test"
	cfg.SelfUpdateEnabled = true
	cfg.SelfUpdateAllowedHosts = []string{"github.com", "objects.githubusercontent.com"}
	cfg.SelfUpdateSignerThumbprints = []string{"AABBCC"}

	runner := NewRunner(cfg, nil, nil)

	if hasRunnerCapability(runner, protocol.CommandUpdateAgent) {
		t.Fatal("local policy alone must not advertise UPDATE_AGENT until runtime verifier/staging collaborators are wired")
	}
	if runner.Executor.UpdateAgentStager != nil {
		t.Fatal("local policy alone must not wire an update stager")
	}
}

func hasRunnerCapability(runner *Runner, target protocol.CommandType) bool {
	for _, capability := range runner.Executor.Capabilities {
		if capability == target {
			return true
		}
	}
	return false
}
