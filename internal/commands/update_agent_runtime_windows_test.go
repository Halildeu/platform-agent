//go:build windows

package commands

import (
	"testing"

	"platform-agent/internal/protocol"
)

func TestPolicyAwareExecutorWindowsWiresDefaultRuntimeCollaborators(t *testing.T) {
	executor := NewPolicyAwareExecutor("0.1.0-dev", true, UpdateAgentStagerOptions{
		AllowedHosts:      []string{"github.com"},
		SignerThumbprints: []string{"AABBCC"},
		MaxRedirects:      5,
		HardMaxBytes:      1000,
	})

	if !hasExecutorCapability(executor, protocol.CommandUpdateAgent) {
		t.Fatal("Windows policy-ready agent should advertise UPDATE_AGENT once default runtime collaborators are wired")
	}
	if executor.UpdateAgentStager == nil {
		t.Fatal("Windows policy-ready agent should wire a self-update stager")
	}
}
