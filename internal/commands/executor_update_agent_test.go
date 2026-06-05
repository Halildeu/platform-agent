package commands

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/protocol"
	"platform-agent/internal/selfupdate"
)

func TestConfigureSelfUpdateAdvertisesUpdateAgentOnWindowsOnly(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandCollectInventory}, "1.0.0")
	executor.ConfigureSelfUpdate(testSelfUpdateConfig())

	found := hasCapability(executor.Capabilities, protocol.CommandUpdateAgent)
	if runtime.GOOS == "windows" && !found {
		t.Fatalf("expected UPDATE_AGENT capability on configured Windows executor; caps=%v", executor.Capabilities)
	}
	if runtime.GOOS != "windows" && found {
		t.Fatalf("UPDATE_AGENT must not be advertised on non-Windows; caps=%v", executor.Capabilities)
	}
}

func TestLocalExecutorUpdateAgentRequiresReason(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandUpdateAgent}, "1.0.0")
	command := updateAgentTestCommand()
	command.Reason = ""

	result := executor.Execute(context.Background(), command)
	if result.Status != protocol.CommandStatusFailed {
		t.Fatalf("status=%s summary=%q, want FAILED missing reason", result.Status, result.Summary)
	}
}

func TestLocalExecutorUpdateAgentUnconfiguredFailsClosed(t *testing.T) {
	executor := NewLocalExecutor([]protocol.CommandType{protocol.CommandUpdateAgent}, "1.0.0")
	command := updateAgentTestCommand()

	result := executor.Execute(context.Background(), command)
	if result.Status != protocol.CommandStatusUnsupported {
		t.Fatalf("status=%s summary=%q details=%v, want UNSUPPORTED", result.Status, result.Summary, result.Details)
	}
	update, ok := result.Details["update"].(selfupdate.StageResult)
	if !ok {
		t.Fatalf("update detail type=%T", result.Details["update"])
	}
	if update.StageStatus != selfupdate.StageFailed || update.ErrorCode != selfupdate.ErrUnsupportedPlatform {
		t.Fatalf("update=%+v, want unsupported self-update config failure", update)
	}
}

func testSelfUpdateConfig() SelfUpdateConfig {
	return SelfUpdateConfig{
		Enabled:           true,
		StagingRoot:       `C:\ProgramData\EndpointAgent\updates`,
		CurrentBinaryPath: `C:\Program Files\EndpointAgent\endpoint-agent.exe`,
		ServiceName:       "EndpointAgent",
		AllowedHosts:      []string{"updates.example.com"},
		MaxRedirects:      1,
		SignerThumbprints: []string{"AABBCC"},
		Verifier: selfupdate.AuthenticodeVerifierFunc(func(string) (selfupdate.AuthenticodeEvidence, selfupdate.ErrorCode, string) {
			return selfupdate.AuthenticodeEvidence{
				ChainValid:        true,
				HasCodeSigningEKU: true,
				SignerThumbprint:  "AA:BB CC",
				Timestamped:       true,
				SigningTimeValid:  true,
			}, "", ""
		}),
		MaxSeenVersion: "1.0.0",
	}
}

func updateAgentTestCommand() protocol.AgentCommand {
	return protocol.AgentCommand{
		CommandID:      "cmd-update-1",
		ClaimID:        "claim-update-1",
		AttemptNumber:  1,
		Type:           protocol.CommandUpdateAgent,
		Reason:         "approved self-update staging test",
		ClaimExpiresAt: time.Now().Add(time.Minute),
		Payload: map[string]interface{}{
			"releaseId":               "rel-1",
			"targetVersion":           "1.1.0",
			"binaryUrl":               "https://updates.example.com/endpoint-agent.exe",
			"claimedSha256":           strings.Repeat("a", 64),
			"claimedSignerThumbprint": "AABBCC",
			"signingTier":             string(selfupdate.TierTrusted),
			"maxBytes":                1024,
		},
	}
}
