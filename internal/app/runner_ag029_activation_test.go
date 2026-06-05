package app

import (
	"context"
	"testing"

	"platform-agent/internal/config"
	"platform-agent/internal/protocol"
	"platform-agent/internal/selfupdate"
)

func TestRunnerActivatesSelfUpdateOnlyAfterSuccessfulStageReadyResult(t *testing.T) {
	root := t.TempDir()
	command := protocol.AgentCommand{
		CommandID: "cmd-update-ready",
		Type:      protocol.CommandUpdateAgent,
		Payload:   map[string]interface{}{"maxBytes": float64(2048)},
	}
	result := protocol.CommandResult{
		Status: protocol.CommandStatusSucceeded,
		Details: map[string]interface{}{"update": selfupdate.StageResult{
			StageStatus:      selfupdate.StageReady,
			StagingID:        command.CommandID,
			ActivationPlanID: command.CommandID,
			TargetVersion:    "1.2.3",
		}},
	}

	var called bool
	runner := &Runner{
		Config: config.Config{SelfUpdateStagingRoot: root},
		SelfUpdateActivation: func(_ context.Context, paths selfupdate.StagingPaths, maxBytes int64) selfupdate.ActivationOutcome {
			called = true
			if paths.StagingID != command.CommandID {
				t.Fatalf("paths.StagingID=%q, want %q", paths.StagingID, command.CommandID)
			}
			if maxBytes != 2048 {
				t.Fatalf("maxBytes=%d, want 2048", maxBytes)
			}
			return selfupdate.ActivationOutcome{
				Status:           selfupdate.ActivationActivated,
				ActivationPlanID: command.CommandID,
				TargetVersion:    "1.2.3",
			}
		},
	}

	runner.maybeActivateSelfUpdateAfterResult(context.Background(), command, result)
	if !called {
		t.Fatal("expected self-update activation hook to be called")
	}
}

func TestRunnerDoesNotActivateSelfUpdateForNonReadyResults(t *testing.T) {
	root := t.TempDir()
	runner := &Runner{
		Config: config.Config{SelfUpdateStagingRoot: root},
		SelfUpdateActivation: func(context.Context, selfupdate.StagingPaths, int64) selfupdate.ActivationOutcome {
			t.Fatal("activation hook must not be called")
			return selfupdate.ActivationOutcome{}
		},
	}
	command := protocol.AgentCommand{CommandID: "cmd-update-skip", Type: protocol.CommandUpdateAgent}

	cases := []protocol.CommandResult{
		{Status: protocol.CommandStatusFailed, Details: map[string]interface{}{"update": selfupdate.StageResult{StageStatus: selfupdate.StageReady}}},
		{Status: protocol.CommandStatusSucceeded, Details: map[string]interface{}{"update": selfupdate.StageResult{StageStatus: selfupdate.StageFailed}}},
		{Status: protocol.CommandStatusSucceeded, Details: map[string]interface{}{"update": selfupdate.StageResult{StageStatus: selfupdate.StageNoopCurrent}}},
		{Status: protocol.CommandStatusSucceeded, Details: map[string]interface{}{"update": "not-a-stage-result"}},
	}
	for _, result := range cases {
		runner.maybeActivateSelfUpdateAfterResult(context.Background(), command, result)
	}

	runner.maybeActivateSelfUpdateAfterResult(context.Background(), protocol.AgentCommand{CommandID: "cmd-inventory", Type: protocol.CommandCollectInventory}, protocol.CommandResult{
		Status:  protocol.CommandStatusSucceeded,
		Details: map[string]interface{}{"update": selfupdate.StageResult{StageStatus: selfupdate.StageReady}},
	})
}

func TestRunnerSelfUpdateActivationNilHookIsStagingOnly(t *testing.T) {
	runner := &Runner{Config: config.Config{SelfUpdateStagingRoot: t.TempDir()}}
	runner.maybeActivateSelfUpdateAfterResult(context.Background(),
		protocol.AgentCommand{CommandID: "cmd-update-ready", Type: protocol.CommandUpdateAgent},
		protocol.CommandResult{
			Status:  protocol.CommandStatusSucceeded,
			Details: map[string]interface{}{"update": selfupdate.StageResult{StageStatus: selfupdate.StageReady}},
		},
	)
}
