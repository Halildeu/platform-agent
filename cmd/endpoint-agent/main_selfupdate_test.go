package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"platform-agent/internal/selfupdate"
)

func TestRunSelfUpdateActivateSwapsPreparedBinary(t *testing.T) {
	root := t.TempDir()
	currentPath := filepath.Join(root, "current-agent.exe")
	if err := os.WriteFile(currentPath, []byte("old-agent"), 0o600); err != nil {
		t.Fatalf("write current binary: %v", err)
	}

	paths := writeActivationPlanForMainTest(t, root, "cmd-activate-1", currentPath, []byte("new-agent"))
	controller := &fakeSelfUpdateServiceController{}
	outcome := runSelfUpdateActivate(context.Background(), selfUpdateActivateOptions{
		StagingRoot: root,
		StagingID:   paths.StagingID,
		MaxBytes:    1024,
	}, controller)

	if outcome.Status != selfupdate.ActivationActivated {
		t.Fatalf("activation status=%s reason=%q", outcome.Status, outcome.Reason)
	}
	if got, err := os.ReadFile(currentPath); err != nil || string(got) != "new-agent" {
		t.Fatalf("current binary not swapped: got=%q err=%v", string(got), err)
	}
	if strings.Join(controller.events, ",") != "stop:EndpointAgent,start:EndpointAgent" {
		t.Fatalf("service events=%v", controller.events)
	}
	raw, err := json.Marshal(outcome)
	if err != nil {
		t.Fatalf("marshal outcome: %v", err)
	}
	if strings.Contains(string(raw), root) || strings.Contains(string(raw), currentPath) {
		t.Fatalf("activation outcome leaked local path: %s", raw)
	}
}

func TestRunSelfUpdateActivateRejectsInvalidStagingInput(t *testing.T) {
	outcome := runSelfUpdateActivate(context.Background(), selfUpdateActivateOptions{
		StagingRoot: t.TempDir(),
		StagingID:   "../escape",
		MaxBytes:    1024,
	}, &fakeSelfUpdateServiceController{})
	if outcome.Status != selfupdate.ActivationFailed {
		t.Fatalf("status=%s, want %s", outcome.Status, selfupdate.ActivationFailed)
	}
	if strings.Contains(outcome.Reason, string(os.PathSeparator)) {
		t.Fatalf("reason should remain bounded and path-free: %q", outcome.Reason)
	}
}

func writeActivationPlanForMainTest(t *testing.T, root, stagingID, currentPath string, stagedPayload []byte) selfupdate.StagingPaths {
	t.Helper()
	paths, code, reason := selfupdate.PrepareProtectedStagingDir(root, stagingID)
	if code == selfupdate.ErrUnsupportedPlatform {
		paths, code, reason = selfupdate.BuildStagingPaths(root, stagingID)
		if code == "" {
			if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
				t.Fatalf("mkdir staging: %v", err)
			}
		}
	}
	if code != "" {
		t.Fatalf("prepare staging: code=%q reason=%q", code, reason)
	}
	if err := os.WriteFile(paths.BinaryPath, stagedPayload, 0o600); err != nil {
		t.Fatalf("write staged binary: %v", err)
	}
	sum := sha256.Sum256(stagedPayload)
	ready, code, reason := selfupdate.BuildReadyStageResult(paths, selfupdate.PreflightEvidence{
		OldVersion:    "1.0.0",
		TargetVersion: "1.1.0",
		SigningTier:   selfupdate.TierTrusted,
	}, hex.EncodeToString(sum[:]), "AABBCC")
	if code != "" {
		t.Fatalf("BuildReadyStageResult: code=%q reason=%q", code, reason)
	}
	plan, code, reason := selfupdate.BuildActivationPlan(paths, currentPath, "EndpointAgent", ready)
	if code != "" {
		t.Fatalf("BuildActivationPlan: code=%q reason=%q", code, reason)
	}
	if code, reason := selfupdate.WriteActivationPlan(paths, plan); code != "" || reason != "" {
		t.Fatalf("WriteActivationPlan: code=%q reason=%q", code, reason)
	}
	return paths
}

type fakeSelfUpdateServiceController struct {
	events []string
}

func (f *fakeSelfUpdateServiceController) Stop(_ context.Context, serviceName string) error {
	f.events = append(f.events, "stop:"+serviceName)
	return nil
}

func (f *fakeSelfUpdateServiceController) Start(_ context.Context, serviceName string) error {
	f.events = append(f.events, "start:"+serviceName)
	return nil
}
