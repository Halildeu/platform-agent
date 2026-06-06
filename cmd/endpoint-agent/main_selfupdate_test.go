package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"platform-agent/internal/selfupdate"
)

func TestRunSelfUpdateActivateSwapsPreparedBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cmd-level activation swap test relies on non-elevated temp ACLs; internal/selfupdate covers Windows activation sequencing with hooks")
	}
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
	outcomeRaw, err := os.ReadFile(filepath.Join(paths.Directory, "activation-outcome.json"))
	if err != nil {
		t.Fatalf("activation outcome evidence not persisted: %v", err)
	}
	if strings.Contains(string(outcomeRaw), root) || strings.Contains(string(outcomeRaw), currentPath) {
		t.Fatalf("persisted activation outcome leaked local path: %s", outcomeRaw)
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

func TestRunSelfUpdateStatusReturnsPersistedPathFreeOutcome(t *testing.T) {
	root := t.TempDir()
	paths, code, reason := selfupdate.BuildStagingPaths(root, "cmd-status-1")
	if code != "" {
		t.Fatalf("BuildStagingPaths: code=%q reason=%q", code, reason)
	}
	if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
		t.Fatalf("mkdir staging dir: %v", err)
	}
	rawOutcome := `{"status":"ACTIVATED","activationPlanId":"cmd-status-1","targetVersion":"1.1.0","newSha256":"` +
		strings.Repeat("a", 64) + `","backupSha256":"` + strings.Repeat("b", 64) +
		`","reason":"activated from C:\\ProgramData\\EndpointAgent\\updates\\cmd-status-1"}`
	if err := os.WriteFile(filepath.Join(paths.Directory, "activation-outcome.json"), []byte(rawOutcome), 0o600); err != nil {
		t.Fatalf("write activation outcome: %v", err)
	}

	outcome, ok := runSelfUpdateStatus(selfUpdateStatusOptions{
		StagingRoot: root,
		StagingID:   paths.StagingID,
	})

	if !ok {
		t.Fatalf("status should load persisted outcome: %+v", outcome)
	}
	if outcome.Status != selfupdate.ActivationActivated || outcome.ActivationPlanID != paths.StagingID {
		t.Fatalf("unexpected status outcome: %+v", outcome)
	}
	raw, err := json.Marshal(outcome)
	if err != nil {
		t.Fatalf("marshal status outcome: %v", err)
	}
	if strings.Contains(string(raw), root) || strings.Contains(string(raw), "ProgramData") {
		t.Fatalf("status outcome leaked local path: %s", raw)
	}
}

func TestRunSelfUpdateStatusFailsWhenOutcomeMissing(t *testing.T) {
	root := t.TempDir()
	outcome, ok := runSelfUpdateStatus(selfUpdateStatusOptions{
		StagingRoot: root,
		StagingID:   "cmd-status-missing",
	})

	if ok {
		t.Fatalf("missing outcome should fail")
	}
	if outcome.Status != selfupdate.ActivationFailed || outcome.ActivationPlanID != "cmd-status-missing" {
		t.Fatalf("unexpected missing outcome: %+v", outcome)
	}
	if strings.Contains(outcome.Reason, root) || strings.Contains(outcome.Reason, string(os.PathSeparator)) {
		t.Fatalf("reason should remain bounded and path-free: %q", outcome.Reason)
	}
}

func TestRunSelfUpdatePreflightReturnsPathFreeReady(t *testing.T) {
	root := t.TempDir()
	currentPath := filepath.Join(root, "current-agent.exe")
	if err := os.WriteFile(currentPath, []byte("old-agent"), 0o600); err != nil {
		t.Fatalf("write current binary: %v", err)
	}
	paths := writeActivationPlanForPreflightMainTest(t, root, "cmd-preflight-1", currentPath, []byte("new-agent"))

	outcome := runSelfUpdatePreflight(selfUpdatePreflightOptions{
		StagingRoot: root,
		StagingID:   paths.StagingID,
		MaxBytes:    1024,
	})

	if outcome.Status != "READY" {
		t.Fatalf("preflight status=%s reason=%q code=%q", outcome.Status, outcome.Reason, outcome.ErrorCode)
	}
	if outcome.ActivationPlanID != paths.StagingID || outcome.TargetVersion != "1.1.0" {
		t.Fatalf("unexpected outcome identity: %+v", outcome)
	}
	if !outcome.CurrentBinaryPresent || !outcome.StagedBinaryVerified {
		t.Fatalf("readiness flags not set: %+v", outcome)
	}
	raw, err := json.Marshal(outcome)
	if err != nil {
		t.Fatalf("marshal outcome: %v", err)
	}
	if strings.Contains(string(raw), root) || strings.Contains(string(raw), currentPath) || strings.Contains(string(raw), paths.BinaryPath) {
		t.Fatalf("preflight outcome leaked local path: %s", raw)
	}
}

func TestRunSelfUpdatePreflightRejectsTamperedStagedBinary(t *testing.T) {
	root := t.TempDir()
	currentPath := filepath.Join(root, "current-agent.exe")
	if err := os.WriteFile(currentPath, []byte("old-agent"), 0o600); err != nil {
		t.Fatalf("write current binary: %v", err)
	}
	paths := writeActivationPlanForPreflightMainTest(t, root, "cmd-preflight-tampered", currentPath, []byte("new-agent"))
	if err := os.WriteFile(paths.BinaryPath, []byte("tampered-agent"), 0o600); err != nil {
		t.Fatalf("tamper staged binary: %v", err)
	}

	outcome := runSelfUpdatePreflight(selfUpdatePreflightOptions{
		StagingRoot: root,
		StagingID:   paths.StagingID,
		MaxBytes:    1024,
	})

	if outcome.Status != "FAILED" || outcome.ErrorCode != selfupdate.ErrHashMismatch {
		t.Fatalf("preflight outcome=%+v, want failed hash mismatch", outcome)
	}
}

func TestRunSelfUpdatePreflightRejectsInvalidStagingInput(t *testing.T) {
	outcome := runSelfUpdatePreflight(selfUpdatePreflightOptions{
		StagingRoot: t.TempDir(),
		StagingID:   "../escape",
		MaxBytes:    1024,
	})
	if outcome.Status != "FAILED" || outcome.ErrorCode != selfupdate.ErrStagingIO {
		t.Fatalf("outcome=%+v, want failed staging IO", outcome)
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

func writeActivationPlanForPreflightMainTest(t *testing.T, root, stagingID, currentPath string, stagedPayload []byte) selfupdate.StagingPaths {
	t.Helper()
	paths, code, reason := selfupdate.BuildStagingPaths(root, stagingID)
	if code != "" {
		t.Fatalf("BuildStagingPaths: code=%q reason=%q", code, reason)
	}
	if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	if err := os.WriteFile(paths.BinaryPath, stagedPayload, 0o600); err != nil {
		t.Fatalf("write staged binary: %v", err)
	}
	sum := sha256.Sum256(stagedPayload)
	plan := selfupdate.ActivationPlan{
		SchemaVersion:          1,
		StagingID:              paths.StagingID,
		ActivationPlanID:       paths.StagingID,
		ServiceName:            "EndpointAgent",
		CurrentBinaryPath:      currentPath,
		StagedBinaryPath:       paths.BinaryPath,
		ActivationPlanPath:     paths.ActivationPlanPath,
		TargetVersion:          "1.1.0",
		ActualSha256:           hex.EncodeToString(sum[:]),
		ActualSignerThumbprint: "AABBCC",
		SigningTier:            selfupdate.TierTrusted,
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal activation plan: %v", err)
	}
	if err := os.WriteFile(paths.ActivationPlanPath, raw, 0o600); err != nil {
		t.Fatalf("write activation plan: %v", err)
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
