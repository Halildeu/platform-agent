package selfupdate

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
)

func TestBuildActivationPlanKeepsPathsLocalOnly(t *testing.T) {
	root := t.TempDir()
	stagingID := "0123456789abcdef0123456789abcdef"
	stagedPath := stagedNameFor(root, stagingID)
	ready := readyStageForPlan(stagingID, strings.Repeat("a", 64))

	plan, code, reason := BuildActivationPlan(stagedPath, filepath.Join(root, "current.exe"), "EndpointAgent", ready)
	if code != "" || reason != "" {
		t.Fatalf("BuildActivationPlan: code=%q reason=%q", code, reason)
	}
	if plan.ActivationPlanPath != activationPlanNameFor(root, stagingID) {
		t.Fatalf("ActivationPlanPath = %q", plan.ActivationPlanPath)
	}
	stageJSON, err := json.Marshal(ready)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(stageJSON)), "path") || strings.Contains(string(stageJSON), root) {
		t.Fatalf("StageResult leaked local path: %s", stageJSON)
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(planJSON), filepath.Base(plan.CurrentBinaryPath)) ||
		!strings.Contains(string(planJSON), filepath.Base(plan.StagedBinaryPath)) ||
		!strings.Contains(string(planJSON), filepath.Base(plan.ActivationPlanPath)) {
		t.Fatalf("ActivationPlan should be local-only and include path fields: %s", planJSON)
	}
}

func TestWriteLoadAndVerifyActivationPlanReady(t *testing.T) {
	root := t.TempDir()
	stagingID := "0123456789abcdef0123456789abcdef"
	payload := []byte("verified staged agent")
	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])
	stagedPath := stagedNameFor(root, stagingID)
	currentPath := filepath.Join(root, "current.exe")
	if err := os.WriteFile(stagedPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(currentPath, []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, code, reason := BuildActivationPlan(stagedPath, currentPath, "EndpointAgent", readyStageForPlan(stagingID, sha))
	if code != "" || reason != "" {
		t.Fatalf("BuildActivationPlan: code=%q reason=%q", code, reason)
	}
	writeActivationPlanOrSkip(t, plan)
	loaded, code, reason := LoadActivationPlan(root, stagingID)
	if code != "" || reason != "" {
		t.Fatalf("LoadActivationPlan: code=%q reason=%q", code, reason)
	}
	if loaded.ActivationPlanID != plan.ActivationPlanID || loaded.StagedBinaryPath != plan.StagedBinaryPath {
		t.Fatalf("loaded plan mismatch: %+v vs %+v", loaded, plan)
	}
	ready, code, reason := VerifyActivationPlanReady(root, stagingID, 1024)
	if code != "" || reason != "" {
		t.Fatalf("VerifyActivationPlanReady: code=%q reason=%q", code, reason)
	}
	if !ready.CurrentBinaryPresent || !ready.StagedBinaryVerified {
		t.Fatalf("readiness mismatch: %+v", ready)
	}
}

func TestVerifyActivationPlanReadyRejectsTamperedStagedBinary(t *testing.T) {
	root := t.TempDir()
	stagingID := "0123456789abcdef0123456789abcdef"
	stagedPath := stagedNameFor(root, stagingID)
	currentPath := filepath.Join(root, "current.exe")
	plan, code, reason := BuildActivationPlan(stagedPath, currentPath, "EndpointAgent", readyStageForPlan(stagingID, strings.Repeat("b", 64)))
	if code != "" || reason != "" {
		t.Fatalf("BuildActivationPlan: code=%q reason=%q", code, reason)
	}
	writeActivationPlanOrSkip(t, plan)
	if err := os.WriteFile(currentPath, []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stagedPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code, _ := VerifyActivationPlanReady(root, stagingID, 1024); code != ErrHashMismatch {
		t.Fatalf("code=%q, want HASH_MISMATCH", code)
	}
}

func TestLoadActivationPlanAcceptsPowerShellUTF8BOM(t *testing.T) {
	root := t.TempDir()
	stagingID := "0123456789abcdef0123456789abcdef"
	stagedPath := stagedNameFor(root, stagingID)
	currentPath := filepath.Join(root, "current.exe")
	plan, code, reason := BuildActivationPlan(stagedPath, currentPath, "EndpointAgent", readyStageForPlan(stagingID, strings.Repeat("c", 64)))
	if code != "" || reason != "" {
		t.Fatalf("BuildActivationPlan: code=%q reason=%q", code, reason)
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	raw = append([]byte{0xef, 0xbb, 0xbf}, raw...)
	if err := os.WriteFile(plan.ActivationPlanPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code, reason := LoadActivationPlan(root, stagingID); code != "" || reason != "" {
		t.Fatalf("LoadActivationPlan with BOM: code=%q reason=%q", code, reason)
	}
}

func readyStageForPlan(stagingID, sha string) StageResult {
	return StageResult{
		StageStatus:            StageReady,
		StagingID:              stagingID,
		ActivationPlanID:       stagingID,
		OldVersion:             "1.0.0",
		TargetVersion:          "1.1.0",
		ActualSha256:           sha,
		ActualSignerThumbprint: "AABBCC",
		SigningTier:            TierTrusted,
		Reason:                 "verified and staged; awaiting activation",
	}
}

func writeActivationPlanOrSkip(t *testing.T, plan ActivationPlan) {
	t.Helper()
	if err := WriteActivationPlan(context.Background(), plan); err != nil {
		skipIfActivationPlanHardenUnavailable(t, err)
		t.Fatalf("WriteActivationPlan: %v", err)
	}
}

func skipIfActivationPlanHardenUnavailable(t *testing.T, err error) {
	t.Helper()
	if runtime.GOOS == "windows" && strings.Contains(err.Error(), "harden activation") {
		t.Skipf("Windows activation plan hardening requires elevated/SYSTEM context: %v", err)
	}
}
