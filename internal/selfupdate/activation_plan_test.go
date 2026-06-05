package selfupdate

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestBuildReadyStageResultAndActivationPlan(t *testing.T) {
	paths, code, reason := BuildStagingPaths(`C:\ProgramData\EndpointAgent\updates`, "req-123")
	if code != "" || reason != "" {
		t.Fatalf("BuildStagingPaths: code=%q reason=%q", code, reason)
	}
	evidence := PreflightEvidence{OldVersion: "1.0.0", TargetVersion: "1.1.0", SigningTier: TierTrusted}
	sha := strings.Repeat("a", 64)
	ready, code, reason := BuildReadyStageResult(paths, evidence, sha, "aa:bb cc")
	if code != "" || reason != "" {
		t.Fatalf("BuildReadyStageResult: code=%q reason=%q", code, reason)
	}
	if ready.StageStatus != StageReady || ready.StagingID != "req-123" || ready.ActualSignerThumbprint != "AABBCC" {
		t.Fatalf("ready result wrong: %+v", ready)
	}

	plan, code, reason := BuildActivationPlan(paths, `C:\Program Files\EndpointAgent\endpoint-agent.exe`, "EndpointAgent", ready)
	if code != "" || reason != "" {
		t.Fatalf("BuildActivationPlan: code=%q reason=%q", code, reason)
	}
	if plan.SchemaVersion != 1 || plan.StagedBinaryPath != paths.BinaryPath || plan.ActivationPlanPath != paths.ActivationPlanPath {
		t.Fatalf("activation plan wrong: %+v", plan)
	}
}

func TestActivationPlanLocalOnlyButStageResultNoPath(t *testing.T) {
	paths, _, _ := BuildStagingPaths(`C:\ProgramData\EndpointAgent\updates`, "req-456")
	evidence := PreflightEvidence{OldVersion: "1.0.0", TargetVersion: "1.2.0", SigningTier: TierTrusted}
	ready, code, reason := BuildReadyStageResult(paths, evidence, strings.Repeat("b", 64), "ABCDEF")
	if code != "" || reason != "" {
		t.Fatalf("BuildReadyStageResult: code=%q reason=%q", code, reason)
	}
	plan, code, reason := BuildActivationPlan(paths, `C:\Program Files\EndpointAgent\endpoint-agent.exe`, "EndpointAgent", ready)
	if code != "" || reason != "" {
		t.Fatalf("BuildActivationPlan: code=%q reason=%q", code, reason)
	}

	stageJSON, err := json.Marshal(ready)
	if err != nil {
		t.Fatalf("stage marshal: %v", err)
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("plan marshal: %v", err)
	}
	if strings.Contains(strings.ToLower(string(stageJSON)), "program") || strings.Contains(string(stageJSON), `\`) {
		t.Fatalf("StageResult leaked local path: %s", stageJSON)
	}
	if !strings.Contains(strings.ToLower(string(planJSON)), "program") || !strings.Contains(string(planJSON), `\`) {
		t.Fatalf("ActivationPlan should be local-only and carry paths: %s", planJSON)
	}
}

func TestBuildActivationPlanRejectsNonReadyAndMismatchedIDs(t *testing.T) {
	paths, _, _ := BuildStagingPaths("/updates", "req-789")
	if _, code, _ := BuildActivationPlan(paths, "/agent", "EndpointAgent", Failed(ErrStagingIO, "x")); code != ErrActivationPlanWrite {
		t.Fatalf("non-ready code=%q, want ACTIVATION_PLAN_WRITE_FAILED", code)
	}
	ready := StageResult{
		StageStatus:            StageReady,
		StagingID:              "other",
		ActivationPlanID:       "other",
		TargetVersion:          "1.1.0",
		ActualSha256:           strings.Repeat("a", 64),
		ActualSignerThumbprint: "ABCDEF",
		SigningTier:            TierTrusted,
	}
	if _, code, _ := BuildActivationPlan(paths, "/agent", "EndpointAgent", ready); code != ErrActivationPlanWrite {
		t.Fatalf("mismatched ID code=%q, want ACTIVATION_PLAN_WRITE_FAILED", code)
	}
}

func TestWriteActivationPlanPersistsLocalOnlyPlan(t *testing.T) {
	root := t.TempDir()
	withNoopStagedFileHardener(t)
	paths, code, reason := BuildStagingPaths(root, "req-write")
	if code != "" || reason != "" {
		t.Fatalf("BuildStagingPaths: code=%q reason=%q", code, reason)
	}
	if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
		t.Fatal(err)
	}
	evidence := PreflightEvidence{OldVersion: "1.0.0", TargetVersion: "1.2.0", SigningTier: TierTrusted}
	ready, code, reason := BuildReadyStageResult(paths, evidence, strings.Repeat("c", 64), "AA:BB")
	if code != "" || reason != "" {
		t.Fatalf("BuildReadyStageResult: code=%q reason=%q", code, reason)
	}
	plan, code, reason := BuildActivationPlan(paths, "/agent/current.exe", "EndpointAgent", ready)
	if code != "" || reason != "" {
		t.Fatalf("BuildActivationPlan: code=%q reason=%q", code, reason)
	}

	if code, reason := WriteActivationPlan(paths, plan); code != "" || reason != "" {
		t.Fatalf("WriteActivationPlan: code=%q reason=%q", code, reason)
	}

	raw, err := os.ReadFile(paths.ActivationPlanPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ActivationPlan
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ActivationPlanID != plan.ActivationPlanID || decoded.StagedBinaryPath != paths.BinaryPath {
		t.Fatalf("decoded plan mismatch: %+v", decoded)
	}
	if _, err := os.Stat(paths.ActivationPlanPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp activation plan left behind: %v", err)
	}
}

func TestWriteActivationPlanRejectsPathMismatch(t *testing.T) {
	paths, _, _ := BuildStagingPaths(t.TempDir(), "req-mismatch")
	plan := ActivationPlan{
		SchemaVersion:          activationPlanSchemaVersion,
		StagingID:              paths.StagingID,
		ActivationPlanID:       paths.StagingID,
		ServiceName:            "EndpointAgent",
		CurrentBinaryPath:      "/agent/current.exe",
		StagedBinaryPath:       "/evil/endpoint-agent.exe",
		ActivationPlanPath:     paths.ActivationPlanPath,
		TargetVersion:          "1.2.0",
		ActualSha256:           strings.Repeat("d", 64),
		ActualSignerThumbprint: "AABB",
		SigningTier:            TierTrusted,
	}
	if code, _ := WriteActivationPlan(paths, plan); code != ErrActivationPlanWrite {
		t.Fatalf("code=%q, want ACTIVATION_PLAN_WRITE_FAILED", code)
	}
}
