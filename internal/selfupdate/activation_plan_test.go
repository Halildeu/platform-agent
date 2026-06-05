package selfupdate

import (
	"encoding/json"
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
