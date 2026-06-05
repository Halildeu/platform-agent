package selfupdate

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestWriteActivationOutcomePersistsPathFreeEvidence(t *testing.T) {
	withNoopStagedFileHardener(t)
	root := t.TempDir()
	paths, code, reason := BuildStagingPaths(root, "req-outcome")
	if code != "" {
		t.Fatalf("BuildStagingPaths: code=%q reason=%q", code, reason)
	}
	if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
		t.Fatalf("mkdir staging dir: %v", err)
	}
	outcome := ActivationOutcome{
		Status:           ActivationActivated,
		ActivationPlanID: paths.StagingID,
		TargetVersion:    "1.2.3",
		NewSha256:        strings.Repeat("a", 64),
		BackupSha256:     strings.Repeat("b", 64),
		Reason:           `activated from C:\ProgramData\EndpointAgent\updates\req-outcome`,
	}
	if code, reason := WriteActivationOutcome(paths, outcome); code != "" {
		t.Fatalf("WriteActivationOutcome: code=%q reason=%q", code, reason)
	}
	raw, err := os.ReadFile(activationOutcomePath(paths))
	if err != nil {
		t.Fatalf("read activation outcome: %v", err)
	}
	if strings.Contains(string(raw), `C:\`) || strings.Contains(string(raw), "ProgramData") {
		t.Fatalf("activation outcome leaked a local path: %s", raw)
	}
	var decoded ActivationOutcome
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode activation outcome: %v", err)
	}
	if decoded.Status != ActivationActivated || decoded.ActivationPlanID != paths.StagingID || decoded.TargetVersion != "1.2.3" {
		t.Fatalf("decoded outcome mismatch: %+v", decoded)
	}
	if decoded.Reason != "(reason redacted: contained a path-like token)" {
		t.Fatalf("reason was not redacted: %q", decoded.Reason)
	}
	if _, err := os.Stat(activationOutcomePath(paths) + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("activation outcome temp should not remain: %v", err)
	}
}

func TestWriteActivationOutcomeRejectsUnknownStatus(t *testing.T) {
	withNoopStagedFileHardener(t)
	root := t.TempDir()
	paths, code, reason := BuildStagingPaths(root, "req-bad-outcome")
	if code != "" {
		t.Fatalf("BuildStagingPaths: code=%q reason=%q", code, reason)
	}
	if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
		t.Fatalf("mkdir staging dir: %v", err)
	}
	code, _ = WriteActivationOutcome(paths, ActivationOutcome{ActivationPlanID: paths.StagingID})
	if code != ErrActivationPlanWrite {
		t.Fatalf("code=%q, want %q", code, ErrActivationPlanWrite)
	}
	if _, err := os.Stat(activationOutcomePath(paths)); !os.IsNotExist(err) {
		t.Fatalf("activation outcome should not be written: %v", err)
	}
}
