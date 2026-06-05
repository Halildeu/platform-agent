package selfupdate

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPrepareRollbackBackupPersistsVerifiedBackupAndPlan(t *testing.T) {
	root := t.TempDir()
	withNoopStagedFileHardener(t)
	paths, plan, stagedPayload := writeTestActivationPlan(t, root)
	currentPayload := []byte("current agent binary")
	if err := os.WriteFile(plan.CurrentBinaryPath, currentPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, reason := WriteActivationPlan(paths, plan); code != "" || reason != "" {
		t.Fatalf("WriteActivationPlan: code=%q reason=%q", code, reason)
	}
	if err := os.WriteFile(paths.BinaryPath, stagedPayload, 0o600); err != nil {
		t.Fatal(err)
	}

	rollbackPlan, readiness, code, reason := PrepareRollbackBackup(paths, 1024)
	if code != "" || reason != "" {
		t.Fatalf("PrepareRollbackBackup: code=%q reason=%q", code, reason)
	}
	if !readiness.BackupVerified || readiness.ActivationPlanID != plan.ActivationPlanID {
		t.Fatalf("readiness mismatch: %+v", readiness)
	}
	backupBytes, err := os.ReadFile(rollbackPlan.BackupBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(backupBytes) != string(currentPayload) {
		t.Fatalf("backup bytes=%q", backupBytes)
	}
	rawPlan, err := os.ReadFile(rollbackPlan.RollbackPlanPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RollbackPlan
	if err := json.Unmarshal(rawPlan, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.BackupSha256 != readiness.BackupSha256 || decoded.BackupBinaryPath != rollbackBackupPath(paths) {
		t.Fatalf("decoded rollback plan mismatch: %+v readiness=%+v", decoded, readiness)
	}
	for _, p := range []string{rollbackBackupPath(paths) + ".tmp", rollbackPlanPath(paths) + ".tmp"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("temp rollback artifact left behind %s: %v", p, err)
		}
	}
}

func TestPrepareRollbackBackupRejectsTamperedStagedBinary(t *testing.T) {
	root := t.TempDir()
	withNoopStagedFileHardener(t)
	paths, plan, _ := writeTestActivationPlan(t, root)
	if err := os.WriteFile(plan.CurrentBinaryPath, []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, reason := WriteActivationPlan(paths, plan); code != "" || reason != "" {
		t.Fatalf("WriteActivationPlan: code=%q reason=%q", code, reason)
	}
	if err := os.WriteFile(paths.BinaryPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, code, _ := PrepareRollbackBackup(paths, 1024); code != ErrHashMismatch {
		t.Fatalf("code=%q, want HASH_MISMATCH", code)
	}
	if _, err := os.Stat(rollbackBackupPath(paths)); !os.IsNotExist(err) {
		t.Fatalf("rollback backup should not exist after failed preflight: %v", err)
	}
}

func TestPrepareRollbackBackupRejectsExistingBackup(t *testing.T) {
	root := t.TempDir()
	withNoopStagedFileHardener(t)
	paths, plan, stagedPayload := writeTestActivationPlan(t, root)
	if err := os.WriteFile(plan.CurrentBinaryPath, []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, reason := WriteActivationPlan(paths, plan); code != "" || reason != "" {
		t.Fatalf("WriteActivationPlan: code=%q reason=%q", code, reason)
	}
	if err := os.WriteFile(paths.BinaryPath, stagedPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rollbackBackupPath(paths), []byte("old backup"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, code, _ := PrepareRollbackBackup(paths, 1024); code != ErrActivationPlanWrite {
		t.Fatalf("code=%q, want ACTIVATION_PLAN_WRITE_FAILED", code)
	}
}
