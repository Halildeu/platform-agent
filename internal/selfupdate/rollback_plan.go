package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
)

const rollbackPlanSchemaVersion = 1

// RollbackPlan is a LOCAL-ONLY handoff file for the later activation helper.
// It records the verified backup of the currently running binary before any
// service stop/swap work is attempted. It is never posted to the backend.
type RollbackPlan struct {
	SchemaVersion     int    `json:"schemaVersion"`
	ActivationPlanID  string `json:"activationPlanId"`
	CurrentBinaryPath string `json:"currentBinaryPath"`
	BackupBinaryPath  string `json:"backupBinaryPath"`
	RollbackPlanPath  string `json:"rollbackPlanPath"`
	BackupSha256      string `json:"backupSha256"`
	TargetVersion     string `json:"targetVersion"`
}

// RollbackReadiness is path-free local evidence that a rollback backup exists
// and matches the current binary bytes captured before activation.
type RollbackReadiness struct {
	ActivationPlanID string `json:"activationPlanId"`
	BackupSha256     string `json:"backupSha256"`
	BackupVerified   bool   `json:"backupVerified"`
}

// PrepareRollbackBackup performs the rollback-preparation phase that is safe
// before service mutation: activation preflight, current-binary backup copy,
// final backup rehash, and rollback-plan persistence. It does not stop the
// service, replace the current binary, or start a watchdog.
func PrepareRollbackBackup(paths StagingPaths, maxBytes int64) (RollbackPlan, RollbackReadiness, ErrorCode, string) {
	activationPlan, code, reason := LoadActivationPlan(paths)
	if code != "" {
		return RollbackPlan{}, RollbackReadiness{}, code, reason
	}
	if _, code, reason := VerifyActivationPlanReady(paths, maxBytes); code != "" {
		return RollbackPlan{}, RollbackReadiness{}, code, reason
	}
	if code, reason := validateRollbackPaths(paths, activationPlan); code != "" {
		return RollbackPlan{}, RollbackReadiness{}, code, reason
	}
	currentHash, code, reason := HashFileWithLimit(activationPlan.CurrentBinaryPath, maxBytes)
	if code != "" {
		return RollbackPlan{}, RollbackReadiness{}, code, reason
	}
	backupPath := rollbackBackupPath(paths)
	backupHash, code, reason := copyBinaryForRollback(activationPlan.CurrentBinaryPath, backupPath, currentHash.ActualSha256, maxBytes)
	if code != "" {
		removeRollbackArtifacts(paths)
		return RollbackPlan{}, RollbackReadiness{}, code, reason
	}
	rollbackPlan := RollbackPlan{
		SchemaVersion:     rollbackPlanSchemaVersion,
		ActivationPlanID:  activationPlan.ActivationPlanID,
		CurrentBinaryPath: activationPlan.CurrentBinaryPath,
		BackupBinaryPath:  backupPath,
		RollbackPlanPath:  rollbackPlanPath(paths),
		BackupSha256:      backupHash.ActualSha256,
		TargetVersion:     activationPlan.TargetVersion,
	}
	if code, reason := WriteRollbackPlan(paths, rollbackPlan); code != "" {
		removeRollbackArtifacts(paths)
		return RollbackPlan{}, RollbackReadiness{}, code, reason
	}
	return rollbackPlan, RollbackReadiness{
		ActivationPlanID: activationPlan.ActivationPlanID,
		BackupSha256:     backupHash.ActualSha256,
		BackupVerified:   true,
	}, "", ""
}

func WriteRollbackPlan(paths StagingPaths, plan RollbackPlan) (ErrorCode, string) {
	if code, reason := validateStagingPaths(paths); code != "" {
		return code, reason
	}
	if code, reason := validateRollbackPlanForWrite(paths, plan); code != "" {
		return code, reason
	}
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return ErrActivationPlanWrite, "marshal rollback plan failed"
	}
	raw = append(raw, '\n')

	tmp := rollbackPlanPath(paths) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrActivationPlanWrite, "create rollback plan temp failed"
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		cleanup()
		return ErrActivationPlanWrite, "write rollback plan temp failed"
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return ErrActivationPlanWrite, "fsync rollback plan temp failed"
	}
	if err := f.Close(); err != nil {
		cleanup()
		return ErrActivationPlanWrite, "close rollback plan temp failed"
	}
	if err := stagedFileHardener(tmp); err != nil {
		cleanup()
		return ErrActivationPlanWrite, "harden rollback plan temp failed"
	}
	if err := os.Rename(tmp, rollbackPlanPath(paths)); err != nil {
		cleanup()
		return ErrActivationPlanWrite, "promote rollback plan failed"
	}
	if err := stagedFileHardener(rollbackPlanPath(paths)); err != nil {
		return ErrActivationPlanWrite, "harden rollback plan final failed"
	}
	return "", ""
}

func validateRollbackPaths(paths StagingPaths, plan ActivationPlan) (ErrorCode, string) {
	if code, reason := validateStagingPaths(paths); code != "" {
		return code, reason
	}
	backupPath := rollbackBackupPath(paths)
	planPath := rollbackPlanPath(paths)
	for _, p := range []string{backupPath, planPath} {
		if !pathWithinRoot(paths.Directory, p) {
			return ErrActivationPlanWrite, "rollback path escaped staging directory"
		}
	}
	if sameCleanPath(plan.CurrentBinaryPath, backupPath) || sameCleanPath(plan.StagedBinaryPath, backupPath) {
		return ErrActivationPlanWrite, "rollback backup path overlaps activation binaries"
	}
	if _, err := os.Stat(backupPath); err == nil {
		return ErrActivationPlanWrite, "rollback backup already exists"
	} else if !os.IsNotExist(err) {
		return ErrActivationPlanWrite, "inspect rollback backup failed"
	}
	if _, err := os.Stat(planPath); err == nil {
		return ErrActivationPlanWrite, "rollback plan already exists"
	} else if !os.IsNotExist(err) {
		return ErrActivationPlanWrite, "inspect rollback plan failed"
	}
	return "", ""
}

func validateRollbackPlanForWrite(paths StagingPaths, plan RollbackPlan) (ErrorCode, string) {
	if plan.SchemaVersion != rollbackPlanSchemaVersion {
		return ErrActivationPlanWrite, "rollback plan schema version mismatch"
	}
	if !validStagingID(paths.StagingID) || plan.ActivationPlanID != paths.StagingID {
		return ErrActivationPlanWrite, "rollback plan identifier does not match staging paths"
	}
	if strings.TrimSpace(plan.CurrentBinaryPath) == "" || plan.BackupBinaryPath != rollbackBackupPath(paths) || plan.RollbackPlanPath != rollbackPlanPath(paths) {
		return ErrActivationPlanWrite, "rollback plan local paths do not match staging paths"
	}
	if code, reason := VerifyClaimedSHA256(plan.BackupSha256, plan.BackupSha256); code != "" {
		return code, reason
	}
	if strings.TrimSpace(plan.TargetVersion) == "" {
		return ErrActivationPlanWrite, "rollback plan missing target version"
	}
	return "", ""
}

func copyBinaryForRollback(sourcePath, backupPath, expectedSha256 string, maxBytes int64) (HashResult, ErrorCode, string) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxUpdateBytes
	}
	src, err := os.Open(sourcePath)
	if err != nil {
		return HashResult{}, ErrStagingIO, "open current binary for rollback backup failed"
	}
	defer src.Close()

	tmp := backupPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return HashResult{}, ErrActivationPlanWrite, "create rollback backup temp failed"
	}
	cleanup := func() { _ = os.Remove(tmp) }

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(src, maxBytes+1))
	if err != nil {
		_ = f.Close()
		cleanup()
		return HashResult{}, ErrStagingIO, "copy current binary for rollback backup failed"
	}
	if n > maxBytes {
		_ = f.Close()
		cleanup()
		return HashResult{Bytes: n}, ErrDownloadTooLarge, "current binary exceeded maxBytes"
	}
	result := HashResult{ActualSha256: hex.EncodeToString(h.Sum(nil)), Bytes: n}
	if code, reason := VerifyClaimedSHA256(result.ActualSha256, expectedSha256); code != "" {
		_ = f.Close()
		cleanup()
		return result, code, reason
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return HashResult{}, ErrActivationPlanWrite, "fsync rollback backup temp failed"
	}
	if err := f.Close(); err != nil {
		cleanup()
		return HashResult{}, ErrActivationPlanWrite, "close rollback backup temp failed"
	}
	if err := stagedFileHardener(tmp); err != nil {
		cleanup()
		return HashResult{}, ErrActivationPlanWrite, "harden rollback backup temp failed"
	}
	if err := os.Rename(tmp, backupPath); err != nil {
		cleanup()
		return HashResult{}, ErrActivationPlanWrite, "promote rollback backup failed"
	}
	if err := stagedFileHardener(backupPath); err != nil {
		return HashResult{}, ErrActivationPlanWrite, "harden rollback backup final failed"
	}
	finalHash, code, reason := HashFileWithLimit(backupPath, maxBytes)
	if code != "" {
		return HashResult{}, code, reason
	}
	if finalHash.ActualSha256 != result.ActualSha256 || finalHash.Bytes != result.Bytes {
		return HashResult{}, ErrHashMismatch, "final rollback backup verification mismatch"
	}
	return result, "", ""
}

func removeRollbackArtifacts(paths StagingPaths) {
	_ = os.Remove(rollbackBackupPath(paths) + ".tmp")
	_ = os.Remove(rollbackBackupPath(paths))
	_ = os.Remove(rollbackPlanPath(paths) + ".tmp")
	_ = os.Remove(rollbackPlanPath(paths))
}
