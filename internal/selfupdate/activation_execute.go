package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// ActivationServiceController is the narrow service-control dependency used by
// the post-result activation helper. Keeping it injected lets tests prove the
// stop/swap/start/rollback sequence without wiring UPDATE_AGENT execution to
// live Windows service mutation in this source slice.
type ActivationServiceController interface {
	Stop(ctx context.Context, serviceName string) error
	Start(ctx context.Context, serviceName string) error
}

// ActivationOutcome is path-free local evidence for the activation phase. It
// uses ActivationStatus rather than StageStatus because this happens after the
// staging command result has already been posted.
type ActivationOutcome struct {
	Status                 ActivationStatus `json:"status"`
	ActivationPlanID       string           `json:"activationPlanId,omitempty"`
	TargetVersion          string           `json:"targetVersion,omitempty"`
	NewSha256              string           `json:"newSha256,omitempty"`
	BackupSha256           string           `json:"backupSha256,omitempty"`
	ServiceRunningVerified bool             `json:"serviceRunningVerified,omitempty"`
	EvidencePersisted      bool             `json:"evidencePersisted"`
	Reason                 string           `json:"reason,omitempty"`
}

// ActivatePreparedUpdate performs the service-safe activation sequence for an
// already-staged update:
//
//	preflight -> rollback backup -> stop service -> binary swap -> start service
//
// If the swap or start step fails, it attempts to restore the rollback backup
// and restart the service. This helper is not called by the command executor;
// PRs that wire it into the runner must still provide watchdog/live Windows
// evidence before claiming AG-029 runtime acceptance.
func ActivatePreparedUpdate(ctx context.Context, paths StagingPaths, maxBytes int64, service ActivationServiceController) ActivationOutcome {
	if service == nil {
		return activationFailed("", "", "", "activation service controller is required")
	}
	rollbackPlan, rollbackReady, code, reason := PrepareRollbackBackup(paths, maxBytes)
	if code != "" {
		return activationFailed("", "", "", reason)
	}
	if err := service.Stop(ctx, rollbackPlanServiceNameFromPlan(rollbackPlan)); err != nil {
		return activationFailed(rollbackPlan.ActivationPlanID, rollbackPlan.TargetVersion, rollbackReady.BackupSha256, "stop service failed")
	}
	newHash, code, reason := replaceCurrentBinaryFromStaged(rollbackPlan.CurrentBinaryPath, paths.BinaryPath, rollbackPlan.TargetVersion, maxBytes)
	if code != "" {
		return rollbackAfterActivationFailure(ctx, service, rollbackPlan, rollbackReady, "binary activation failed: "+reason, maxBytes)
	}
	if err := service.Start(ctx, rollbackPlanServiceNameFromPlan(rollbackPlan)); err != nil {
		return rollbackAfterActivationFailure(ctx, service, rollbackPlan, rollbackReady, "start service failed", maxBytes)
	}
	return ActivationOutcome{
		Status:                 ActivationActivated,
		ActivationPlanID:       rollbackPlan.ActivationPlanID,
		TargetVersion:          rollbackPlan.TargetVersion,
		NewSha256:              newHash.ActualSha256,
		BackupSha256:           rollbackReady.BackupSha256,
		ServiceRunningVerified: true,
		Reason:                 "activation applied",
	}
}

func rollbackAfterActivationFailure(ctx context.Context, service ActivationServiceController, plan RollbackPlan, readiness RollbackReadiness, reason string, maxBytes int64) ActivationOutcome {
	if code, restoreReason := restoreCurrentBinaryFromRollback(plan, maxBytes); code != "" {
		return activationFailed(plan.ActivationPlanID, plan.TargetVersion, readiness.BackupSha256, "rollback restore failed: "+restoreReason)
	}
	if err := service.Start(ctx, rollbackPlanServiceNameFromPlan(plan)); err != nil {
		return activationFailed(plan.ActivationPlanID, plan.TargetVersion, readiness.BackupSha256, "rollback start failed")
	}
	return ActivationOutcome{
		Status:                 ActivationRolledBack,
		ActivationPlanID:       plan.ActivationPlanID,
		TargetVersion:          plan.TargetVersion,
		BackupSha256:           readiness.BackupSha256,
		ServiceRunningVerified: true,
		Reason:                 sanitizeReason(reason + "; rollback restored"),
	}
}

func activationFailed(planID, targetVersion, backupSha, reason string) ActivationOutcome {
	return ActivationOutcome{
		Status:           ActivationFailed,
		ActivationPlanID: planID,
		TargetVersion:    targetVersion,
		BackupSha256:     backupSha,
		Reason:           sanitizeReason(reason),
	}
}

func replaceCurrentBinaryFromStaged(currentPath, stagedPath, targetVersion string, maxBytes int64) (HashResult, ErrorCode, string) {
	if targetVersion == "" {
		return HashResult{}, ErrActivationPlanWrite, "target version is required"
	}
	stagedHash, code, reason := HashFileWithLimit(stagedPath, maxBytes)
	if code != "" {
		return HashResult{}, code, reason
	}
	tmpPath := currentPath + ".ag029.tmp"
	if result, code, reason := copyVerifiedBinaryToPath(stagedPath, tmpPath, stagedHash.ActualSha256, maxBytes); code != "" {
		return result, code, reason
	}
	cleanup := func() { _ = os.Remove(tmpPath) }
	if err := os.Remove(currentPath); err != nil && !os.IsNotExist(err) {
		cleanup()
		return HashResult{}, ErrStagingIO, "remove current binary before activation failed"
	}
	if err := os.Rename(tmpPath, currentPath); err != nil {
		cleanup()
		return HashResult{}, ErrStagingIO, "promote activated binary failed"
	}
	if err := stagedFileHardener(currentPath); err != nil {
		return HashResult{}, ErrStagingIO, "harden activated binary failed"
	}
	finalHash, code, reason := HashFileWithLimit(currentPath, maxBytes)
	if code != "" {
		return HashResult{}, code, reason
	}
	if finalHash.ActualSha256 != stagedHash.ActualSha256 || finalHash.Bytes != stagedHash.Bytes {
		return HashResult{}, ErrHashMismatch, "activated binary verification mismatch"
	}
	return finalHash, "", ""
}

func restoreCurrentBinaryFromRollback(plan RollbackPlan, maxBytes int64) (ErrorCode, string) {
	if _, code, reason := copyVerifiedBinaryToPath(plan.BackupBinaryPath, plan.CurrentBinaryPath+".ag029.rollback.tmp", plan.BackupSha256, maxBytes); code != "" {
		return code, reason
	}
	tmpPath := plan.CurrentBinaryPath + ".ag029.rollback.tmp"
	cleanup := func() { _ = os.Remove(tmpPath) }
	if err := os.Remove(plan.CurrentBinaryPath); err != nil && !os.IsNotExist(err) {
		cleanup()
		return ErrStagingIO, "remove current binary before rollback failed"
	}
	if err := os.Rename(tmpPath, plan.CurrentBinaryPath); err != nil {
		cleanup()
		return ErrStagingIO, "promote rollback binary failed"
	}
	if err := stagedFileHardener(plan.CurrentBinaryPath); err != nil {
		return ErrStagingIO, "harden rollback binary failed"
	}
	finalHash, code, reason := HashFileWithLimit(plan.CurrentBinaryPath, maxBytes)
	if code != "" {
		return code, reason
	}
	if code, reason := VerifyClaimedSHA256(finalHash.ActualSha256, plan.BackupSha256); code != "" {
		return code, reason
	}
	return "", ""
}

func copyVerifiedBinaryToPath(sourcePath, targetPath, expectedSha256 string, maxBytes int64) (HashResult, ErrorCode, string) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxUpdateBytes
	}
	src, err := os.Open(sourcePath)
	if err != nil {
		return HashResult{}, ErrStagingIO, "open source binary failed"
	}
	defer src.Close()

	f, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return HashResult{}, ErrStagingIO, "create binary temp failed"
	}
	cleanup := func() { _ = os.Remove(targetPath) }

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(src, maxBytes+1))
	if err != nil {
		_ = f.Close()
		cleanup()
		return HashResult{}, ErrStagingIO, "copy binary failed"
	}
	if n > maxBytes {
		_ = f.Close()
		cleanup()
		return HashResult{Bytes: n}, ErrDownloadTooLarge, "binary exceeded maxBytes"
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
		return HashResult{}, ErrStagingIO, "fsync binary temp failed"
	}
	if err := f.Close(); err != nil {
		cleanup()
		return HashResult{}, ErrStagingIO, "close binary temp failed"
	}
	if err := stagedFileHardener(targetPath); err != nil {
		cleanup()
		return HashResult{}, ErrStagingIO, "harden binary temp failed"
	}
	return result, "", ""
}

func rollbackPlanServiceNameFromPlan(plan RollbackPlan) string {
	if plan.ServiceName == "" {
		return "EndpointAgent"
	}
	return plan.ServiceName
}
