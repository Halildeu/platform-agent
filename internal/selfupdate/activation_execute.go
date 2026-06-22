package selfupdate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

// ActivationServiceController is the narrow service-control dependency used by
// the post-result activation helper. Production wires Windows SCM; tests use a
// fake so the stop/swap/start/rollback ordering stays deterministic.
type ActivationServiceController interface {
	Stop(ctx context.Context, serviceName string) error
	Start(ctx context.Context, serviceName string) error
}

// HighWaterWriter advances the activated-version anti-replay marker after a
// successful service restart. FileHighWaterStore implements this interface.
type HighWaterWriter interface {
	WriteMaxSeen(ctx context.Context, version string) error
}

// ActivationOutcome is path-free evidence for the activation phase.
type ActivationOutcome struct {
	Status                   ActivationStatus `json:"status"`
	ActivationPlanID         string           `json:"activationPlanId,omitempty"`
	TargetVersion            string           `json:"targetVersion,omitempty"`
	NewSha256                string           `json:"newSha256,omitempty"`
	BackupSha256             string           `json:"backupSha256,omitempty"`
	ServiceRunningVerified   bool             `json:"serviceRunningVerified,omitempty"`
	EvidencePersisted        bool             `json:"evidencePersisted"`
	EvidencePersistenceError string           `json:"evidencePersistenceError,omitempty"`
	Reason                   string           `json:"reason,omitempty"`
}

// ActivatePreparedUpdate applies an already-staged self-update. It is called
// after the staging command result has been submitted to the backend.
func ActivatePreparedUpdate(ctx context.Context, root, stagingID string, maxBytes int64, service ActivationServiceController, highWater HighWaterWriter) ActivationOutcome {
	if service == nil {
		return persistActivationOutcome(ctx, root, stagingID, activationFailed(validActivationPlanIDOrEmpty(stagingID), "", "", "activation service controller is required"))
	}
	plan, code, reason := LoadActivationPlan(root, stagingID)
	if code != "" {
		return persistActivationOutcome(ctx, root, stagingID, activationFailed(stagingID, "", "", reason))
	}
	if _, code, reason := VerifyActivationPlanReady(root, stagingID, maxBytes); code != "" {
		return persistActivationOutcome(ctx, root, stagingID, activationFailed(plan.ActivationPlanID, plan.TargetVersion, "", reason))
	}
	backupHash, code, reason := copyBinaryWithExpectedHash(plan.CurrentBinaryPath, activationBackupNameFor(root, stagingID), "", maxBytes)
	if code != "" {
		return persistActivationOutcome(ctx, root, stagingID, activationFailed(plan.ActivationPlanID, plan.TargetVersion, "", reason))
	}
	if err := service.Stop(ctx, plan.ServiceName); err != nil {
		return persistActivationOutcome(ctx, root, stagingID, activationFailed(plan.ActivationPlanID, plan.TargetVersion, backupHash.ActualSha256, "stop service failed"))
	}
	newHash, code, reason := copyBinaryWithExpectedHash(plan.StagedBinaryPath, plan.CurrentBinaryPath+".ag029.tmp", plan.ActualSha256, maxBytes)
	if code != "" {
		return rollbackAfterActivationFailure(ctx, root, stagingID, service, plan, backupHash.ActualSha256, "binary activation failed: "+reason, maxBytes)
	}
	if err := replaceFile(plan.CurrentBinaryPath+".ag029.tmp", plan.CurrentBinaryPath); err != nil {
		return rollbackAfterActivationFailure(ctx, root, stagingID, service, plan, backupHash.ActualSha256, "binary activation promote failed", maxBytes)
	}
	if err := service.Start(ctx, plan.ServiceName); err != nil {
		return rollbackAfterActivationFailure(ctx, root, stagingID, service, plan, backupHash.ActualSha256, "start service failed", maxBytes)
	}
	if highWater != nil {
		if err := highWater.WriteMaxSeen(ctx, plan.TargetVersion); err != nil {
			out := activationFailed(plan.ActivationPlanID, plan.TargetVersion, backupHash.ActualSha256, "high-water persistence failed")
			return persistActivationOutcome(ctx, root, stagingID, out)
		}
	}
	out := ActivationOutcome{
		Status:                 ActivationActivated,
		ActivationPlanID:       plan.ActivationPlanID,
		TargetVersion:          plan.TargetVersion,
		NewSha256:              newHash.ActualSha256,
		BackupSha256:           backupHash.ActualSha256,
		ServiceRunningVerified: true,
		Reason:                 "activation applied",
	}
	persistedOut := out
	persistedOut.EvidencePersisted = true
	if err := WriteActivationOutcome(ctx, root, stagingID, persistedOut); err != nil {
		out.Status = ActivationFailed
		out.ServiceRunningVerified = true
		out.Reason = "activation applied but evidence persistence failed"
		return out
	}
	return persistedOut
}

func persistActivationOutcome(ctx context.Context, root, stagingID string, outcome ActivationOutcome) ActivationOutcome {
	if !validStagingID(stagingID) {
		outcome.EvidencePersistenceError = "invalid activation outcome identifier"
		return outcome
	}
	persistedOut := outcome
	persistedOut.EvidencePersisted = true
	if err := WriteActivationOutcome(ctx, root, stagingID, persistedOut); err != nil {
		outcome.EvidencePersistenceError = sanitizeReason("activation outcome persistence failed: " + err.Error())
		return outcome
	}
	return persistedOut
}

func validActivationPlanIDOrEmpty(stagingID string) string {
	if !validStagingID(stagingID) {
		return ""
	}
	return stagingID
}

func WriteActivationOutcome(ctx context.Context, root, stagingID string, outcome ActivationOutcome) error {
	if !validStagingID(stagingID) {
		return activationPlanError{code: ErrActivationPlanWrite, reason: "invalid activation outcome identifier"}
	}
	raw, err := json.MarshalIndent(outcome, "", "  ")
	if err != nil {
		return activationPlanError{code: ErrActivationPlanWrite, reason: "marshal activation outcome failed"}
	}
	raw = append(raw, '\n')
	return atomicWriteLocalSelfUpdateJSON(ctx, activationOutcomeNameFor(root, stagingID), raw)
}

func LoadActivationOutcome(root, stagingID string) (ActivationOutcome, ErrorCode, string) {
	if !validStagingID(stagingID) {
		return ActivationOutcome{}, ErrActivationPlanWrite, "invalid activation outcome identifier"
	}
	raw, err := os.ReadFile(activationOutcomeNameFor(root, stagingID))
	if err != nil {
		return ActivationOutcome{}, ErrActivationPlanWrite, "read activation outcome failed"
	}
	var out ActivationOutcome
	if err := json.Unmarshal(stripUTF8BOM(raw), &out); err != nil {
		return ActivationOutcome{}, ErrActivationPlanWrite, "decode activation outcome failed"
	}
	if out.Status == "" {
		return ActivationOutcome{}, ErrActivationPlanWrite, "activation outcome missing status"
	}
	return out, "", ""
}

func rollbackAfterActivationFailure(ctx context.Context, root, stagingID string, service ActivationServiceController, plan ActivationPlan, backupSha, reason string, maxBytes int64) ActivationOutcome {
	backupPath := activationBackupNameFor(filepath.Dir(plan.StagedBinaryPath), plan.StagingID)
	if _, code, restoreReason := copyBinaryWithExpectedHash(backupPath, plan.CurrentBinaryPath+".ag029.rollback.tmp", backupSha, maxBytes); code != "" {
		return persistActivationOutcome(ctx, root, stagingID, activationFailed(plan.ActivationPlanID, plan.TargetVersion, backupSha, "rollback restore failed: "+restoreReason))
	}
	if err := replaceFile(plan.CurrentBinaryPath+".ag029.rollback.tmp", plan.CurrentBinaryPath); err != nil {
		return persistActivationOutcome(ctx, root, stagingID, activationFailed(plan.ActivationPlanID, plan.TargetVersion, backupSha, "rollback promote failed"))
	}
	if err := service.Start(ctx, plan.ServiceName); err != nil {
		return persistActivationOutcome(ctx, root, stagingID, activationFailed(plan.ActivationPlanID, plan.TargetVersion, backupSha, "rollback start failed"))
	}
	return persistActivationOutcome(ctx, root, stagingID, ActivationOutcome{
		Status:                 ActivationRolledBack,
		ActivationPlanID:       plan.ActivationPlanID,
		TargetVersion:          plan.TargetVersion,
		BackupSha256:           backupSha,
		ServiceRunningVerified: true,
		Reason:                 sanitizeReason(reason + "; rollback restored"),
	})
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

func copyBinaryWithExpectedHash(sourcePath, targetPath, expectedSha string, maxBytes int64) (HashResult, ErrorCode, string) {
	sourceHash, code, reason := HashFileWithLimit(sourcePath, maxBytes)
	if code != "" {
		return HashResult{}, code, reason
	}
	if expectedSha != "" {
		if code, reason := VerifySHA256Equal(sourceHash.ActualSha256, expectedSha); code != "" {
			return HashResult{}, code, reason
		}
	}
	raw, err := os.ReadFile(sourcePath)
	if err != nil {
		return HashResult{}, ErrStagingIO, "read binary failed"
	}
	if int64(len(raw)) > maxBytes && maxBytes > 0 {
		return HashResult{Bytes: int64(len(raw))}, ErrDownloadTooLarge, "binary exceeded maxBytes"
	}
	dst, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return HashResult{}, ErrStagingIO, "write binary temp failed"
	}
	cleanup := func() { _ = os.Remove(targetPath) }
	if _, err := dst.Write(raw); err != nil {
		_ = dst.Close()
		cleanup()
		return HashResult{}, ErrStagingIO, "write binary temp failed"
	}
	if err := dst.Sync(); err != nil {
		_ = dst.Close()
		cleanup()
		return HashResult{}, ErrStagingIO, "fsync binary temp failed"
	}
	if err := dst.Close(); err != nil {
		cleanup()
		return HashResult{}, ErrStagingIO, "close binary temp failed"
	}
	if err := hardenActivationArtifact(targetPath); err != nil {
		cleanup()
		return HashResult{}, ErrStagingIO, "harden binary temp failed"
	}
	return sourceHash, "", ""
}

func replaceFile(tempPath, finalPath string) error {
	if err := os.Remove(finalPath); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(tempPath)
		return err
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return hardenActivationArtifact(finalPath)
}
