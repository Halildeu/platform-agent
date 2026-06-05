package selfupdate

import "strings"

const activationPlanSchemaVersion = 1

// ActivationPlan is a LOCAL-ONLY handoff file for the post-result activation
// helper (PR3). It may contain filesystem paths because it is never posted to
// the backend. StageResult remains the only wire shape and carries only opaque
// IDs plus bounded evidence.
type ActivationPlan struct {
	SchemaVersion          int         `json:"schemaVersion"`
	StagingID              string      `json:"stagingId"`
	ActivationPlanID       string      `json:"activationPlanId"`
	ServiceName            string      `json:"serviceName"`
	CurrentBinaryPath      string      `json:"currentBinaryPath"`
	StagedBinaryPath       string      `json:"stagedBinaryPath"`
	ActivationPlanPath     string      `json:"activationPlanPath"`
	TargetVersion          string      `json:"targetVersion"`
	ActualSha256           string      `json:"actualSha256"`
	ActualSignerThumbprint string      `json:"actualSignerThumbprint"`
	SigningTier            SigningTier `json:"signingTier"`
}

// BuildReadyStageResult converts verified local staging evidence into the
// backend-safe wire result. It rejects unsafe IDs and malformed hashes before
// constructing a STAGED_ACTIVATION_READY outcome.
func BuildReadyStageResult(paths StagingPaths, evidence PreflightEvidence, actualSha256, actualSignerThumbprint string) (StageResult, ErrorCode, string) {
	if !validStagingID(paths.StagingID) {
		return StageResult{}, ErrStagingIO, "invalid staging identifier"
	}
	if code, reason := VerifyClaimedSHA256(actualSha256, actualSha256); code != "" {
		return StageResult{}, code, reason
	}
	if strings.TrimSpace(actualSignerThumbprint) == "" {
		return StageResult{}, ErrSignerNotAllowed, "actual signer thumbprint is required"
	}
	return StageResult{
		StageStatus:            StageReady,
		StagingID:              paths.StagingID,
		ActivationPlanID:       paths.StagingID,
		OldVersion:             evidence.OldVersion,
		TargetVersion:          evidence.TargetVersion,
		ActualSha256:           strings.ToLower(strings.TrimSpace(actualSha256)),
		ActualSignerThumbprint: normalizeThumbprint(actualSignerThumbprint),
		SigningTier:            evidence.SigningTier,
		Reason:                 "staged activation ready",
	}, "", ""
}

// BuildActivationPlan constructs the local activation helper contract from
// the same evidence used in the wire result. The plan is valid only for a
// StageReady result; noop/failed staging outcomes must not create activation
// work.
func BuildActivationPlan(paths StagingPaths, currentBinaryPath, serviceName string, ready StageResult) (ActivationPlan, ErrorCode, string) {
	if ready.StageStatus != StageReady {
		return ActivationPlan{}, ErrActivationPlanWrite, "activation plan requires STAGED_ACTIVATION_READY"
	}
	if !validStagingID(paths.StagingID) || ready.StagingID != paths.StagingID || ready.ActivationPlanID != paths.StagingID {
		return ActivationPlan{}, ErrActivationPlanWrite, "activation plan identifiers do not match staging paths"
	}
	if strings.TrimSpace(currentBinaryPath) == "" || strings.TrimSpace(serviceName) == "" {
		return ActivationPlan{}, ErrActivationPlanWrite, "current binary path and service name are required"
	}
	if code, reason := VerifyClaimedSHA256(ready.ActualSha256, ready.ActualSha256); code != "" {
		return ActivationPlan{}, code, reason
	}
	if strings.TrimSpace(ready.TargetVersion) == "" || strings.TrimSpace(ready.ActualSignerThumbprint) == "" {
		return ActivationPlan{}, ErrActivationPlanWrite, "activation plan missing target version or signer"
	}
	return ActivationPlan{
		SchemaVersion:          activationPlanSchemaVersion,
		StagingID:              paths.StagingID,
		ActivationPlanID:       ready.ActivationPlanID,
		ServiceName:            strings.TrimSpace(serviceName),
		CurrentBinaryPath:      strings.TrimSpace(currentBinaryPath),
		StagedBinaryPath:       paths.BinaryPath,
		ActivationPlanPath:     paths.ActivationPlanPath,
		TargetVersion:          ready.TargetVersion,
		ActualSha256:           strings.ToLower(strings.TrimSpace(ready.ActualSha256)),
		ActualSignerThumbprint: normalizeThumbprint(ready.ActualSignerThumbprint),
		SigningTier:            ready.SigningTier,
	}, "", ""
}
