package selfupdate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

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

// ActivationReadiness is local-only evidence that the persisted activation
// handoff still matches the staged binary before any service stop/swap work is
// attempted. It deliberately omits filesystem paths so a future wire/audit
// mirror cannot accidentally leak local layout.
type ActivationReadiness struct {
	ActivationPlanID       string      `json:"activationPlanId"`
	TargetVersion          string      `json:"targetVersion"`
	ActualSha256           string      `json:"actualSha256"`
	ActualSignerThumbprint string      `json:"actualSignerThumbprint"`
	SigningTier            SigningTier `json:"signingTier"`
	CurrentBinaryPresent   bool        `json:"currentBinaryPresent"`
	StagedBinaryVerified   bool        `json:"stagedBinaryVerified"`
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

// WriteActivationPlan atomically persists the local-only activation handoff
// file. The file is deliberately not part of StageResult; it is consumed by a
// later service-safe activation helper after the backend has received the
// bounded staging evidence.
func WriteActivationPlan(paths StagingPaths, plan ActivationPlan) (ErrorCode, string) {
	if code, reason := validateStagingPaths(paths); code != "" {
		return code, reason
	}
	if code, reason := validateActivationPlanForWrite(paths, plan); code != "" {
		return code, reason
	}
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return ErrActivationPlanWrite, "marshal activation plan failed"
	}
	raw = append(raw, '\n')

	tmp := paths.ActivationPlanPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrActivationPlanWrite, "create activation plan temp failed"
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		cleanup()
		return ErrActivationPlanWrite, "write activation plan temp failed"
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return ErrActivationPlanWrite, "fsync activation plan temp failed"
	}
	if err := f.Close(); err != nil {
		cleanup()
		return ErrActivationPlanWrite, "close activation plan temp failed"
	}
	if err := stagedFileHardener(tmp); err != nil {
		cleanup()
		return ErrActivationPlanWrite, "harden activation plan temp failed"
	}
	if err := os.Rename(tmp, paths.ActivationPlanPath); err != nil {
		cleanup()
		return ErrActivationPlanWrite, "promote activation plan failed"
	}
	if err := stagedFileHardener(paths.ActivationPlanPath); err != nil {
		return ErrActivationPlanWrite, "harden activation plan final failed"
	}
	return "", ""
}

// LoadActivationPlan reads and validates the local activation handoff file
// without performing service mutation. This is the first step a later
// activation helper must take before stopping the service or touching the
// current binary.
func LoadActivationPlan(paths StagingPaths) (ActivationPlan, ErrorCode, string) {
	if code, reason := validateStagingPaths(paths); code != "" {
		return ActivationPlan{}, code, reason
	}
	raw, err := os.ReadFile(paths.ActivationPlanPath)
	if err != nil {
		return ActivationPlan{}, ErrActivationPlanWrite, "read activation plan failed"
	}
	var plan ActivationPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return ActivationPlan{}, ErrActivationPlanWrite, "decode activation plan failed"
	}
	if code, reason := validateActivationPlanForWrite(paths, plan); code != "" {
		return ActivationPlan{}, code, reason
	}
	return plan, "", ""
}

// VerifyActivationPlanReady performs the activation-phase preflight that is
// safe to run before any service mutation: load the local plan, prove the
// staged binary still hashes to the plan evidence, and prove the current binary
// exists and is distinct from the staged binary. It does not stop services,
// replace binaries, or create rollback state.
func VerifyActivationPlanReady(paths StagingPaths, maxBytes int64) (ActivationReadiness, ErrorCode, string) {
	plan, code, reason := LoadActivationPlan(paths)
	if code != "" {
		return ActivationReadiness{}, code, reason
	}
	if sameCleanPath(plan.CurrentBinaryPath, plan.StagedBinaryPath) {
		return ActivationReadiness{}, ErrActivationPlanWrite, "current and staged binary paths must differ"
	}
	currentInfo, err := os.Stat(plan.CurrentBinaryPath)
	if err != nil {
		return ActivationReadiness{}, ErrStagingIO, "current binary is not readable"
	}
	if currentInfo.IsDir() {
		return ActivationReadiness{}, ErrStagingIO, "current binary path is a directory"
	}
	stagedHash, code, reason := HashFileWithLimit(plan.StagedBinaryPath, maxBytes)
	if code != "" {
		return ActivationReadiness{}, code, reason
	}
	if code, reason := VerifyClaimedSHA256(stagedHash.ActualSha256, plan.ActualSha256); code != "" {
		return ActivationReadiness{}, code, reason
	}
	return ActivationReadiness{
		ActivationPlanID:       plan.ActivationPlanID,
		TargetVersion:          plan.TargetVersion,
		ActualSha256:           plan.ActualSha256,
		ActualSignerThumbprint: plan.ActualSignerThumbprint,
		SigningTier:            plan.SigningTier,
		CurrentBinaryPresent:   true,
		StagedBinaryVerified:   true,
	}, "", ""
}

func validateActivationPlanForWrite(paths StagingPaths, plan ActivationPlan) (ErrorCode, string) {
	if plan.SchemaVersion != activationPlanSchemaVersion {
		return ErrActivationPlanWrite, "activation plan schema version mismatch"
	}
	if !validStagingID(plan.StagingID) || plan.StagingID != paths.StagingID || plan.ActivationPlanID != paths.StagingID {
		return ErrActivationPlanWrite, "activation plan identifiers do not match staging paths"
	}
	if strings.TrimSpace(plan.ServiceName) == "" || strings.TrimSpace(plan.CurrentBinaryPath) == "" {
		return ErrActivationPlanWrite, "activation plan missing service or current binary path"
	}
	if plan.StagedBinaryPath != paths.BinaryPath || plan.ActivationPlanPath != paths.ActivationPlanPath {
		return ErrActivationPlanWrite, "activation plan local paths do not match staging paths"
	}
	if code, reason := VerifyClaimedSHA256(plan.ActualSha256, plan.ActualSha256); code != "" {
		return code, reason
	}
	if strings.TrimSpace(plan.TargetVersion) == "" || strings.TrimSpace(plan.ActualSignerThumbprint) == "" {
		return ErrActivationPlanWrite, "activation plan missing target version or signer"
	}
	if plan.SigningTier == "" {
		return ErrActivationPlanWrite, "activation plan missing signing tier"
	}
	return "", ""
}

func sameCleanPath(a, b string) bool {
	return filepath.Clean(strings.TrimSpace(a)) == filepath.Clean(strings.TrimSpace(b))
}
