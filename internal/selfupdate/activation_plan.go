package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const activationPlanSchemaVersion = 1

// ActivationPlan is a local-only handoff for the post-result activation
// helper. It may carry filesystem paths because it is never posted to the
// backend; StageResult remains the only wire surface and contains no paths.
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

// ActivationReadiness is path-free evidence that the local activation handoff
// still matches the staged binary before any service mutation is attempted.
type ActivationReadiness struct {
	ActivationPlanID       string      `json:"activationPlanId"`
	TargetVersion          string      `json:"targetVersion"`
	ActualSha256           string      `json:"actualSha256"`
	ActualSignerThumbprint string      `json:"actualSignerThumbprint"`
	SigningTier            SigningTier `json:"signingTier"`
	CurrentBinaryPresent   bool        `json:"currentBinaryPresent"`
	StagedBinaryVerified   bool        `json:"stagedBinaryVerified"`
}

// ActivationPlanWriter persists the local handoff after staging succeeds.
type ActivationPlanWriter interface {
	WriteActivationPlan(ctx context.Context, plan ActivationPlan) error
}

// FileActivationPlanWriter atomically writes activation plans next to the
// staged binary in the hardened self-update staging root.
type FileActivationPlanWriter struct{}

func (FileActivationPlanWriter) WriteActivationPlan(ctx context.Context, plan ActivationPlan) error {
	return WriteActivationPlan(ctx, plan)
}

func activationPlanNameFor(root, stagingID string) string {
	return filepath.Join(root, "activation-"+stagingID+".json")
}

func activationOutcomeNameFor(root, stagingID string) string {
	return filepath.Join(root, "activation-outcome-"+stagingID+".json")
}

func activationBackupNameFor(root, stagingID string) string {
	return filepath.Join(root, "rollback-"+stagingID+".bin")
}

// BuildActivationPlan converts a successful StageResult into the local helper
// contract. It rejects non-ready staging outcomes and mismatched identifiers.
func BuildActivationPlan(stagedPath, currentBinaryPath, serviceName string, ready StageResult) (ActivationPlan, ErrorCode, string) {
	if ready.StageStatus != StageReady {
		return ActivationPlan{}, ErrActivationPlanWrite, "activation plan requires STAGED_ACTIVATION_READY"
	}
	if !validStagingID(ready.StagingID) || ready.ActivationPlanID != ready.StagingID {
		return ActivationPlan{}, ErrActivationPlanWrite, "activation plan identifiers are invalid"
	}
	stagedPath = strings.TrimSpace(stagedPath)
	currentBinaryPath = strings.TrimSpace(currentBinaryPath)
	serviceName = strings.TrimSpace(serviceName)
	if stagedPath == "" || currentBinaryPath == "" || serviceName == "" {
		return ActivationPlan{}, ErrActivationPlanWrite, "activation plan missing local path or service"
	}
	root := filepath.Dir(stagedPath)
	if filepath.Base(stagedPath) != filepath.Base(stagedNameFor(root, ready.StagingID)) {
		return ActivationPlan{}, ErrActivationPlanWrite, "staged binary name does not match staging identifier"
	}
	if sameCleanPath(stagedPath, currentBinaryPath) {
		return ActivationPlan{}, ErrActivationPlanWrite, "current and staged binary paths must differ"
	}
	if !isSHA256Hex(ready.ActualSha256) {
		return ActivationPlan{}, ErrHashMismatch, "activation plan sha256 evidence is invalid"
	}
	if strings.TrimSpace(ready.TargetVersion) == "" || strings.TrimSpace(ready.ActualSignerThumbprint) == "" || ready.SigningTier == "" {
		return ActivationPlan{}, ErrActivationPlanWrite, "activation plan missing target version or signer evidence"
	}
	return ActivationPlan{
		SchemaVersion:          activationPlanSchemaVersion,
		StagingID:              ready.StagingID,
		ActivationPlanID:       ready.ActivationPlanID,
		ServiceName:            serviceName,
		CurrentBinaryPath:      currentBinaryPath,
		StagedBinaryPath:       stagedPath,
		ActivationPlanPath:     activationPlanNameFor(root, ready.StagingID),
		TargetVersion:          ready.TargetVersion,
		ActualSha256:           strings.ToLower(strings.TrimSpace(ready.ActualSha256)),
		ActualSignerThumbprint: normalizeThumbprint(ready.ActualSignerThumbprint),
		SigningTier:            ready.SigningTier,
	}, "", ""
}

func WriteActivationPlan(ctx context.Context, plan ActivationPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if code, reason := validateActivationPlan(plan); code != "" {
		return activationPlanError{code: code, reason: reason}
	}
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return activationPlanError{code: ErrActivationPlanWrite, reason: "marshal activation plan failed"}
	}
	raw = append(raw, '\n')
	if err := atomicWriteLocalSelfUpdateJSON(ctx, plan.ActivationPlanPath, raw); err != nil {
		return err
	}
	return nil
}

func LoadActivationPlan(root, stagingID string) (ActivationPlan, ErrorCode, string) {
	if !validStagingID(stagingID) || strings.TrimSpace(root) == "" {
		return ActivationPlan{}, ErrActivationPlanWrite, "invalid activation plan locator"
	}
	path := activationPlanNameFor(filepath.Clean(root), stagingID)
	raw, err := os.ReadFile(path)
	if err != nil {
		return ActivationPlan{}, ErrActivationPlanWrite, "read activation plan failed"
	}
	var plan ActivationPlan
	if err := json.Unmarshal(stripUTF8BOM(raw), &plan); err != nil {
		return ActivationPlan{}, ErrActivationPlanWrite, "decode activation plan failed"
	}
	if code, reason := validateActivationPlan(plan); code != "" {
		return ActivationPlan{}, code, reason
	}
	if filepath.Clean(plan.ActivationPlanPath) != filepath.Clean(path) {
		return ActivationPlan{}, ErrActivationPlanWrite, "activation plan path mismatch"
	}
	return plan, "", ""
}

func VerifyActivationPlanReady(root, stagingID string, maxBytes int64) (ActivationReadiness, ErrorCode, string) {
	plan, code, reason := LoadActivationPlan(root, stagingID)
	if code != "" {
		return ActivationReadiness{}, code, reason
	}
	if _, err := os.Stat(plan.CurrentBinaryPath); err != nil {
		return ActivationReadiness{}, ErrStagingIO, "current binary is not readable"
	}
	stagedHash, code, reason := HashFileWithLimit(plan.StagedBinaryPath, maxBytes)
	if code != "" {
		return ActivationReadiness{}, code, reason
	}
	if code, reason := VerifySHA256Equal(stagedHash.ActualSha256, plan.ActualSha256); code != "" {
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

func validateActivationPlan(plan ActivationPlan) (ErrorCode, string) {
	if plan.SchemaVersion != activationPlanSchemaVersion {
		return ErrActivationPlanWrite, "activation plan schema version mismatch"
	}
	if !validStagingID(plan.StagingID) || plan.ActivationPlanID != plan.StagingID {
		return ErrActivationPlanWrite, "activation plan identifiers do not match"
	}
	if strings.TrimSpace(plan.ServiceName) == "" || strings.TrimSpace(plan.CurrentBinaryPath) == "" || strings.TrimSpace(plan.StagedBinaryPath) == "" || strings.TrimSpace(plan.ActivationPlanPath) == "" {
		return ErrActivationPlanWrite, "activation plan local fields are incomplete"
	}
	root := filepath.Dir(plan.StagedBinaryPath)
	if filepath.Clean(plan.StagedBinaryPath) != filepath.Clean(stagedNameFor(root, plan.StagingID)) {
		return ErrActivationPlanWrite, "staged binary path does not match staging id"
	}
	if filepath.Clean(plan.ActivationPlanPath) != filepath.Clean(activationPlanNameFor(root, plan.StagingID)) {
		return ErrActivationPlanWrite, "activation plan path does not match staging id"
	}
	if sameCleanPath(plan.CurrentBinaryPath, plan.StagedBinaryPath) {
		return ErrActivationPlanWrite, "current and staged binary paths overlap"
	}
	if !isSHA256Hex(plan.ActualSha256) {
		return ErrHashMismatch, "activation plan sha256 evidence is invalid"
	}
	if strings.TrimSpace(plan.TargetVersion) == "" || strings.TrimSpace(plan.ActualSignerThumbprint) == "" || plan.SigningTier == "" {
		return ErrActivationPlanWrite, "activation plan evidence is incomplete"
	}
	return "", ""
}

func atomicWriteLocalSelfUpdateJSON(ctx context.Context, finalPath string, raw []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Dir(finalPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return activationPlanError{code: ErrActivationPlanWrite, reason: "create activation directory failed"}
	}
	tmp, err := os.OpenFile(finalPath+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return activationPlanError{code: ErrActivationPlanWrite, reason: "create activation temp failed"}
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		cleanup()
		return activationPlanError{code: ErrActivationPlanWrite, reason: "write activation temp failed"}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return activationPlanError{code: ErrActivationPlanWrite, reason: "fsync activation temp failed"}
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return activationPlanError{code: ErrActivationPlanWrite, reason: "close activation temp failed"}
	}
	if err := hardenActivationArtifact(tmpName); err != nil {
		cleanup()
		return activationPlanError{code: ErrActivationPlanWrite, reason: "harden activation temp failed"}
	}
	if err := os.Rename(tmpName, finalPath); err != nil {
		cleanup()
		return activationPlanError{code: ErrActivationPlanWrite, reason: "promote activation file failed"}
	}
	if err := hardenActivationArtifact(finalPath); err != nil {
		return activationPlanError{code: ErrActivationPlanWrite, reason: "harden activation file failed"}
	}
	return nil
}

type activationPlanError struct {
	code   ErrorCode
	reason string
}

func (e activationPlanError) Error() string { return e.reason }

func activationPlanFailure(err error) (ErrorCode, string) {
	var ape activationPlanError
	if errors.As(err, &ape) {
		return ape.code, ape.reason
	}
	if err != nil {
		return ErrActivationPlanWrite, "activation plan write failed"
	}
	return "", ""
}

func sameCleanPath(a, b string) bool {
	return filepath.Clean(strings.TrimSpace(a)) == filepath.Clean(strings.TrimSpace(b))
}

func stripUTF8BOM(raw []byte) []byte {
	if len(raw) >= 3 && raw[0] == 0xef && raw[1] == 0xbb && raw[2] == 0xbf {
		return raw[3:]
	}
	return raw
}
