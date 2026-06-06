package selfupdate

import (
	"encoding/json"
	"os"
)

// WriteActivationOutcome atomically persists path-free local activation
// evidence in the protected staging directory. This is a local smoke/support
// artifact only: backend acceptance still requires a post-activation heartbeat
// or dedicated update-state record proving AgentVersion == targetVersion.
func WriteActivationOutcome(paths StagingPaths, outcome ActivationOutcome) (ErrorCode, string) {
	if code, reason := validateStagingPaths(paths); code != "" {
		return code, reason
	}
	outcome = sanitizedActivationOutcome(outcome)
	if !IsKnownActivationStatus(outcome.Status) {
		return ErrActivationPlanWrite, "activation outcome status is invalid"
	}
	raw, err := json.MarshalIndent(outcome, "", "  ")
	if err != nil {
		return ErrActivationPlanWrite, "marshal activation outcome failed"
	}
	raw = append(raw, '\n')
	path := activationOutcomePath(paths)
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrActivationPlanWrite, "create activation outcome temp failed"
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		cleanup()
		return ErrActivationPlanWrite, "write activation outcome temp failed"
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return ErrActivationPlanWrite, "fsync activation outcome temp failed"
	}
	if err := f.Close(); err != nil {
		cleanup()
		return ErrActivationPlanWrite, "close activation outcome temp failed"
	}
	if err := stagedFileHardener(tmp); err != nil {
		cleanup()
		return ErrActivationPlanWrite, "harden activation outcome temp failed"
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return ErrActivationPlanWrite, "promote activation outcome failed"
	}
	if err := stagedFileHardener(path); err != nil {
		return ErrActivationPlanWrite, "harden activation outcome final failed"
	}
	return "", ""
}

// LoadActivationOutcome reads the local activation evidence file written by
// WriteActivationOutcome. The returned outcome is sanitized again before it is
// shown by CLI helpers, so a manually-edited file cannot leak path-like reason
// text into smoke evidence.
func LoadActivationOutcome(paths StagingPaths) (ActivationOutcome, ErrorCode, string) {
	if code, reason := validateStagingPaths(paths); code != "" {
		return ActivationOutcome{}, code, reason
	}
	raw, err := os.ReadFile(activationOutcomePath(paths))
	if err != nil {
		return ActivationOutcome{}, ErrStagingIO, "read activation outcome failed"
	}
	var outcome ActivationOutcome
	if err := json.Unmarshal(raw, &outcome); err != nil {
		return ActivationOutcome{}, ErrActivationPlanWrite, "decode activation outcome failed"
	}
	outcome = sanitizedActivationOutcome(outcome)
	if !IsKnownActivationStatus(outcome.Status) {
		return ActivationOutcome{}, ErrActivationPlanWrite, "activation outcome status is invalid"
	}
	if outcome.ActivationPlanID != "" && outcome.ActivationPlanID != paths.StagingID {
		return ActivationOutcome{}, ErrActivationPlanWrite, "activation outcome identity mismatch"
	}
	return outcome, "", ""
}

func sanitizedActivationOutcome(outcome ActivationOutcome) ActivationOutcome {
	outcome.Reason = sanitizeReason(outcome.Reason)
	return outcome
}
