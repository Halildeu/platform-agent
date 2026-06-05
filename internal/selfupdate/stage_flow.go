package selfupdate

import "io"

// StageCandidateInput is the PR1 local staging orchestration input. The caller
// supplies Candidate bytes and platform-extracted AuthenticodeEvidence; this
// helper performs no network I/O, does not execute commands, and does not
// activate or replace the running binary.
type StageCandidateInput struct {
	Preflight         PreflightInput
	StagingRoot       string
	StagingID         string
	CurrentBinaryPath string
	ServiceName       string
	Candidate         io.Reader
	Authenticode      AuthenticodeEvidence
	SignerAllowlist   SignerAllowlist
}

// StageCandidateFromReader runs the PR1 staging sequence after an already
// available candidate stream is supplied:
//
//	preflight policy -> protected staging dir -> atomic write/hash/rehash ->
//	authenticode policy -> local signer allowlist -> StageResult + local plan
//
// Failures return a bounded FAILED_STAGE result. A candidate that passes the
// hash gate but fails signature/signer policy is removed from staging before
// returning, so rejected bytes are not left as an activation candidate.
func StageCandidateFromReader(in StageCandidateInput) (StageResult, ActivationPlan) {
	decision := EvaluatePreflight(in.Preflight)
	if decision.Noop || !decision.Proceed {
		return decision.Result, ActivationPlan{}
	}
	if in.Candidate == nil {
		return Failed(ErrDownloadFailed, "candidate binary stream is required"), ActivationPlan{}
	}

	paths, code, reason := protectedStagingDirPreparer(in.StagingRoot, in.StagingID)
	if code != "" {
		return Failed(code, reason), ActivationPlan{}
	}

	hash, code, reason := WriteStagedBinaryFromReader(paths, in.Candidate, in.Preflight.Payload.ClaimedSha256, in.Preflight.Payload.MaxBytes)
	if code != "" {
		return Failed(code, reason), ActivationPlan{}
	}

	if d := EvaluateAuthenticodePolicy(in.Authenticode, in.Preflight.Payload.SigningTier); !d.Allowed {
		removeStagedArtifacts(paths)
		return Failed(d.Code, d.Reason), ActivationPlan{}
	}
	if d := EvaluateSignerPolicy(in.Authenticode.SignerThumbprint, in.SignerAllowlist); !d.Allowed {
		removeStagedArtifacts(paths)
		return Failed(d.Code, d.Reason), ActivationPlan{}
	}

	ready, code, reason := BuildReadyStageResult(paths, decision.Evidence, hash.ActualSha256, in.Authenticode.SignerThumbprint)
	if code != "" {
		removeStagedArtifacts(paths)
		return Failed(code, reason), ActivationPlan{}
	}
	plan, code, reason := BuildActivationPlan(paths, in.CurrentBinaryPath, in.ServiceName, ready)
	if code != "" {
		removeStagedArtifacts(paths)
		return Failed(code, reason), ActivationPlan{}
	}
	return ready, plan
}
