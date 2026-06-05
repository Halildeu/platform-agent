package selfupdate

import "strings"

// PreflightInput is the NON-I/O policy input available BEFORE any download.
type PreflightInput struct {
	Platform       string // runtime.GOOS, e.g. "windows"
	CurrentVersion string
	MaxSeenVersion string
	Payload        UpdateAgentPayload
	URLPolicy      URLPolicy
	TierPolicy     TierPolicy
}

// PreflightEvidence is the non-secret evidence carried when preflight is clean
// and PR1 should proceed to download + stage. It is SEPARATE from StageResult
// (Codex 019e9912 #2) so that a StageResult always carries a valid, bounded
// stageStatus — a clean preflight is "policy says go", not a staging outcome.
type PreflightEvidence struct {
	OldVersion    string
	TargetVersion string
	SigningTier   SigningTier
}

// PreflightDecision is the outcome of EvaluatePreflight.
//   - Proceed=true: all non-I/O gates passed; Evidence is populated and PR1 may
//     download → hash → authenticode → signer-allowlist → credential-preflight
//     → stage. Result is the zero value in this case.
//   - Noop=true: target == current; Result is a NOOP_ALREADY_CURRENT.
//   - otherwise (both false): Result is a FAILED_STAGE with a bounded ErrorCode.
type PreflightDecision struct {
	Proceed  bool
	Noop     bool
	Result   StageResult
	Evidence PreflightEvidence
}

// EvaluatePreflight runs the fail-closed, NON-I/O policy gates in canonical
// order and returns the first refusal. It performs NO download, hashing, or
// signature verification (those are PR1, gated behind a clean preflight).
//
// Order is pinned by tests: platform → payload shape → tier → version → URL.
// Cheapest + most-restrictive gates first, so a refusal never requires
// touching the network, and a backend-supplied lab-tier "consent" is rejected
// before a URL is ever contacted.
func EvaluatePreflight(in PreflightInput) PreflightDecision {
	if !strings.EqualFold(strings.TrimSpace(in.Platform), "windows") {
		return failPreflight(ErrUnsupportedPlatform, "self-update is windows-only in v1")
	}
	if code, reason := in.Payload.ValidateShape(); code != "" {
		return failPreflight(code, reason)
	}
	if d := EvaluateTierPolicy(in.Payload.SigningTier, in.TierPolicy); !d.Allowed {
		return failPreflight(d.Code, d.Reason)
	}
	vd := EvaluateVersionPolicy(in.CurrentVersion, in.Payload.TargetVersion, in.MaxSeenVersion)
	if vd.Noop {
		return PreflightDecision{Noop: true, Result: Noop(in.CurrentVersion)}
	}
	if !vd.Allowed {
		return failPreflight(vd.Code, vd.Reason)
	}
	if _, code, reason := CheckURL(in.Payload.BinaryURL, in.URLPolicy); code != "" {
		return failPreflight(code, reason)
	}
	return PreflightDecision{
		Proceed: true,
		Evidence: PreflightEvidence{
			OldVersion:    in.CurrentVersion,
			TargetVersion: in.Payload.TargetVersion,
			SigningTier:   in.Payload.SigningTier,
		},
	}
}

func failPreflight(code ErrorCode, reason string) PreflightDecision {
	return PreflightDecision{Result: Failed(code, reason)}
}
