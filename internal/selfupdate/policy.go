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

// PreflightDecision is the outcome of EvaluatePreflight.
//   - Proceed=true: all non-I/O gates passed; PR1 may download → hash →
//     authenticode → signer-allowlist → credential-preflight → stage.
//   - Noop=true: target == current; nothing to do.
//   - otherwise Result is a FAILED_STAGE with a bounded ErrorCode.
type PreflightDecision struct {
	Proceed bool
	Noop    bool
	Result  StageResult
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
		Result: StageResult{
			TargetVersion: in.Payload.TargetVersion,
			OldVersion:    in.CurrentVersion,
			SigningTier:   in.Payload.SigningTier,
			Reason:        "preflight policy clean; staging proceeds",
		},
	}
}

func failPreflight(code ErrorCode, reason string) PreflightDecision {
	return PreflightDecision{Result: Failed(code, reason)}
}
