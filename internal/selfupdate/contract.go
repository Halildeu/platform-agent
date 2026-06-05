package selfupdate

import "strings"

// SigningTier is the signature-trust tier a release was produced under.
// Production self-update accepts TierTrusted ONLY; TierLabOnlyEvidence is
// refused for unattended self-update unless a LOCAL opt-in is present (see
// EvaluateTierPolicy). The wire value is bounded + stable.
type SigningTier string

const (
	TierTrusted         SigningTier = "TRUSTED"
	TierLabOnlyEvidence SigningTier = "LAB_ONLY_EVIDENCE"
)

// IsKnownTier reports whether t is a recognized tier (defense-in-depth: an
// unknown tier is treated as untrusted by policy).
func IsKnownTier(t SigningTier) bool {
	return t == TierTrusted || t == TierLabOnlyEvidence
}

// UpdateAgentPayload is the UPDATE_AGENT command payload the agent receives.
// The backend resolves it from a TRUSTED RELEASE CATALOG (admin selects a
// releaseId/channel/ring + targetVersion; the backend fills the URL + claims)
// — the agent never accepts a freeform admin URL (Codex 019e94fd).
//
// CRITICAL trust note: ClaimedSha256 / ClaimedSignerThumbprint /
// ClaimedAcceptLabOnly are AUDIT EVIDENCE ONLY. They are NOT authority:
//   - the agent recomputes the SHA256 of the staged bytes and (independently)
//     verifies the Authenticode signer against its LOCAL allowlist;
//   - ClaimedAcceptLabOnly is IGNORED by tier policy — lab-tier consent can
//     only come from a LOCAL opt-in, never from the backend payload.
//
// A compromised backend that ships a self-consistent malicious payload still
// fails because the malicious signer is not in the agent's local allowlist.
type UpdateAgentPayload struct {
	ReleaseID               string      `json:"releaseId"`
	Channel                 string      `json:"channel,omitempty"`
	Ring                    string      `json:"ring,omitempty"`
	TargetVersion           string      `json:"targetVersion"`
	BinaryURL               string      `json:"binaryUrl"`
	ClaimedSha256           string      `json:"claimedSha256"`
	ClaimedSignerThumbprint string      `json:"claimedSignerThumbprint"`
	SigningTier             SigningTier `json:"signingTier"`
	MaxBytes                int64       `json:"maxBytes,omitempty"`
	// ClaimedAcceptLabOnly is accepted on the wire for AUDIT but ignored as
	// authority — see the trust note above and EvaluateTierPolicy.
	ClaimedAcceptLabOnly bool `json:"acceptLabOnlySigning,omitempty"`
}

// ValidateShape does cheap, fail-closed structural validation of a payload
// BEFORE any version/URL/signature work. It checks only presence + bounded
// enum membership; deep policy lives in the Evaluate* functions. Returns an
// empty ErrorCode ("") when the shape is acceptable.
func (p UpdateAgentPayload) ValidateShape() (ErrorCode, string) {
	if strings.TrimSpace(p.TargetVersion) == "" {
		return ErrVersionUnparseable, "targetVersion is required"
	}
	if strings.TrimSpace(p.BinaryURL) == "" {
		return ErrURLRejected, "binaryUrl is required"
	}
	if strings.TrimSpace(p.ClaimedSha256) == "" {
		return ErrHashMismatch, "claimedSha256 is required"
	}
	if !IsKnownTier(p.SigningTier) {
		// Unknown tier => cannot be trusted; surface as a lab-tier refusal
		// (the most restrictive non-trusted classification).
		return ErrLabTierRefused, "unknown signingTier"
	}
	return "", ""
}

// StageStatus is the bounded outcome of the STAGING phase — the ONLY phase a
// command Execute() can observe. Activation-phase results live in a SEPARATE
// ActivationStatus enum (Codex 019e94fd must-fix #1): an Execute() result can
// never carry PENDING_REBOOT / ACTIVATED / ROLLED_BACK, because those are
// only known AFTER the staging command's result POST has already succeeded.
type StageStatus string

const (
	StageReady       StageStatus = "STAGED_ACTIVATION_READY"
	StageNoopCurrent StageStatus = "NOOP_ALREADY_CURRENT"
	StageFailed      StageStatus = "FAILED_STAGE"
)

// ActivationStatus is the bounded outcome of the ACTIVATION phase, reported
// LATER via the new agent's heartbeat / a dedicated update-state evidence
// surface (PR3) — NOT via the staging command result. Defined here so the
// two-phase contract is one source of truth; PR0 wires no activation.
type ActivationStatus string

const (
	ActivationActivated     ActivationStatus = "ACTIVATED"
	ActivationRolledBack    ActivationStatus = "ROLLED_BACK"
	ActivationPendingReboot ActivationStatus = "PENDING_REBOOT"
	ActivationFailed        ActivationStatus = "ACTIVATION_FAILED"
)

// StageResult is the structured result a STAGING Execute() returns under
// `details.update`. It carries opaque identifiers + bounded evidence — never
// a filesystem path (Codex 019e94fd must-fix #5): the backend has no need for
// the local staging path, which stays in local logs only.
type StageResult struct {
	StageStatus StageStatus `json:"stageStatus"`
	ErrorCode   ErrorCode   `json:"errorCode,omitempty"`
	// StagingID / ActivationPlanID are opaque correlation handles (e.g. the
	// requestId), NOT paths.
	StagingID        string `json:"stagingId,omitempty"`
	ActivationPlanID string `json:"activationPlanId,omitempty"`
	OldVersion       string `json:"oldVersion,omitempty"`
	TargetVersion    string `json:"targetVersion,omitempty"`
	// Actual* are the agent-INDEPENDENTLY-derived values (recomputed hash +
	// verified signer), the authoritative counterpart to the payload's
	// Claimed* audit fields.
	ActualSha256           string      `json:"actualSha256,omitempty"`
	ActualSignerThumbprint string      `json:"actualSignerThumbprint,omitempty"`
	SigningTier            SigningTier `json:"signingTier,omitempty"`
	// Reason is a bounded, static-phrasing explanation (no PII, no paths).
	Reason string `json:"reason,omitempty"`
}

// Failed builds a FAILED_STAGE result with a bounded reason.
func Failed(code ErrorCode, reason string) StageResult {
	return StageResult{StageStatus: StageFailed, ErrorCode: code, Reason: reason}
}

// Noop builds a NOOP_ALREADY_CURRENT result (target == current).
func Noop(current string) StageResult {
	return StageResult{StageStatus: StageNoopCurrent, OldVersion: current, TargetVersion: current, Reason: "already at target version"}
}
