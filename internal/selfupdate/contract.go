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

// IsKnownStageStatus reports whether s is one of the bounded staging statuses.
// A StageResult returned to a caller must always carry a known status (Codex
// 019e9912 #2); the empty/zero value is NOT a valid staging outcome.
func IsKnownStageStatus(s StageStatus) bool {
	switch s {
	case StageReady, StageNoopCurrent, StageFailed:
		return true
	}
	return false
}

// ActivationStatus is the bounded outcome of the ACTIVATION phase, reported
// LATER via the new agent's heartbeat / a dedicated update-state evidence
// surface (PR3) — NOT via the staging command result. Defined here so the
// two-phase contract is one source of truth; PR0 wires no activation.
type ActivationStatus string

const (
	ActivationHelperStarted ActivationStatus = "ACTIVATION_HELPER_STARTED"
	ActivationActivated     ActivationStatus = "ACTIVATED"
	ActivationRolledBack    ActivationStatus = "ROLLED_BACK"
	ActivationPendingReboot ActivationStatus = "PENDING_REBOOT"
	ActivationFailed        ActivationStatus = "ACTIVATION_FAILED"
)

// IsKnownActivationStatus reports whether s is one of the bounded activation
// statuses. Activation evidence may be persisted locally after service
// mutation, so the zero value must fail closed rather than becoming an
// ambiguous status file.
func IsKnownActivationStatus(s ActivationStatus) bool {
	switch s {
	case ActivationHelperStarted, ActivationActivated, ActivationRolledBack, ActivationPendingReboot, ActivationFailed:
		return true
	}
	return false
}

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

// Failed builds a FAILED_STAGE result with a bounded, path-sanitized reason.
func Failed(code ErrorCode, reason string) StageResult {
	return StageResult{StageStatus: StageFailed, ErrorCode: code, Reason: sanitizeReason(reason)}
}

// Noop builds a NOOP_ALREADY_CURRENT result (target == current).
func Noop(current string) StageResult {
	return StageResult{StageStatus: StageNoopCurrent, OldVersion: current, TargetVersion: current, Reason: "already at target version"}
}

// maxReasonBytes bounds a wire reason.
const maxReasonBytes = 200

// sanitizeReason mechanically enforces the "no path / bounded reason" wire
// invariant (Codex 019e9912 #3): a reason that contains a filesystem-path-like
// token is replaced wholesale (so a future PR1/PR3 I/O error reason can never
// leak a local path), control characters are stripped, and the result is
// length-capped. PR0's own reasons are already static + safe; this guards the
// later phases that surface real I/O error text.
func sanitizeReason(s string) string {
	if looksPathish(s) {
		return "(reason redacted: contained a path-like token)"
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= maxReasonBytes {
			break
		}
	}
	return b.String()
}

// looksPathish reports whether s contains an obvious filesystem-path token
// (a backslash, a "<drive>:/" or "<drive>:\\" prefix, or a well-known
// per-machine/per-user directory name).
func looksPathish(s string) bool {
	if strings.Contains(s, `\`) {
		return true
	}
	low := strings.ToLower(s)
	for _, tok := range []string{"c:/", "/users/", "/home/", "programdata", "appdata"} {
		if strings.Contains(low, tok) {
			return true
		}
	}
	for i := 0; i+2 < len(s); i++ {
		c := s[i]
		isAlpha := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		if isAlpha && s[i+1] == ':' && (s[i+2] == '/' || s[i+2] == '\\') {
			return true
		}
	}
	return false
}
