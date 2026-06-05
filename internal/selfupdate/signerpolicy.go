package selfupdate

import "strings"

// SignerAllowlist is the agent's LOCAL trust anchor (install-time secure
// config) and the ONLY authority for "may I run this binary". The
// backend-claimed thumbprint is never consulted as authority; a compromised
// backend cannot widen this set. Allowlist ROTATION is a separate, locally
// controlled flow (see the threat model) — the payload can never add a
// thumbprint.
type SignerAllowlist struct {
	Thumbprints []string // any case; ':'/space separators tolerated
}

// normalizeThumbprint upper-cases and strips ':' and whitespace so
// "ab:cd ef" and "ABCDEF" compare equal.
func normalizeThumbprint(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// Contains reports whether thumbprint (any case/format) is allowlisted.
func (a SignerAllowlist) Contains(thumbprint string) bool {
	want := normalizeThumbprint(thumbprint)
	if want == "" {
		return false
	}
	for _, t := range a.Thumbprints {
		if normalizeThumbprint(t) == want {
			return true
		}
	}
	return false
}

// SignerDecision is the outcome of the LOCAL signer-allowlist authority gate.
type SignerDecision struct {
	Allowed bool
	Code    ErrorCode
	Reason  string
}

// EvaluateSignerPolicy is the AUTHORITY gate: the ACTUAL verified signer
// thumbprint (extracted from the staged binary by PR1) must be present in the
// agent's LOCAL allowlist. The payload's claimedSignerThumbprint is NOT an
// input here.
func EvaluateSignerPolicy(actualThumbprint string, allow SignerAllowlist) SignerDecision {
	if strings.TrimSpace(actualThumbprint) == "" {
		return SignerDecision{Code: ErrSignerNotAllowed, Reason: "no verified signer thumbprint"}
	}
	if !allow.Contains(actualThumbprint) {
		return SignerDecision{Code: ErrSignerNotAllowed, Reason: "verified signer not in local allowlist"}
	}
	return SignerDecision{Allowed: true, Reason: "verified signer in local allowlist"}
}

// TierPolicy holds the LOCAL self-update tier configuration. AllowLabOnly is a
// LOCAL opt-in (install-time config / test build) — NEVER derived from the
// backend payload's acceptLabOnlySigning.
type TierPolicy struct {
	AllowLabOnly bool
	DomainJoined bool
}

// TierDecision is the outcome of EvaluateTierPolicy.
type TierDecision struct {
	Allowed bool
	Code    ErrorCode
	Reason  string
}

// EvaluateTierPolicy decides whether a release of the given tier may be
// self-update-activated. TRUSTED is always acceptable. LAB_ONLY_EVIDENCE is
// refused for unattended self-update unless a LOCAL opt-in is present AND the
// host is non-domain-joined (mirroring the install-time guardrail, but
// without honoring any backend-supplied consent). Unknown tiers are treated
// as untrusted.
func EvaluateTierPolicy(tier SigningTier, pol TierPolicy) TierDecision {
	switch tier {
	case TierTrusted:
		return TierDecision{Allowed: true, Reason: "trusted tier"}
	case TierLabOnlyEvidence:
		if pol.AllowLabOnly && !pol.DomainJoined {
			return TierDecision{Allowed: true, Reason: "lab tier permitted by local opt-in on non-domain-joined host"}
		}
		return TierDecision{Code: ErrLabTierRefused, Reason: "lab-only tier refused for unattended self-update"}
	default:
		return TierDecision{Code: ErrLabTierRefused, Reason: "unknown tier treated as untrusted"}
	}
}

// AuthenticodeEvidence is the platform-extracted signature facts the policy
// consumes. PR1 populates this from the real Windows Authenticode APIs; PR0
// only DECIDES on it (and tests the decision).
type AuthenticodeEvidence struct {
	ChainValid        bool   // chain validates to a trusted root (per tier)
	HasCodeSigningEKU bool   // leaf carries the Code Signing EKU
	SignerThumbprint  string // leaf cert thumbprint
	Timestamped       bool   // a trusted countersignature timestamp is present
	SigningTimeValid  bool   // cert was valid at the timestamped signing time
	CurrentTimeValid  bool   // cert is valid at the current wall-clock time
}

// AuthenticodeDecision is the outcome of EvaluateAuthenticodePolicy.
type AuthenticodeDecision struct {
	Allowed bool
	Code    ErrorCode
	Reason  string
}

// EvaluateAuthenticodePolicy decides whether the staged binary's Authenticode
// evidence is acceptable for the given tier (Codex 019e94fd checklist #7).
//
// Timestamp semantics: a TIMESTAMPED signature only requires the cert to have
// been valid AT SIGNING TIME (so a correctly-signed older release stays
// acceptable after the signing cert expires); an UNTIMESTAMPED signature
// requires the cert to be valid at the CURRENT time. For TierTrusted the
// chain must validate. In all tiers the leaf must carry the Code Signing EKU.
//
// This is NOT the authority gate — it validates the signature shape/validity.
// The signer-allowlist authority (EvaluateSignerPolicy) is separate; BOTH
// must pass before activation.
func EvaluateAuthenticodePolicy(ev AuthenticodeEvidence, tier SigningTier) AuthenticodeDecision {
	if tier == TierTrusted && !ev.ChainValid {
		return AuthenticodeDecision{Code: ErrSignatureInvalid, Reason: "trusted tier requires a valid certificate chain"}
	}
	if !ev.HasCodeSigningEKU {
		return AuthenticodeDecision{Code: ErrSignatureInvalid, Reason: "leaf certificate lacks the Code Signing EKU"}
	}
	timeOK := ev.CurrentTimeValid
	if ev.Timestamped {
		timeOK = ev.SigningTimeValid
	}
	if !timeOK {
		return AuthenticodeDecision{Code: ErrSignatureInvalid, Reason: "certificate validity does not cover the signing/current time"}
	}
	return AuthenticodeDecision{Allowed: true, Reason: "authenticode evidence acceptable for tier"}
}
