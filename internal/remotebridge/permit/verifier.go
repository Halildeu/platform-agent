package permit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
)

// Alg is the only accepted signature algorithm (pinned, config-drift guard —
// matches RemoteBridgePermitSigner.PERMIT_ALG). The Java JCA name maps to
// ECDSA over P-256 with SHA-256 and an ASN.1 DER-encoded signature, which is
// exactly what ecdsa.VerifyASN1 checks.
const Alg = "SHA256withECDSA"

// permitVersionPinned is the only permit schema version this agent accepts.
const permitVersionPinned = 1

// commandHashPattern is the CanonicalCommand.hash() shape: SHA-256 as
// 64 lowercase hex chars. CONSTRAINED_PTY permits MUST carry it; VIEW_ONLY
// permits MUST NOT carry any hash.
var commandHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Verifier validates broker-signed OperationPermits on the agent. It is the
// agent-authoritative DENY gate: the broker decides ALLOW, but this verifier
// can always refuse (fail-closed on ANY mismatch). Beyond the Java reference
// verifier (kid + pinned alg + freshness + signature) it also re-enforces the
// signer-side issuance invariants — pilot-capability-only,
// capability↔commandHash consistency, permitVersion pin, seq ≥ 0 — and binds
// the permit to THIS device (expectedDeviceID, Codex T-3 revision #1), so a
// permit minted for another endpoint never verifies here even with a valid
// broker signature.
type Verifier struct {
	pub              *ecdsa.PublicKey
	expectedKid      string
	expectedDeviceID string
}

// NewVerifier builds a Verifier. The key MUST be EC P-256 (the pinned curve
// of the permit-signing boundary); kid and deviceID must be non-blank — a
// blank device binding would silently disable the device check.
func NewVerifier(pub *ecdsa.PublicKey, expectedKid, expectedDeviceID string) (*Verifier, error) {
	if pub == nil || pub.Curve != elliptic.P256() || pub.X == nil {
		return nil, errors.New("permit verify key must be EC P-256")
	}
	if strings.TrimSpace(expectedKid) == "" {
		return nil, errors.New("expectedKid must not be blank")
	}
	if strings.TrimSpace(expectedDeviceID) == "" {
		return nil, errors.New("expectedDeviceID must not be blank")
	}
	return &Verifier{pub: pub, expectedKid: expectedKid, expectedDeviceID: expectedDeviceID}, nil
}

// Verify reports whether the permit is acceptable at nowEpochMillis.
// Fail-closed: any nil/mismatch/tamper/expiry/decoding/crypto error → false.
func (v *Verifier) Verify(p *Permit, nowEpochMillis int64) bool {
	if p == nil {
		return false
	}
	if p.Kid != v.expectedKid {
		return false
	}
	if p.Alg != Alg {
		return false
	}
	if strings.TrimSpace(p.SignatureB64) == "" {
		return false
	}
	if !p.IsFresh(nowEpochMillis) {
		return false
	}
	if p.PermitVersion != permitVersionPinned {
		return false
	}
	if p.Seq < 0 {
		return false
	}
	if p.DeviceID != v.expectedDeviceID {
		return false
	}
	switch p.Capability {
	case CapabilityConstrainedPTY:
		if !commandHashPattern.MatchString(p.CommandHash) {
			return false
		}
	case CapabilityViewOnly:
		if p.CommandHash != "" {
			return false
		}
	default:
		// Non-pilot or unknown capability — default-deny (ADR-0034 D8).
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(p.SignatureB64)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(p.CanonicalPayload())
	return ecdsa.VerifyASN1(v.pub, digest[:], sig)
}
