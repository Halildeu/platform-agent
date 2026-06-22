package operation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	permitDomain = "RemoteBridgeOperationPermit:v1"
	// PermitAlg is the single pinned permit signature algorithm (config-drift guard) — it MUST equal the
	// broker's RemoteBridgePermitSigner.PERMIT_ALG. "SHA256withECDSA" = SHA-256 digest + a DER-encoded ECDSA
	// signature over the P-256 curve, which crypto/ecdsa.VerifyASN1 consumes directly.
	PermitAlg = "SHA256withECDSA"
	// permitVersionPinned is the only permit schema version this agent accepts
	// (matches the broker's OperationPermit.PERMIT_VERSION). A future schema
	// bump must be an explicit, reviewed change here — never a silently-accepted
	// version. (Restored from the device-bound permit.Verifier reference; the
	// lean operation.Verifier had dropped it.)
	permitVersionPinned int32 = 1
	// MaxPermitValidityMillis caps one broker-issued operation permit at 15 minutes. The broker should issue
	// much shorter permits for attended sessions; this agent-side ceiling makes TTL a local fail-closed guard
	// even if a broker bug signs an over-broad window.
	MaxPermitValidityMillis int64 = 15 * 60 * 1000
	// PermitClockSkewMillis tolerates a small broker/endpoint wall-clock skew on
	// the not-before side of a freshly minted permit. This matches common
	// signed-token validation practice without extending the permit's expiry
	// window: replay lifetime remains bounded by expiresAtEpochMillis.
	PermitClockSkewMillis int64 = 2 * 60 * 1000
)

// OperationPermit mirrors the broker's signed OperationPermit (broker-private / agent-public). The agent only
// ever VERIFIES one — it can never mint one (it holds no signing key). canonicalPayload() is byte-exact with
// the broker so the broker's signature verifies here.
type OperationPermit struct {
	Alg                  string
	Kid                  string
	PermitVersion        int32
	PolicyVersion        string
	DecisionID           string
	SessionID            string
	OperationID          string
	DeviceID             string
	OperatorSubject      string
	Capability           string // the capability enum NAME, e.g. "CONSTRAINED_PTY"
	CommandHash          string
	IssuedAtEpochMillis  int64
	ExpiresAtEpochMillis int64
	Seq                  int64
	SignatureB64         string // broker signature over canonicalPayload(); itself NOT part of the signed bytes
}

// canonicalPayload is the stable, length-prefixed byte sequence the broker SIGNS — byte-exact with the
// broker's OperationPermit.canonicalPayload() (Java DataOutputStream: writeField = 4-byte-BE UTF-8 length +
// bytes; writeInt = 4-byte BE; writeLong = 8-byte BE). Independent of the protobuf wire encoding.
func (p OperationPermit) canonicalPayload() []byte {
	var b bytes.Buffer
	writeField(&b, permitDomain)
	writeField(&b, p.Alg)
	writeField(&b, p.Kid)
	writeInt32(&b, p.PermitVersion)
	writeField(&b, p.PolicyVersion)
	writeField(&b, p.DecisionID)
	writeField(&b, p.SessionID)
	writeField(&b, p.OperationID)
	writeField(&b, p.DeviceID)
	writeField(&b, p.OperatorSubject)
	writeField(&b, p.Capability)
	writeField(&b, p.CommandHash)
	writeInt64(&b, p.IssuedAtEpochMillis)
	writeInt64(&b, p.ExpiresAtEpochMillis)
	writeInt64(&b, p.Seq)
	return b.Bytes()
}

// IsFresh reports issuedAt-skew <= now < expiresAt with malformed-window guards: both bounds must be positive
// (rejects zero/negative epochs) and issuedAt < expiresAt (rejects a degenerate/inverted window). The skew is
// intentionally not applied to expiresAt, so a clock-lag tolerance cannot become a replay extension.
func (p OperationPermit) IsFresh(nowEpochMillis int64) bool {
	return p.IssuedAtEpochMillis > 0 && p.ExpiresAtEpochMillis > 0 &&
		p.IssuedAtEpochMillis < p.ExpiresAtEpochMillis &&
		p.ExpiresAtEpochMillis-p.IssuedAtEpochMillis <= MaxPermitValidityMillis &&
		nowEpochMillis+PermitClockSkewMillis >= p.IssuedAtEpochMillis &&
		nowEpochMillis < p.ExpiresAtEpochMillis
}

// Verifier holds ONLY the broker's PUBLIC key + the expected kid — it verifies a permit but never mints one.
type Verifier struct {
	pub         *ecdsa.PublicKey
	expectedKid string
	// expectedDeviceID binds every accepted permit to THIS agent's enrolled
	// identity (the signed DeviceID field): a permit minted for ANOTHER device
	// never verifies here even with a valid broker signature. Defense-in-depth —
	// the dispatch harness also refuses a wrong-device permit dynamically (the
	// authoritative, re-enrollment-aware check); this is the gate/executor-path
	// backstop so the verifier is self-protecting regardless of caller. Set at
	// construction (the attended pilot has no mid-session re-enrollment); a stale
	// value fails CLOSED, never open.
	expectedDeviceID string
}

// NewVerifier parses the broker's X.509/SPKI DER public key (base64) and pins the expected kid + device.
// Fail-closed: a blank kid, a blank deviceID, an unparseable key, or a non-P-256 key is an error — no insecure
// verifier is constructed (a blank device binding would silently disable the device check).
func NewVerifier(brokerPublicKeyB64, expectedKid, expectedDeviceID string) (*Verifier, error) {
	if strings.TrimSpace(expectedKid) == "" {
		return nil, errors.New("operation: expectedKid must not be blank")
	}
	if strings.TrimSpace(expectedDeviceID) == "" {
		return nil, errors.New("operation: expectedDeviceID must not be blank")
	}
	der, err := base64.StdEncoding.DecodeString(brokerPublicKeyB64)
	if err != nil {
		return nil, errors.New("operation: broker public key is not valid base64")
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("operation: broker public key is not a valid SPKI key")
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("operation: broker public key must be EC P-256")
	}
	return &Verifier{pub: pub, expectedKid: expectedKid, expectedDeviceID: expectedDeviceID}, nil
}

// Verify reports whether the permit is from the expected key + pinned alg, fresh at now, and its signature
// verifies over canonicalPayload(). Fail-closed: ANY mismatch / tamper / expiry / crypto error → false.
// (Public-key verification is not secret-dependent, so no constant-time comparison is needed.)
func (v *Verifier) Verify(p OperationPermit, nowEpochMillis int64) bool {
	ok, _ := v.VerifyWithReason(p, nowEpochMillis)
	return ok
}

// VerifyWithReason is the diagnostic form of Verify. It preserves the same fail-closed security decision but
// returns a bounded, non-secret reason code for broker/operator audit when a live endpoint rejects a permit.
func (v *Verifier) VerifyWithReason(p OperationPermit, nowEpochMillis int64) (bool, string) {
	if v == nil || v.pub == nil {
		return false, ReasonPermitVerifierUnavailable
	}
	if p.Kid != v.expectedKid {
		return false, ReasonPermitKidMismatch
	}
	if p.Alg != PermitAlg {
		return false, ReasonPermitAlgMismatch
	}
	if p.SignatureB64 == "" {
		return false, ReasonPermitSignatureMissing
	}
	// Schema-version pin + device binding (both signed CanonicalPayload fields;
	// restored defense-in-depth the lean verifier had dropped vs permit.Verifier).
	if p.PermitVersion != permitVersionPinned {
		return false, ReasonPermitVersionMismatch
	}
	if p.DeviceID != v.expectedDeviceID {
		return false, ReasonPermitDeviceMismatch
	}
	if !p.IsFresh(nowEpochMillis) {
		return false, ReasonPermitNotFresh
	}
	sig, err := base64.StdEncoding.DecodeString(p.SignatureB64)
	if err != nil || len(sig) == 0 {
		return false, ReasonPermitSignatureDecode
	}
	digest := sha256.Sum256(p.canonicalPayload())
	if !ecdsa.VerifyASN1(v.pub, digest[:], sig) {
		return false, ReasonPermitSignatureInvalid
	}
	return true, ""
}

// --- byte-exact serialization helpers (mirror Java DataOutputStream); shared with command.go ---

// writeField writes a 4-byte big-endian UTF-8 length prefix + the UTF-8 bytes (Java writeInt + write).
func writeField(b *bytes.Buffer, s string) {
	bs := []byte(s)
	writeInt32(b, int32(len(bs)))
	b.Write(bs)
}

func writeInt32(b *bytes.Buffer, v int32) {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], uint32(v))
	b.Write(x[:])
}

func writeInt64(b *bytes.Buffer, v int64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], uint64(v))
	b.Write(x[:])
}
