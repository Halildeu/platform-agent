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
)

const (
	permitDomain = "RemoteBridgeOperationPermit:v1"
	// PermitAlg is the single pinned permit signature algorithm (config-drift guard) — it MUST equal the
	// broker's RemoteBridgePermitSigner.PERMIT_ALG. "SHA256withECDSA" = SHA-256 digest + a DER-encoded ECDSA
	// signature over the P-256 curve, which crypto/ecdsa.VerifyASN1 consumes directly.
	PermitAlg = "SHA256withECDSA"
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

// IsFresh reports issuedAt <= now < expiresAt with malformed-window guards: both bounds must be positive
// (rejects zero/negative epochs) and issuedAt < expiresAt (rejects a degenerate/inverted window). This is
// defense-in-depth beyond the broker's isFresh — never weaker; a real permit's epoch-millis are always > 0.
func (p OperationPermit) IsFresh(nowEpochMillis int64) bool {
	return p.IssuedAtEpochMillis > 0 && p.ExpiresAtEpochMillis > 0 &&
		p.IssuedAtEpochMillis < p.ExpiresAtEpochMillis &&
		nowEpochMillis >= p.IssuedAtEpochMillis && nowEpochMillis < p.ExpiresAtEpochMillis
}

// Verifier holds ONLY the broker's PUBLIC key + the expected kid — it verifies a permit but never mints one.
type Verifier struct {
	pub         *ecdsa.PublicKey
	expectedKid string
}

// NewVerifier parses the broker's X.509/SPKI DER public key (base64) and pins the expected kid. Fail-closed:
// a blank kid, an unparseable key, or a non-P-256 key is an error — no insecure verifier is constructed.
func NewVerifier(brokerPublicKeyB64, expectedKid string) (*Verifier, error) {
	if expectedKid == "" {
		return nil, errors.New("operation: expectedKid must not be blank")
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
	return &Verifier{pub: pub, expectedKid: expectedKid}, nil
}

// Verify reports whether the permit is from the expected key + pinned alg, fresh at now, and its signature
// verifies over canonicalPayload(). Fail-closed: ANY mismatch / tamper / expiry / crypto error → false.
// (Public-key verification is not secret-dependent, so no constant-time comparison is needed.)
func (v *Verifier) Verify(p OperationPermit, nowEpochMillis int64) bool {
	if v == nil || v.pub == nil {
		return false
	}
	if p.Kid != v.expectedKid || p.Alg != PermitAlg || p.SignatureB64 == "" {
		return false
	}
	if !p.IsFresh(nowEpochMillis) {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(p.SignatureB64)
	if err != nil || len(sig) == 0 {
		return false
	}
	digest := sha256.Sum256(p.canonicalPayload())
	return ecdsa.VerifyASN1(v.pub, digest[:], sig)
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
