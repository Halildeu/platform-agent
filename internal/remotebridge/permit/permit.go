// Package permit re-implements the Faz 22.6 T-1b OperationPermit verifier on
// the agent side (T-3). The broker (platform-backend
// endpoint-admin-service, com.example.endpointadmin.remoteaccess.bridge)
// signs a short-lived permit for ONE operation with its PRIVATE ECDSA P-256
// key; the agent holds ONLY the broker's public key — it can verify a permit
// but never mint one, so a compromised endpoint cannot forge local
// authorization (ADR-0038 §5, Codex 019eb9fb).
//
// The signature covers CanonicalPayload(), a stable length-prefixed byte
// sequence that is independent of BOTH the protobuf wire encoding and any
// language's string formatting. The byte layout below MUST stay byte-equal
// to the Java reference (OperationPermit.canonicalPayload()); the
// cross-language test vector in testdata pins that equality.
package permit

import (
	"bytes"
	"encoding/binary"
)

// Domain is the canonical-payload domain separation tag. It MUST match the
// Java side (OperationPermit.DOMAIN) byte-for-byte.
const Domain = "RemoteBridgeOperationPermit:v1"

// Pilot capability names (RemoteSessionCapability.name() on the Java side).
// ADR-0034 D8: the interactive pilot is limited to these two; everything
// else is refused by the verifier (default-deny).
const (
	CapabilityViewOnly       = "VIEW_ONLY"
	CapabilityConstrainedPTY = "CONSTRAINED_PTY"
	// MaxPermitValidityMillis caps one broker-issued operation permit at 15 minutes.
	MaxPermitValidityMillis int64 = 15 * 60 * 1000
	// PermitClockSkewMillis is bounded wall-clock leeway for broker/endpoint drift.
	PermitClockSkewMillis int64 = 2 * 60 * 1000
)

// Permit mirrors the 15-field OperationPermit record (wire-contract field
// numbers 1-15). Capability carries the Java enum NAME (e.g. "VIEW_ONLY"),
// exactly what CanonicalPayload signs. SignatureB64 (field 15) is NOT part
// of the signed payload.
type Permit struct {
	Alg                  string
	Kid                  string
	PermitVersion        int32
	PolicyVersion        string
	DecisionID           string
	SessionID            string
	OperationID          string
	DeviceID             string
	OperatorSubject      string
	Capability           string
	CommandHash          string
	IssuedAtEpochMillis  int64
	ExpiresAtEpochMillis int64
	Seq                  int64
	SignatureB64         string
}

// IsFresh reports whether now is within issuedAt-skew <= now < expiresAt+skew,
// while still rejecting malformed windows and permits whose signed validity
// exceeds MaxPermitValidityMillis.
func (p *Permit) IsFresh(nowEpochMillis int64) bool {
	return p != nil &&
		p.IssuedAtEpochMillis > 0 &&
		p.ExpiresAtEpochMillis > 0 &&
		p.IssuedAtEpochMillis < p.ExpiresAtEpochMillis &&
		p.ExpiresAtEpochMillis-p.IssuedAtEpochMillis <= MaxPermitValidityMillis &&
		nowEpochMillis+PermitClockSkewMillis >= p.IssuedAtEpochMillis &&
		nowEpochMillis < p.ExpiresAtEpochMillis+PermitClockSkewMillis
}

// CanonicalPayload returns the exact byte sequence the broker signs: the
// domain tag and every security field (1-14), length-prefixed
// (delimiter-safe), excluding the signature. Strings are written as 4-byte
// big-endian length + UTF-8 bytes; permitVersion is a 4-byte big-endian
// int32; issuedAt/expiresAt/seq are 8-byte big-endian int64s. This mirrors
// Java DataOutputStream writeInt/writeLong + the writeField helper.
func (p *Permit) CanonicalPayload() []byte {
	var buf bytes.Buffer
	writeField(&buf, Domain)
	writeField(&buf, p.Alg)
	writeField(&buf, p.Kid)
	writeInt32(&buf, p.PermitVersion)
	writeField(&buf, p.PolicyVersion)
	writeField(&buf, p.DecisionID)
	writeField(&buf, p.SessionID)
	writeField(&buf, p.OperationID)
	writeField(&buf, p.DeviceID)
	writeField(&buf, p.OperatorSubject)
	writeField(&buf, p.Capability)
	writeField(&buf, p.CommandHash)
	writeInt64(&buf, p.IssuedAtEpochMillis)
	writeInt64(&buf, p.ExpiresAtEpochMillis)
	writeInt64(&buf, p.Seq)
	return buf.Bytes()
}

func writeField(buf *bytes.Buffer, field string) {
	b := []byte(field)
	writeInt32(buf, int32(len(b)))
	buf.Write(b)
}

func writeInt32(buf *bytes.Buffer, v int32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(v))
	buf.Write(b[:])
}

func writeInt64(buf *bytes.Buffer, v int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	buf.Write(b[:])
}
