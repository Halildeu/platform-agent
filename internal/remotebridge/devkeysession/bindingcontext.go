// Package devkeysession implements the Faz 22.6 #548 agent side of the canonical TPM-native device-key SESSION
// attestation: answering a broker DeviceKeyChallenge with a DeviceKeyAttestationResponse. The broker
// (platform-backend endpoint-admin-service) issues a broker-nonced challenge per opened remote-support session;
// this package re-derives the canonical binding context, signs it with the TPM device key, and packages the AK
// Certify/Quote + AK/EK/device-key material so the broker's DEVICE_KEY_ATTESTATION_REAL verifier can establish a
// real HARDWARE_KEY_ATTESTATION. Gated, default-off.
package devkeysession

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// DomainTag is the fixed domain-separation prefix of the binding context (FROZEN with the #741 wire contract).
// It MUST be byte-identical to the broker's DeviceKeySessionBindingContext.DOMAIN_TAG.
const DomainTag = "F22.6_DEVICE_KEY_SESSION_V1"

// ResponseSchema is the schema literal the DeviceKeyAttestationResponse carries; the broker verifier pins it.
const ResponseSchema = "faz22.6.device-key-session.v1"

// ChallengeProtocolVersion is the broker DeviceKeyChallenge.protocol_version the agent answers; the broker pins
// it too (DeviceKeyChallengeStore.PROTOCOL_VERSION) and denies a mismatch.
const ChallengeProtocolVersion = "device-key-session-v1"

// BindingContext builds the canonical bytes the TPM device key signs, byte-IDENTICAL to the broker's
// DeviceKeySessionBindingContext.compute (Java): the fixed ASCII DomainTag, a NUL separator, then each variable
// field LENGTH-PREFIXED with a big-endian UINT32 (so no two distinct field tuples can ever collide), then the
// expiry as a fixed-width big-endian UINT64.
//
//	DomainTag ‖ 0x00 ‖ u32(len)|sessionID(ascii) ‖ u32(len)|challengeID(ascii) ‖ u32(len)|nonce(raw)
//	          ‖ u32(len)|transportPeerKey(ascii) ‖ u64(expiresAtEpochMillis)
//
// sessionID/challengeID/transportPeerKey are ASCII on the wire (the broker sessionId, the lowercase-hex
// challengeId, and the lowercase-hex transport peer key); nonce is the RAW decoded broker nonce bytes. Any
// missing/empty required input is an error (fail-closed — the caller must not sign a partial context).
func BindingContext(sessionID, challengeID string, nonce []byte, transportPeerKey string, expiresAtEpochMillis int64) ([]byte, error) {
	if sessionID == "" {
		return nil, errors.New("devkeysession: sessionID required for binding context")
	}
	if challengeID == "" {
		return nil, errors.New("devkeysession: challengeID required for binding context")
	}
	if len(nonce) == 0 {
		return nil, errors.New("devkeysession: nonce required for binding context")
	}
	if transportPeerKey == "" {
		return nil, errors.New("devkeysession: transportPeerKey required for binding context")
	}
	var b bytes.Buffer
	b.Grow(len(DomainTag) + 1 + 4*4 + len(sessionID) + len(challengeID) + len(nonce) + len(transportPeerKey) + 8)
	b.WriteString(DomainTag) // fixed-length tag, no length prefix
	b.WriteByte(0)           // NUL separates the fixed tag from the first length-prefixed field
	writeLengthPrefixed(&b, []byte(sessionID))
	writeLengthPrefixed(&b, []byte(challengeID))
	writeLengthPrefixed(&b, nonce)
	writeLengthPrefixed(&b, []byte(transportPeerKey))
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], uint64(expiresAtEpochMillis))
	b.Write(u64[:])
	return b.Bytes(), nil
}

func writeLengthPrefixed(b *bytes.Buffer, field []byte) {
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(field)))
	b.Write(prefix[:])
	b.Write(field)
}
