package devkeysession

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"platform-agent/internal/tpmenroll"
)

// Challenge is the broker DeviceKeyChallenge as the agent consumes it: the wire payload fields plus the broker
// sessionId that rode the CONTROL Envelope (Envelope.sessionId), which the signature must commit to.
type Challenge struct {
	ChallengeID          string
	SessionID            string // from the CONTROL Envelope.sessionId (NOT the DeviceKeyChallenge payload)
	Nonce                []byte // the RAW (decoded) broker nonce
	TransportPeerKey     string // the broker's view of this agent's mTLS leaf fingerprint (from the challenge)
	ExpiresAtEpochMillis int64
}

// Response is the agent's produced device-key session attestation in RAW form (bytes, not base64): the caller's
// thin proto adapter base64-encodes these into the wire DeviceKeyAttestationResponse. Decoupled from the
// generated protobuf so the security-bearing production logic is unit-testable without the regenerated stubs.
type Response struct {
	ChallengeID         string
	Schema              string
	DeviceKeyPub        []byte
	AKPub               []byte
	AKName              []byte
	EKPub               []byte
	EKCert              []byte
	EKCertChain         [][]byte
	CertifyInfo         []byte
	CertifySig          []byte
	Quote               []byte
	QuoteSig            []byte
	BindingContext      []byte
	DeviceKeySig        []byte
	SignedAtEpochMillis int64
}

// Produce answers a broker DeviceKeyChallenge with the canonical TPM-native attestation (Faz 22.6 #548): it
// re-derives the binding context, has the AK certify the device key (V4) + quote the broker nonce (V5), and has
// the device key SIGN the binding context (live possession, session/transport-bound). The broker's
// DEVICE_KEY_ATTESTATION_REAL verifier re-derives + checks every one of these. Fail-closed on any TPM error or a
// non-RSA device key (the enrollment policy issues an RSA-3072 device key; an EC leaf would need an ECDSA marshal
// not yet wired — surfaced as an explicit error rather than a silently malformed signature).
func Produce(tpm tpmenroll.TPMDevice, ch Challenge, nowEpochMillis int64) (*Response, error) {
	if tpm == nil {
		return nil, errors.New("devkeysession: nil TPM device")
	}
	bindingCtx, err := BindingContext(ch.SessionID, ch.ChallengeID, ch.Nonce, ch.TransportPeerKey, ch.ExpiresAtEpochMillis)
	if err != nil {
		return nil, err
	}

	deviceKeyPub, err := tpm.DeviceKey()
	if err != nil {
		return nil, fmt.Errorf("devkeysession: device key: %w", err)
	}
	akPub, akName, err := tpm.AttestationKey()
	if err != nil {
		return nil, fmt.Errorf("devkeysession: attestation key: %w", err)
	}
	ekPub, ekCert, ekChain, err := tpm.EndorsementKey()
	if err != nil {
		return nil, fmt.Errorf("devkeysession: endorsement key: %w", err)
	}

	// V4 — the AK certifies the device key's Name; qualifyingData binds the nonce (mirrors the enrollment flow).
	certifyInfo, certifySig, err := tpm.CertifyDeviceKey(ch.Nonce)
	if err != nil {
		return nil, fmt.Errorf("devkeysession: certify device key: %w", err)
	}
	// V5 — a fresh AK quote whose extraData is the broker nonce (PCR selection is the broker's opt-in V6, omitted).
	quote, quoteSig, err := tpm.Quote(ch.Nonce, nil)
	if err != nil {
		return nil, fmt.Errorf("devkeysession: quote: %w", err)
	}

	// The device key itself signs the binding context → live possession, bound to THIS session + challenge + peer.
	deviceKeySig, err := signBindingContext(tpm.DeviceKeySigner(), bindingCtx)
	if err != nil {
		return nil, err
	}

	return &Response{
		ChallengeID:         ch.ChallengeID,
		Schema:              ResponseSchema,
		DeviceKeyPub:        deviceKeyPub,
		AKPub:               akPub,
		AKName:              akName,
		EKPub:               ekPub,
		EKCert:              ekCert,
		EKCertChain:         ekChain,
		CertifyInfo:         certifyInfo,
		CertifySig:          certifySig,
		Quote:               quote,
		QuoteSig:            quoteSig,
		BindingContext:      bindingCtx,
		DeviceKeySig:        deviceKeySig,
		SignedAtEpochMillis: nowEpochMillis,
	}, nil
}

// signBindingContext signs the binding context with the device key and wraps the result as a TPMT_SIGNATURE the
// broker can parse — PKCS#1 v1.5 over SHA-256, matching the broker's "SHA256withRSA" verify path (the same scheme
// the enrollment CSR proof-of-possession uses). Only RSA device keys are supported in this slice.
func signBindingContext(signer crypto.Signer, bindingCtx []byte) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("devkeysession: no device key signer")
	}
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("devkeysession: device key is not RSA (got %T); only RSASSA is wired", signer.Public())
	}
	digest := sha256.Sum256(bindingCtx)
	raw, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("devkeysession: device-key sign: %w", err)
	}
	return tpmenroll.MarshalRSASSASignature(tpmenroll.AlgSHA256, raw), nil
}
