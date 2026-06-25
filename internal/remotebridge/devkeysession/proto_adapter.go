package devkeysession

import (
	"encoding/base64"
	"errors"
	"fmt"

	pb "platform-agent/internal/remotebridge/pb"
	"platform-agent/internal/tpmenroll"
)

// Respond decodes a wire DeviceKeyChallenge (+ the broker sessionId that rode the CONTROL Envelope), produces the
// TPM-native attestation via Produce, and marshals it to the wire DeviceKeyAttestationResponse. This is the
// concrete agent answer to a broker challenge — the agent's main wiring adapts it to the harness DeviceKeyResponder
// hook. Fail-closed: a nil/blank challenge, a malformed nonce, or any TPM error returns an error (no partial wire
// response).
func Respond(tpm tpmenroll.TPMDevice, challenge *pb.DeviceKeyChallenge, sessionID string, nowEpochMillis int64) (*pb.DeviceKeyAttestationResponse, error) {
	if challenge == nil {
		return nil, errors.New("devkeysession: nil challenge")
	}
	// pin the broker challenge protocol (the broker also pins it + denies a mismatch) — avoids doing TPM work for
	// a wrong/future-protocol challenge; cheap defense, not the security boundary (the broker verifier is).
	if challenge.GetProtocolVersion() != ChallengeProtocolVersion {
		return nil, fmt.Errorf("devkeysession: unsupported challenge protocol %q (want %q)",
			challenge.GetProtocolVersion(), ChallengeProtocolVersion)
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge.GetNonceB64())
	if err != nil {
		return nil, fmt.Errorf("devkeysession: malformed challenge nonce_b64: %w", err)
	}
	resp, err := Produce(tpm, Challenge{
		ChallengeID:          challenge.GetChallengeId(),
		SessionID:            sessionID,
		Nonce:                nonce,
		TransportPeerKey:     challenge.GetTransportPeerKey(),
		ExpiresAtEpochMillis: challenge.GetExpiresAtEpochMillis(),
	}, nowEpochMillis)
	if err != nil {
		return nil, err
	}
	return ToProto(resp), nil
}

// ToProto marshals a produced Response to the wire DeviceKeyAttestationResponse: standard-base64 over every raw
// byte field (the codebase's binary-on-the-wire convention; the broker adapter base64-decodes + bounds-checks).
func ToProto(r *Response) *pb.DeviceKeyAttestationResponse {
	if r == nil {
		return nil
	}
	enc := base64.StdEncoding.EncodeToString
	chain := make([]string, 0, len(r.EKCertChain))
	for _, c := range r.EKCertChain {
		chain = append(chain, enc(c))
	}
	return &pb.DeviceKeyAttestationResponse{
		ChallengeId:         r.ChallengeID,
		Schema:              r.Schema,
		DeviceKeyPubB64:     enc(r.DeviceKeyPub),
		AkPubB64:            enc(r.AKPub),
		AkNameB64:           enc(r.AKName),
		EkPubB64:            enc(r.EKPub),
		EkCertB64:           encOrEmpty(r.EKCert),
		EkCertChainB64:      chain,
		CertifyInfoB64:      enc(r.CertifyInfo),
		CertifySigB64:       enc(r.CertifySig),
		QuoteB64:            enc(r.Quote),
		QuoteSigB64:         enc(r.QuoteSig),
		BindingContextB64:   enc(r.BindingContext),
		DeviceKeySigB64:     enc(r.DeviceKeySig),
		SignedAtEpochMillis: r.SignedAtEpochMillis,
	}
}

// encOrEmpty keeps an absent optional field (EK cert may be empty on a bounded-lab path) as "" rather than the
// base64 of an empty slice — matching the broker's optional-field decode (empty/blank → absent).
func encOrEmpty(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
