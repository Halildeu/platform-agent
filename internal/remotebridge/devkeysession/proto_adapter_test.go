package devkeysession_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	"platform-agent/internal/remotebridge/devkeysession"
	pb "platform-agent/internal/remotebridge/pb"
	"platform-agent/internal/tpmenroll"
)

func TestRespond_ProducesAWireResponseCorrelatedToTheChallenge(t *testing.T) {
	tpm, err := tpmenroll.NewMockTPMDevice()
	if err != nil {
		t.Fatalf("mock TPM: %v", err)
	}
	defer tpm.Close()

	nonce := []byte("broker-nonce-32-bytes-exactly!!!")
	ch := &pb.DeviceKeyChallenge{
		ChallengeId:          "00112233445566778899aabbccddeeff",
		NonceB64:             base64.StdEncoding.EncodeToString(nonce),
		IssuedAtEpochMillis:  1_900_000_000_000,
		ExpiresAtEpochMillis: 1_900_060_000_000,
		TransportPeerKey:     "ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
		ProtocolVersion:      "device-key-session-v1",
	}

	resp, err := devkeysession.Respond(tpm, ch, "sess-1", 1_900_000_000_000)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if resp.GetChallengeId() != ch.GetChallengeId() {
		t.Errorf("challengeId = %q, want %q", resp.GetChallengeId(), ch.GetChallengeId())
	}
	if resp.GetSchema() != devkeysession.ResponseSchema {
		t.Errorf("schema = %q, want %q", resp.GetSchema(), devkeysession.ResponseSchema)
	}

	// the binding context on the wire decodes to exactly what the broker re-derives for (sess-1, challenge, peer)
	gotCtx, err := base64.StdEncoding.DecodeString(resp.GetBindingContextB64())
	if err != nil {
		t.Fatalf("binding_context_b64 not base64: %v", err)
	}
	wantCtx, err := devkeysession.BindingContext("sess-1", ch.GetChallengeId(), nonce, ch.GetTransportPeerKey(), ch.GetExpiresAtEpochMillis())
	if err != nil {
		t.Fatalf("BindingContext: %v", err)
	}
	if !bytes.Equal(gotCtx, wantCtx) {
		t.Fatalf("wire binding context != broker re-derivation")
	}

	for name, v := range map[string]string{
		"device_key_pub_b64": resp.GetDeviceKeyPubB64(), "ak_pub_b64": resp.GetAkPubB64(),
		"ak_name_b64": resp.GetAkNameB64(), "certify_info_b64": resp.GetCertifyInfoB64(),
		"certify_sig_b64": resp.GetCertifySigB64(), "quote_b64": resp.GetQuoteB64(),
		"quote_sig_b64": resp.GetQuoteSigB64(), "binding_context_b64": resp.GetBindingContextB64(),
		"device_key_sig_b64": resp.GetDeviceKeySigB64(),
	} {
		if v == "" {
			t.Errorf("required wire field %s is empty", name)
		}
		if _, err := base64.StdEncoding.DecodeString(v); err != nil {
			t.Errorf("wire field %s is not valid base64: %v", name, err)
		}
	}
}

func TestRespond_FailsClosed(t *testing.T) {
	tpm, err := tpmenroll.NewMockTPMDevice()
	if err != nil {
		t.Fatalf("mock TPM: %v", err)
	}
	defer tpm.Close()
	if _, err := devkeysession.Respond(tpm, nil, "sess-1", 1); err == nil {
		t.Error("nil challenge must error")
	}
	if _, err := devkeysession.Respond(tpm, &pb.DeviceKeyChallenge{
		ChallengeId: "c", NonceB64: "!!!not-base64!!!", TransportPeerKey: "p",
		ProtocolVersion: devkeysession.ChallengeProtocolVersion,
	}, "sess-1", 1); err == nil {
		t.Error("a malformed nonce_b64 must error")
	}
	if _, err := devkeysession.Respond(tpm, &pb.DeviceKeyChallenge{
		ChallengeId: "c", NonceB64: "AQ==", TransportPeerKey: "p", ProtocolVersion: "bogus-v9",
	}, "sess-1", 1); err == nil {
		t.Error("a wrong challenge protocol_version must error before any TPM work")
	}
}
