package devkeysession_test

import (
	"bytes"
	"crypto/rsa"
	"testing"

	"platform-agent/internal/remotebridge/devkeysession"
	"platform-agent/internal/tpmenroll"
)

func validChallenge() devkeysession.Challenge {
	return devkeysession.Challenge{
		ChallengeID:          "00112233445566778899aabbccddeeff",
		SessionID:            "sess-1",
		Nonce:                []byte("broker-nonce-32-bytes-exactly!!!"),
		TransportPeerKey:     "ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
		ExpiresAtEpochMillis: 1_900_060_000_000,
	}
}

func TestProduce_AnswersChallengeWithAVerifiableAttestation(t *testing.T) {
	tpm, err := tpmenroll.NewMockTPMDevice()
	if err != nil {
		t.Fatalf("mock TPM: %v", err)
	}
	defer tpm.Close()
	ch := validChallenge()

	resp, err := devkeysession.Produce(tpm, ch, 1_900_000_000_000)
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}

	if resp.Schema != devkeysession.ResponseSchema {
		t.Errorf("schema = %q, want %q", resp.Schema, devkeysession.ResponseSchema)
	}
	if resp.ChallengeID != ch.ChallengeID {
		t.Errorf("challengeID = %q, want %q", resp.ChallengeID, ch.ChallengeID)
	}
	if resp.SignedAtEpochMillis != 1_900_000_000_000 {
		t.Errorf("signedAt = %d", resp.SignedAtEpochMillis)
	}

	// the binding context equals an independent recompute (what the broker will re-derive + verify against)
	wantCtx, err := devkeysession.BindingContext(ch.SessionID, ch.ChallengeID, ch.Nonce, ch.TransportPeerKey, ch.ExpiresAtEpochMillis)
	if err != nil {
		t.Fatalf("BindingContext: %v", err)
	}
	if !bytes.Equal(resp.BindingContext, wantCtx) {
		t.Fatalf("binding context mismatch")
	}

	// the device key's signature verifies over the binding context (live possession proof the broker checks)
	devicePub := tpm.DeviceKeySigner().Public().(*rsa.PublicKey)
	if err := tpmenroll.VerifyAttestSignature(devicePub, resp.BindingContext, resp.DeviceKeySig); err != nil {
		t.Fatalf("device-key signature must verify over the binding context: %v", err)
	}
	// a tampered context must NOT verify (the signature is bound to THIS context)
	if err := tpmenroll.VerifyAttestSignature(devicePub, []byte("a-different-context"), resp.DeviceKeySig); err == nil {
		t.Fatalf("device-key signature must not verify over a different context")
	}

	// the AK certify (V4) + quote (V5) are real AK signatures over their attests
	akArea, err := tpmenroll.ParsePublicArea(resp.AKPub, true)
	if err != nil {
		t.Fatalf("parse AK pub: %v", err)
	}
	akPubKey, err := akArea.PublicKey()
	if err != nil {
		t.Fatalf("AK public key: %v", err)
	}
	akRSA, ok := akPubKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("AK is not RSA: %T", akPubKey)
	}
	if err := tpmenroll.VerifyAttestSignature(akRSA, resp.CertifyInfo, resp.CertifySig); err != nil {
		t.Fatalf("AK certify signature must verify: %v", err)
	}
	if err := tpmenroll.VerifyAttestSignature(akRSA, resp.Quote, resp.QuoteSig); err != nil {
		t.Fatalf("AK quote signature must verify: %v", err)
	}

	// every core member the broker's strong-path verifier requires is present
	for name, b := range map[string][]byte{
		"deviceKeyPub": resp.DeviceKeyPub, "akPub": resp.AKPub, "akName": resp.AKName,
		"ekCert": resp.EKCert, "certifyInfo": resp.CertifyInfo, "certifySig": resp.CertifySig,
		"quote": resp.Quote, "quoteSig": resp.QuoteSig, "bindingContext": resp.BindingContext,
		"deviceKeySig": resp.DeviceKeySig,
	} {
		if len(b) == 0 {
			t.Errorf("core member %s is empty", name)
		}
	}
}

func TestProduce_FailsClosed(t *testing.T) {
	tpm, err := tpmenroll.NewMockTPMDevice()
	if err != nil {
		t.Fatalf("mock TPM: %v", err)
	}
	defer tpm.Close()

	if _, err := devkeysession.Produce(nil, validChallenge(), 1); err == nil {
		t.Error("nil TPM must error")
	}
	bad := validChallenge()
	bad.SessionID = "" // a missing required binding-context input
	if _, err := devkeysession.Produce(tpm, bad, 1); err == nil {
		t.Error("a malformed challenge (blank sessionID) must error before producing a partial attestation")
	}
}
