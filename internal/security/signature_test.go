package security

import "testing"

func TestVerifyRequestSignatureAcceptsMatchingSignature(t *testing.T) {
	body := []byte(`{"status":"SUCCEEDED"}`)
	signature := SignRequest("agent-secret", "post", "/api/v1/endpoint-agent/heartbeat", 1777362000000, "nonce-1", body)

	if !VerifyRequestSignature("agent-secret", "POST", "/api/v1/endpoint-agent/heartbeat", 1777362000000, "nonce-1", body, signature) {
		t.Fatal("signature verification failed")
	}
}

func TestVerifyRequestSignatureRejectsChangedBody(t *testing.T) {
	body := []byte(`{"status":"SUCCEEDED"}`)
	signature := SignRequest("agent-secret", "POST", "/api/v1/endpoint-agent/heartbeat", 1777362000000, "nonce-1", body)

	changedBody := []byte(`{"status":"FAILED"}`)
	if VerifyRequestSignature("agent-secret", "POST", "/api/v1/endpoint-agent/heartbeat", 1777362000000, "nonce-1", changedBody, signature) {
		t.Fatal("signature verification accepted changed body")
	}
}
