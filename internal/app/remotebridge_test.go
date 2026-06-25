package app

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/config"
	remotebridgepb "platform-agent/internal/remotebridge/pb"
)

const testBrokerPermitPublicKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY7DAtgJHZjLaQdftKvXyhbbNlvYCmbuOjoxfTk5LII9UrdN/xZMmP43qQ6zJtERHS7PpBbIppbPMTNxcPk9aIQ=="

func boolPtr(v bool) *bool { return &v }

func consentPrompt(sessionID string) *remotebridgepb.ConsentPrompt {
	return &remotebridgepb.ConsentPrompt{
		SessionId:           sessionID,
		OperatorDisplayName: "operator",
		Capabilities:        []remotebridgepb.Capability{remotebridgepb.Capability_CONSTRAINED_PTY},
		ExpiryEpochMillis:   time.Now().Add(time.Minute).UnixMilli(),
	}
}

// The remote-bridge harness is disabled-by-default (ADR-0034 discipline):
// a default config must produce NO harness, NO goroutine, NO dial.
func TestStartRemoteBridgeDisabledByDefault(t *testing.T) {
	cfg := config.Default()
	if cfg.RemoteBridgeEnabled {
		t.Fatal("RemoteBridgeEnabled must default to false")
	}
	h := StartRemoteBridge(context.Background(), cfg, func() string { return "device" }, log.New(io.Discard, "", 0))
	if h != nil {
		t.Fatal("disabled remote-bridge flag still produced a harness")
	}
}

// Enabled-but-misconfigured (no broker address) refuses loudly instead of
// half-starting.
func TestStartRemoteBridgeRefusesWithoutBrokerAddr(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	h := StartRemoteBridge(context.Background(), cfg, func() string { return "device" }, log.New(io.Discard, "", 0))
	if h != nil {
		t.Fatal("enabled harness without a broker address must refuse init")
	}
}

func TestRemoteBridgeOperationDispatcherDisabledByDefault(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"

	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{})
	if err != nil {
		t.Fatalf("idle harness config should be valid without operation config: %v", err)
	}
	if hcfg.PTYDispatcher != nil {
		t.Fatal("remote-bridge PTY dispatcher must be disabled by default")
	}
	if hcfg.TLSConfig != nil {
		t.Fatal("idle harness should not require operation mTLS config")
	}
}

func TestRemoteBridgeRawAttestationEvidenceOverridesStructuredProducer(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgeAttestationEvidenceB64 = "ZGlnZXN0fGJ1aWxkZXJ8cG9saWN5fHNpZw=="
	cfg.RemoteBridgeAttestationSLSABinaryDigest = "sha256:partial"

	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{})
	if err != nil {
		t.Fatalf("raw attestation override should bypass structured producer validation: %v", err)
	}
	if hcfg.AttestationEvidenceB64 != cfg.RemoteBridgeAttestationEvidenceB64 {
		t.Fatalf("attestation evidence = %q, want raw override %q", hcfg.AttestationEvidenceB64, cfg.RemoteBridgeAttestationEvidenceB64)
	}
}

func TestRemoteBridgeStructuredAttestationEnvelopeWired(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgeAttestationSLSABinaryDigest = "sha256:bin"
	cfg.RemoteBridgeAttestationSLSABuilderID = "builder"
	cfg.RemoteBridgeAttestationSLSAPredicateHash = "sha256:predicate"
	cfg.RemoteBridgeAttestationSLSAPredicateSignature = "sig"
	cfg.RemoteBridgeDeviceKeyDerB64 = "AQID"
	cfg.RemoteBridgeDeviceKeyProtectionLevel = "SECURE_ELEMENT_OR_TPM"
	cfg.RemoteBridgeDeviceKeyNonExportable = boolPtr(true)
	cfg.RemoteBridgeDeviceKeySignatureB64 = "BAU="
	cfg.RemoteBridgeDeviceKeySignatureAlgorithm = "SHA256withECDSA"
	cfg.RemoteBridgeDeviceKeyChainDerB64 = []string{"Bgc=", "CAk="}

	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{})
	if err != nil {
		t.Fatalf("structured attestation envelope config: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(hcfg.AttestationEvidenceB64)
	if err != nil {
		t.Fatalf("decode attestation evidence: %v", err)
	}
	text := string(decoded)
	for _, want := range []string{
		`"v":1`,
		`"slsa"`,
		`"deviceKey"`,
		`"protectionLevel":"SECURE_ELEMENT_OR_TPM"`,
		`"nonExportable":true`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("attestation envelope %s missing %s", text, want)
		}
	}
}

func TestRemoteBridgePartialStructuredAttestationConfigRefuses(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgeDeviceKeyDerB64 = "AQID"
	cfg.RemoteBridgeDeviceKeyProtectionLevel = "SECURE_ELEMENT_OR_TPM"

	_, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{})
	if err == nil {
		t.Fatal("partial structured attestation config must refuse remote-bridge init")
	}
}

func TestRemoteBridgePilotAutoConsentRequiresOperationMode(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgePilotAutoConsent = true

	_, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{})
	if err == nil {
		t.Fatal("pilot auto-consent without operation mode must be refused")
	}
}

func TestRemoteBridgeOperationDispatcherWiringRequiresTrustConfig(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"

	_, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
	})
	if err == nil {
		t.Fatal("operation-capable remote bridge must require a broker permit public key and kid")
	}
}

func TestRemoteBridgeOperationDispatcherWiringRejectsPlaintext(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgeInsecurePlaintext = true
	cfg.RemoteBridgeBrokerAddr = "127.0.0.1:9444"
	cfg.RemoteBridgePermitBrokerPublicKeyB64 = testBrokerPermitPublicKeyB64
	cfg.RemoteBridgePermitKeyID = "kid-1"

	_, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
	})
	if err == nil {
		t.Fatal("operation-capable remote bridge must reject plaintext")
	}
}

func TestRemoteBridgeOperationDispatcherWiresStatefulPTY(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgePermitBrokerPublicKeyB64 = testBrokerPermitPublicKeyB64
	cfg.RemoteBridgePermitKeyID = "kid-1"

	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
	})
	if err != nil {
		t.Fatalf("operation harness config: %v", err)
	}
	if hcfg.PTYDispatcher == nil {
		t.Fatal("operation-capable remote bridge did not wire a PTY dispatcher")
	}
	if hcfg.TLSConfig == nil {
		t.Fatal("operation-capable remote bridge did not wire mTLS config")
	}
	if hcfg.ConsentResponder != nil {
		t.Fatal("pilot auto-consent must be disabled unless explicitly configured")
	}
	dispatcher, ok := hcfg.PTYDispatcher.(*deviceBoundPTYDispatcher)
	if !ok {
		t.Fatalf("dispatcher type = %T, want *deviceBoundPTYDispatcher", hcfg.PTYDispatcher)
	}
	first, err := dispatcher.handlerFor("dev-1")
	if err != nil {
		t.Fatalf("first handler: %v", err)
	}
	second, err := dispatcher.handlerFor("dev-1")
	if err != nil {
		t.Fatalf("second handler: %v", err)
	}
	if first != second {
		t.Fatal("same device must reuse the stateful PTY handler so seq replay state is preserved")
	}
	rotated, err := dispatcher.handlerFor("dev-2")
	if err != nil {
		t.Fatalf("rotated handler: %v", err)
	}
	if rotated == first {
		t.Fatal("device identity change must rebuild the verifier-bound handler")
	}
}

func TestRemoteBridgePilotAutoConsentWiring(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgePilotAutoConsent = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgePermitBrokerPublicKeyB64 = testBrokerPermitPublicKeyB64
	cfg.RemoteBridgePermitKeyID = "kid-1"

	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
	})
	if err != nil {
		t.Fatalf("operation harness config: %v", err)
	}
	if hcfg.ConsentResponder == nil {
		t.Fatal("pilot auto-consent did not wire a consent responder")
	}
	result, err := hcfg.ConsentResponder(context.Background(), consentPrompt("sess-1"))
	if err != nil {
		t.Fatalf("consent responder: %v", err)
	}
	if result.GetSessionId() != "sess-1" || !result.GetGranted() {
		t.Fatalf("consent result = %+v, want granted for constrained PTY prompt", result)
	}
	denied, err := hcfg.ConsentResponder(context.Background(), &remotebridgepb.ConsentPrompt{
		SessionId:           "sess-2",
		ExpiryEpochMillis:   1,
		Capabilities:        []remotebridgepb.Capability{remotebridgepb.Capability_CONSTRAINED_PTY},
		OperatorDisplayName: "operator",
	})
	if err != nil {
		t.Fatalf("expired consent responder: %v", err)
	}
	if denied.GetGranted() {
		t.Fatal("expired prompt must not be granted")
	}
}

func TestRemoteBridgeDeviceKeySessionWiring(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgeDeviceKeySessionEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgePermitBrokerPublicKeyB64 = testBrokerPermitPublicKeyB64
	cfg.RemoteBridgePermitKeyID = "kid-1"

	called := false
	fake := func(_ context.Context, ch *remotebridgepb.DeviceKeyChallenge, _ string) (*remotebridgepb.DeviceKeyAttestationResponse, error) {
		called = true
		return &remotebridgepb.DeviceKeyAttestationResponse{ChallengeId: ch.GetChallengeId()}, nil
	}
	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{
		tlsConfig:          &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
		deviceKeyResponder: fake,
	})
	if err != nil {
		t.Fatalf("device-key session harness config: %v", err)
	}
	if hcfg.DeviceKeyResponder == nil {
		t.Fatal("device-key session enabled did not wire a DeviceKeyResponder")
	}
	resp, err := hcfg.DeviceKeyResponder(context.Background(), &remotebridgepb.DeviceKeyChallenge{ChallengeId: "c1"}, "sess-1")
	if err != nil {
		t.Fatalf("wired responder: %v", err)
	}
	if !called || resp.GetChallengeId() != "c1" {
		t.Fatalf("wired responder not invoked correctly: called=%v resp=%+v", called, resp)
	}
}

func TestRemoteBridgeDeviceKeySessionDisabledByDefault(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgePermitBrokerPublicKeyB64 = testBrokerPermitPublicKeyB64
	cfg.RemoteBridgePermitKeyID = "kid-1"
	// RemoteBridgeDeviceKeySessionEnabled defaults false — no responder must be wired.

	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
	})
	if err != nil {
		t.Fatalf("harness config: %v", err)
	}
	if hcfg.DeviceKeyResponder != nil {
		t.Fatal("device-key session must be disabled unless explicitly enabled")
	}
}

func TestRemoteBridgeDeviceKeySessionRequiresOperations(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeDeviceKeySessionEnabled = true
	// RemoteBridgeOperationsEnabled stays false — the flag must refuse loudly, not silently no-op.
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"

	_, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{})
	if err == nil {
		t.Fatal("device-key session with operations disabled must refuse, not silently no-op")
	}
}
