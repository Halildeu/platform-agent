package app

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"platform-agent/internal/config"
	"platform-agent/internal/remotebridge/operation"
	remotebridgepb "platform-agent/internal/remotebridge/pb"
	"platform-agent/internal/remotebridge/screenview"
)

func viewOnlyTLSDeps() remoteBridgeDeps {
	return remoteBridgeDeps{
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
	}
}

func operationCapableCfg() config.Config {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	cfg.RemoteBridgePermitBrokerPublicKeyB64 = testBrokerPermitPublicKeyB64
	cfg.RemoteBridgePermitKeyID = "kid-1"
	return cfg
}

// must-fix #1: enabling VIEW_ONLY must NOT auto-enable the PTY command-execution path (least-privilege,
// ADR-0034 §13). A VIEW_ONLY-only config wires the screen dispatcher and NOTHING that executes a command.
func TestRemoteBridgeViewOnlyOnlyWiresScreenNotPTY(t *testing.T) {
	cfg := operationCapableCfg()
	cfg.RemoteBridgeViewOnlyEnabled = true // operations stays false

	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, viewOnlyTLSDeps())
	if err != nil {
		t.Fatalf("view-only harness config: %v", err)
	}
	if hcfg.ScreenViewDispatcher == nil {
		t.Fatal("view-only enabled did not wire a ScreenViewDispatcher")
	}
	if hcfg.PTYDispatcher != nil {
		t.Fatal("view-only must NOT auto-enable the PTY dispatcher (least-privilege)")
	}
	if hcfg.ConsentResponder == nil {
		t.Fatal("view-only must wire an explicit consent deny responder until attended consent is enabled")
	}
	if hcfg.DeviceKeyResponder != nil {
		t.Fatal("view-only must not wire device-key responders")
	}
	if hcfg.TLSConfig == nil {
		t.Fatal("view-only is operation-capable and must require mTLS")
	}
	result, err := hcfg.ConsentResponder(context.Background(), &remotebridgepb.ConsentPrompt{
		SessionId:         "sess-view",
		Capabilities:      []remotebridgepb.Capability{remotebridgepb.Capability_VIEW_ONLY},
		ExpiryEpochMillis: time.Now().Add(time.Minute).UnixMilli(),
	})
	if err != nil {
		t.Fatalf("view-only disabled consent responder: %v", err)
	}
	if result.GetGranted() || result.GetWindowsInteractiveSession() != "view-only-attended-consent-disabled" {
		t.Fatalf("view-only without attended consent should explicitly deny: %+v", result)
	}
}

func TestRemoteBridgeViewOnlyRejectsMalformedMaskPolicy(t *testing.T) {
	cfg := operationCapableCfg()
	cfg.RemoteBridgeViewOnlyEnabled = true
	cfg.RemoteBridgeViewOnlyMaskRectBPS = "9000,0,1001,1000"
	_, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, viewOnlyTLSDeps())
	if err == nil || !strings.Contains(err.Error(), "view-only mask policy") {
		t.Fatalf("malformed mask policy must fail closed, got: %v", err)
	}
}

func TestRemoteBridgeViewOnlyAttendedConsentWiresResponderWithoutPTY(t *testing.T) {
	cfg := operationCapableCfg()
	cfg.RemoteBridgeViewOnlyEnabled = true
	cfg.RemoteBridgeViewOnlyAttendedConsentEnabled = true

	called := false
	fakeResponder := func(_ context.Context, prompt *remotebridgepb.ConsentPrompt) (*remotebridgepb.ConsentResult, error) {
		called = true
		return &remotebridgepb.ConsentResult{
			SessionId:                 prompt.GetSessionId(),
			Granted:                   true,
			WindowsInteractiveSession: "test-attended-session",
			GrantedAtEpochMillis:      time.Now().UnixMilli(),
			ExpiryEpochMillis:         prompt.GetExpiryEpochMillis(),
		}, nil
	}
	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, remoteBridgeDeps{
		tlsConfig:                &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("cert")}}}},
		viewOnlyConsentResponder: fakeResponder,
	})
	if err != nil {
		t.Fatalf("view-only attended harness config: %v", err)
	}
	if hcfg.ScreenViewDispatcher == nil {
		t.Fatal("view-only attended consent must still wire ScreenViewDispatcher")
	}
	if hcfg.PTYDispatcher != nil {
		t.Fatal("view-only attended consent must not enable PTY")
	}
	if hcfg.ConsentResponder == nil {
		t.Fatal("view-only attended consent did not wire a consent responder")
	}
	result, err := hcfg.ConsentResponder(context.Background(), &remotebridgepb.ConsentPrompt{
		SessionId:           "sess-view",
		OperatorDisplayName: "operator",
		Capabilities:        []remotebridgepb.Capability{remotebridgepb.Capability_VIEW_ONLY},
		ExpiryEpochMillis:   time.Now().Add(time.Minute).UnixMilli(),
	})
	if err != nil {
		t.Fatalf("view-only consent responder: %v", err)
	}
	if !called || !result.GetGranted() || result.GetWindowsInteractiveSession() != "test-attended-session" {
		t.Fatalf("view-only consent did not route to attended responder: called=%v result=%+v", called, result)
	}
}

// must-fix #2: the operations-only path is unchanged by the VIEW_ONLY work — it wires PTY and NO screen
// dispatcher.
func TestRemoteBridgeOperationsOnlyDoesNotWireScreen(t *testing.T) {
	cfg := operationCapableCfg()
	cfg.RemoteBridgeOperationsEnabled = true // view-only stays false

	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, viewOnlyTLSDeps())
	if err != nil {
		t.Fatalf("operations harness config: %v", err)
	}
	if hcfg.PTYDispatcher == nil {
		t.Fatal("operations enabled did not wire a PTY dispatcher")
	}
	if hcfg.ScreenViewDispatcher != nil {
		t.Fatal("operations-only must NOT wire a screen dispatcher")
	}
}

func TestRemoteBridgeBothCapabilitiesWireBoth(t *testing.T) {
	cfg := operationCapableCfg()
	cfg.RemoteBridgeOperationsEnabled = true
	cfg.RemoteBridgeViewOnlyEnabled = true

	hcfg, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, viewOnlyTLSDeps())
	if err != nil {
		t.Fatalf("both-capability harness config: %v", err)
	}
	if hcfg.PTYDispatcher == nil || hcfg.ScreenViewDispatcher == nil {
		t.Fatalf("both flags must wire both dispatchers: pty=%v screen=%v", hcfg.PTYDispatcher != nil, hcfg.ScreenViewDispatcher != nil)
	}
}

// VIEW_ONLY is operation-capable: it shares the secure-channel + broker permit trust-anchor preconditions.
func TestRemoteBridgeViewOnlyRequiresTrustConfig(t *testing.T) {
	cfg := config.Default()
	cfg.RemoteBridgeEnabled = true
	cfg.RemoteBridgeViewOnlyEnabled = true
	cfg.RemoteBridgeBrokerAddr = "broker.example:443"
	// no broker permit public key / kid

	if _, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, viewOnlyTLSDeps()); err == nil {
		t.Fatal("view-only must require a broker permit public key and kid")
	}
}

func TestRemoteBridgeViewOnlyRejectsPlaintext(t *testing.T) {
	cfg := operationCapableCfg()
	cfg.RemoteBridgeViewOnlyEnabled = true
	cfg.RemoteBridgeInsecurePlaintext = true

	if _, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, viewOnlyTLSDeps()); err == nil {
		t.Fatal("view-only must reject plaintext (operations require TLS/mTLS)")
	}
}

// VIEW_ONLY must NOT relax the operation-only guards: pilot auto-consent and the device-key strong path still
// require operations specifically, even when view-only is enabled.
func TestRemoteBridgeViewOnlyDoesNotSatisfyPilotConsent(t *testing.T) {
	cfg := operationCapableCfg()
	cfg.RemoteBridgeViewOnlyEnabled = true // operations false
	cfg.RemoteBridgePilotAutoConsent = true

	if _, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, viewOnlyTLSDeps()); err == nil {
		t.Fatal("pilot auto-consent must require operations even when view-only is enabled")
	}
}

func TestRemoteBridgeViewOnlyDoesNotSatisfyDeviceKey(t *testing.T) {
	cfg := operationCapableCfg()
	cfg.RemoteBridgeViewOnlyEnabled = true // operations false
	cfg.RemoteBridgeDeviceKeySessionEnabled = true

	if _, err := remoteBridgeHarnessConfig(context.Background(), cfg, func() string { return "dev-1" }, viewOnlyTLSDeps()); err == nil {
		t.Fatal("device-key session must require operations even when view-only is enabled")
	}
}

// must-fix #3 (wiring layer): one device-bound provider yields ONE *operation.Authorizer per device (so the
// per-session seq guard is shared), rebuilt only on a device-identity change. The behavioural cross-capability
// seq-replay invariant itself is proven in the operation package (AuthorizeViewOnly shares Authorize's
// a.lastSeq+a.mu); here we prove the wiring delivers a SINGLE shared instance.
func TestDeviceBoundAuthorizerProviderReuseAndRebuild(t *testing.T) {
	p := newDeviceBoundAuthorizerProvider(testBrokerPermitPublicKeyB64, "kid-1", func() string { return "dev-1" })

	a1, err := p.authorizerFor("dev-1")
	if err != nil {
		t.Fatalf("authorizerFor dev-1: %v", err)
	}
	a1b, err := p.authorizerFor("dev-1")
	if err != nil {
		t.Fatalf("authorizerFor dev-1 again: %v", err)
	}
	if a1 != a1b {
		t.Fatal("same device must reuse ONE authorizer so the per-session seq state is preserved")
	}
	a2, err := p.authorizerFor("dev-2")
	if err != nil {
		t.Fatalf("authorizerFor dev-2: %v", err)
	}
	if a2 == a1 {
		t.Fatal("a device-identity change must rebuild the verifier-bound authorizer")
	}
	if _, err := p.authorizerFor(""); err == nil {
		t.Fatal("an empty device id must be refused (fail-closed)")
	}
}

// must-fix #3 (the keystone): the PTY dispatcher and the VIEW_ONLY adapter, wired from the same provider,
// resolve the SAME *operation.Authorizer for a device — so they share one cross-capability seq window.
func TestPTYAndViewOnlyShareOneAuthorizer(t *testing.T) {
	p := newDeviceBoundAuthorizerProvider(testBrokerPermitPublicKeyB64, "kid-1", func() string { return "dev-1" })
	ptyDisp, ok := newDeviceBoundPTYDispatcher(p).(*deviceBoundPTYDispatcher)
	if !ok {
		t.Fatalf("dispatcher type = %T, want *deviceBoundPTYDispatcher", newDeviceBoundPTYDispatcher(p))
	}
	adapter := newProviderViewOnlyAuthorizer(p)
	if ptyDisp.provider != adapter.provider {
		t.Fatal("PTY dispatcher and VIEW_ONLY adapter must share ONE authorizer provider")
	}

	// Building the PTY handler populates the shared provider's authorizer; the adapter must resolve the SAME one.
	if _, err := ptyDisp.handlerFor("dev-1"); err != nil {
		t.Fatalf("pty handlerFor: %v", err)
	}
	viaPTY, err := ptyDisp.provider.authorizerFor("dev-1")
	if err != nil {
		t.Fatalf("provider via pty: %v", err)
	}
	viaView, err := adapter.provider.authorizerFor("dev-1")
	if err != nil {
		t.Fatalf("provider via view: %v", err)
	}
	if viaPTY != viaView {
		t.Fatal("PTY and VIEW_ONLY must resolve the SAME *operation.Authorizer (one shared seq guard)")
	}
}

// must-fix #4: the VIEW_ONLY adapter mirrors the PTY dispatcher's re-enrollment-aware device check — a blank or
// mismatched device is denied fail-closed BEFORE any crypto, so no double-Authorizer and no wrong-device stream.
func TestProviderViewOnlyAuthorizerFailsClosedOnDevice(t *testing.T) {
	const now int64 = 1000
	permit := operation.OperationPermit{
		DeviceID: "dev-1", Capability: operation.CapabilityViewOnly,
		SessionID: "sess-1", OperationID: "op-1", Seq: 1,
	}

	blank := newProviderViewOnlyAuthorizer(newDeviceBoundAuthorizerProvider(testBrokerPermitPublicKeyB64, "kid-1", func() string { return "" }))
	if d := blank.AuthorizeViewOnly(permit, now); d.Allowed || d.Reason != operation.ReasonPermitDeviceMismatch {
		t.Fatalf("blank device must deny with %s, got allowed=%v reason=%q", operation.ReasonPermitDeviceMismatch, d.Allowed, d.Reason)
	}

	mismatch := newProviderViewOnlyAuthorizer(newDeviceBoundAuthorizerProvider(testBrokerPermitPublicKeyB64, "kid-1", func() string { return "dev-1" }))
	wrongDevice := permit
	wrongDevice.DeviceID = "dev-OTHER"
	if d := mismatch.AuthorizeViewOnly(wrongDevice, now); d.Allowed || d.Reason != operation.ReasonPermitDeviceMismatch {
		t.Fatalf("wrong device must deny with %s, got allowed=%v reason=%q", operation.ReasonPermitDeviceMismatch, d.Allowed, d.Reason)
	}
}

// must-fix #6/#7: the default VIEW_ONLY producer factory is fail-closed off-Windows (no active-desktop capture)
// — non-nil so VIEW_ONLY can be WIRED, but every call errors so no frame ever egresses until real capture (the
// Session-0 helper, sub-slice #6) is wired and proven on a Windows host.
func TestScreenViewProducerFactoryDefaultFailsClosed(t *testing.T) {
	factory := screenview.NewWindowsProducerFactory(screenview.MaskPolicy{})
	if factory == nil {
		t.Fatal("the producer factory must be non-nil so VIEW_ONLY can be wired")
	}
	if _, err := factory(context.Background(), "session-1", "stream-1"); err == nil {
		t.Fatal("the default screen-view producer factory must be fail-closed (no active-desktop capture off-Windows)")
	}
}
