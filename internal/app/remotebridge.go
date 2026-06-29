package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"platform-agent/internal/autoenroll"
	"platform-agent/internal/config"
	"platform-agent/internal/mtls"
	"platform-agent/internal/platform/windows/certstore"
	"platform-agent/internal/remotebridge/attestation"
	"platform-agent/internal/remotebridge/harness"
	"platform-agent/internal/remotebridge/operation"
	pb "platform-agent/internal/remotebridge/pb"
	"platform-agent/internal/remotebridge/ptyexec"
	"platform-agent/internal/remotebridge/screenview"
)

// StartRemoteBridge starts the Faz 22.6 T-3 remote-bridge idle harness when
// — and only when — the explicit config flag is set. Default off: the agent
// never auto-connects to a broker (ADR-0034 disabled-by-default discipline);
// with the flag off this returns nil and spawns nothing.
//
// deviceID is the live identity getter (protocol.Client.DeviceID for the
// HMAC runner): the harness polls it and never dials while it is empty, so
// an enabled flag cannot produce a stream before enrollment (Codex T-3
// revision #2). The returned harness is observational (counters/session
// state); lifecycle is owned by ctx.
func StartRemoteBridge(ctx context.Context, cfg config.Config, deviceID func() string, logger *log.Logger) *harness.Harness {
	if !cfg.RemoteBridgeEnabled {
		return nil
	}
	if logger == nil {
		logger = log.Default()
	}
	hcfg, err := remoteBridgeHarnessConfig(ctx, cfg, deviceID, remoteBridgeDeps{})
	if err != nil {
		logger.Printf("remote-bridge: harness config refused: %v", err)
		return nil
	}
	h, err := harness.New(hcfg, logger)
	if err != nil {
		// Misconfiguration (e.g. enabled without a broker addr) refuses
		// loudly instead of half-starting.
		logger.Printf("remote-bridge: harness init refused: %v", err)
		return nil
	}
	go h.Run(ctx)
	return h
}

type remoteBridgeDeps struct {
	tlsConfig *tls.Config
	// deviceKeyResponder, when non-nil, is used instead of opening a real TPM
	// — the test seam for the #548 device-key session wiring (a real TPM is
	// unavailable in CI).
	deviceKeyResponder harness.DeviceKeyResponder
	// screenViewProducerFactory, when non-nil, overrides the platform default
	// VIEW_ONLY capture factory — the test seam for the #1580 screen-observation
	// wiring (a real capture needs an active desktop; the default is fail-closed
	// off-Windows).
	screenViewProducerFactory screenview.ProducerFactory
}

func remoteBridgeHarnessConfig(ctx context.Context, cfg config.Config, deviceID func() string, deps remoteBridgeDeps) (harness.Config, error) {
	attestationEvidenceB64, err := remoteBridgeAttestationEvidenceB64(cfg)
	if err != nil {
		return harness.Config{}, err
	}
	hcfg := harness.Config{
		BrokerAddr:             cfg.RemoteBridgeBrokerAddr,
		DeviceIDProvider:       deviceID,
		AgentVersion:           cfg.AgentVersion,
		InsecurePlaintext:      cfg.RemoteBridgeInsecurePlaintext,
		FirstHeartbeatDeadline: cfg.RemoteBridgeFirstHeartbeatDeadline,
		HeartbeatMissFactor:    cfg.RemoteBridgeHeartbeatMissFactor,
		BackoffMin:             cfg.RemoteBridgeBackoffMin,
		BackoffMax:             cfg.RemoteBridgeBackoffMax,
		IdentityPollInterval:   cfg.RemoteBridgeIdentityPollInterval,
		DialTimeout:            cfg.RemoteBridgeDialTimeout,
		AttestationEvidenceB64: attestationEvidenceB64,
	}
	// Pilot auto-consent and the #548 device-key strong path are CONSTRAINED_PTY-operation concerns (command
	// execution + an mTLS-pinned challenge); they require operations specifically and are NEVER enabled as a
	// side effect of VIEW_ONLY. Refuse loudly, not a silent no-op.
	if cfg.RemoteBridgePilotAutoConsent && !cfg.RemoteBridgeOperationsEnabled {
		return harness.Config{}, errors.New("remote-bridge pilot auto-consent requires ENDPOINT_AGENT_REMOTE_BRIDGE_OPERATIONS_ENABLED")
	}
	if cfg.RemoteBridgeDeviceKeySessionEnabled && !cfg.RemoteBridgeOperationsEnabled {
		return harness.Config{}, errors.New("remote-bridge device-key session requires ENDPOINT_AGENT_REMOTE_BRIDGE_OPERATIONS_ENABLED")
	}

	// VIEW_ONLY (screen observation, #1580) and CONSTRAINED_PTY (command execution) are INDEPENDENT capabilities
	// (ADR-0034 §13/D10; least-privilege). Each is wired only by its own flag — enabling VIEW_ONLY never enables
	// PTY and vice-versa — but both are "operation-capable" and so share the secure-channel + broker-permit
	// trust-anchor preconditions below. With neither enabled the harness stays idle (observational only).
	operationCapable := cfg.RemoteBridgeOperationsEnabled || cfg.RemoteBridgeViewOnlyEnabled
	if !operationCapable {
		return hcfg, nil
	}
	if cfg.RemoteBridgeInsecurePlaintext {
		return harness.Config{}, errors.New("remote-bridge operations require TLS/mTLS; plaintext is refused")
	}
	if strings.TrimSpace(cfg.RemoteBridgePermitBrokerPublicKeyB64) == "" {
		return harness.Config{}, errors.New("remote-bridge operations require ENDPOINT_AGENT_REMOTE_BRIDGE_PERMIT_BROKER_PUBLIC_KEY_B64")
	}
	if strings.TrimSpace(cfg.RemoteBridgePermitKeyID) == "" {
		return harness.Config{}, errors.New("remote-bridge operations require ENDPOINT_AGENT_REMOTE_BRIDGE_PERMIT_KEY_ID")
	}
	tlsCfg := deps.tlsConfig
	if tlsCfg == nil {
		var err error
		tlsCfg, err = remoteBridgeMTLSConfig(ctx, cfg)
		if err != nil {
			return harness.Config{}, err
		}
	}
	hcfg.TLSConfig = tlsCfg

	// ONE shared device-bound authorizer provider for BOTH capabilities: PTY and VIEW_ONLY fetch the SAME
	// *operation.Authorizer for a given device id, so the broker's per-session seq (monotonic ACROSS
	// capabilities) is replay-protected by ONE window. Two separate Authorizers would reopen a cross-capability
	// replay hole at this wiring layer (operation.AuthorizeViewOnly shares Authorize's a.lastSeq+a.mu).
	authzProvider := newDeviceBoundAuthorizerProvider(
		cfg.RemoteBridgePermitBrokerPublicKeyB64,
		cfg.RemoteBridgePermitKeyID,
		deviceID,
	)

	if cfg.RemoteBridgeOperationsEnabled {
		hcfg.PTYDispatcher = newDeviceBoundPTYDispatcher(authzProvider)
		if cfg.RemoteBridgePilotAutoConsent {
			hcfg.ConsentResponder = pilotAutoConsentResponder
		}
		if cfg.RemoteBridgeDeviceKeySessionEnabled {
			// #548 strong path: answer the broker's device-key session challenge with a
			// TPM-native attestation. Gated inside the operations block because the binding
			// context pins the mTLS transport-peer key — the challenge is only meaningful over
			// the secure channel. A TPM-open failure refuses loudly (fail-closed) instead of
			// silently leaving the strong path unanswered.
			responder := deps.deviceKeyResponder
			if responder == nil {
				// Catch the obvious misconfig (harness.New would reject it later) BEFORE opening the
				// TPM, so a config error never leaves a TPM handle held for the agent's lifetime.
				if strings.TrimSpace(cfg.RemoteBridgeBrokerAddr) == "" {
					return harness.Config{}, errors.New("remote-bridge device-key session requires a broker address")
				}
				var rerr error
				responder, rerr = newTPMDeviceKeyResponder(ctx)
				if rerr != nil {
					return harness.Config{}, fmt.Errorf("remote-bridge device-key session: %w", rerr)
				}
			}
			hcfg.DeviceKeyResponder = responder
		}
	}

	if cfg.RemoteBridgeViewOnlyEnabled {
		// VIEW_ONLY (#1580) recording-OFF screen observation. The VIEW_ONLY authorizer adapter shares
		// authzProvider with the PTY path (one seq guard) and mirrors the re-enrollment-aware device check; the
		// producer factory is fail-closed by default on every platform without an active-desktop capture impl
		// (sub-slice #6), so an enabled flag wires the gate + routing but never egresses a frame until capture
		// is proven on a real host.
		producerFactory := deps.screenViewProducerFactory
		if producerFactory == nil {
			producerFactory = newScreenViewProducerFactory()
		}
		dispatcher, err := screenview.New(newProviderViewOnlyAuthorizer(authzProvider), producerFactory, screenview.Options{})
		if err != nil {
			return harness.Config{}, fmt.Errorf("remote-bridge view-only dispatcher: %w", err)
		}
		hcfg.ScreenViewDispatcher = dispatcher
	}

	return hcfg, nil
}

func remoteBridgeAttestationEvidenceB64(cfg config.Config) (string, error) {
	if strings.TrimSpace(cfg.RemoteBridgeAttestationEvidenceB64) != "" {
		return cfg.RemoteBridgeAttestationEvidenceB64, nil
	}
	return attestation.BuildEvidenceB64(attestation.Config{
		SLSA: attestation.SLSAConfig{
			BinaryDigest:       cfg.RemoteBridgeAttestationSLSABinaryDigest,
			BuilderID:          cfg.RemoteBridgeAttestationSLSABuilderID,
			PredicateHash:      cfg.RemoteBridgeAttestationSLSAPredicateHash,
			PredicateSignature: cfg.RemoteBridgeAttestationSLSAPredicateSignature,
		},
		DeviceKey: attestation.DeviceKeyConfig{
			KeyDerB64:       cfg.RemoteBridgeDeviceKeyDerB64,
			ProtectionLevel: cfg.RemoteBridgeDeviceKeyProtectionLevel,
			NonExportable:   cfg.RemoteBridgeDeviceKeyNonExportable,
			SignatureB64:    cfg.RemoteBridgeDeviceKeySignatureB64,
			Algorithm:       cfg.RemoteBridgeDeviceKeySignatureAlgorithm,
			ChainDerB64:     cfg.RemoteBridgeDeviceKeyChainDerB64,
		},
	})
}

func pilotAutoConsentResponder(ctx context.Context, prompt *pb.ConsentPrompt) (*pb.ConsentResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if prompt == nil || strings.TrimSpace(prompt.GetSessionId()) == "" {
		return nil, errors.New("remote-bridge pilot auto-consent requires a session id")
	}
	now := time.Now().UnixMilli()
	expiry := prompt.GetExpiryEpochMillis()
	if expiry <= 0 {
		expiry = time.Now().Add(5 * time.Minute).UnixMilli()
	}
	granted := expiry > now && constrainedPTYOnly(prompt.GetCapabilities())
	return &pb.ConsentResult{
		SessionId:                 prompt.GetSessionId(),
		Granted:                   granted,
		WindowsInteractiveSession: "pilot-auto-consent",
		GrantedAtEpochMillis:      now,
		ExpiryEpochMillis:         expiry,
	}, nil
}

func constrainedPTYOnly(caps []pb.Capability) bool {
	if len(caps) == 0 {
		return false
	}
	for _, cap := range caps {
		if cap != pb.Capability_CONSTRAINED_PTY {
			return false
		}
	}
	return true
}

func remoteBridgeMTLSConfig(ctx context.Context, cfg config.Config) (*tls.Config, error) {
	filter, err := remoteBridgeCertFilter(cfg)
	if err != nil {
		return nil, err
	}
	material, err := certstore.New().LoadEligibleCert(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("remote-bridge mTLS cert load: %w", err)
	}
	serverName, err := remoteBridgeServerName(cfg)
	if err != nil {
		if c, ok := material.TLSCertificate.PrivateKey.(interface{ Close() }); ok {
			c.Close()
		}
		return nil, err
	}
	tlsCfg, err := mtls.TLSConfigFor(mtls.Options{
		Cert:       material.TLSCertificate,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		if c, ok := material.TLSCertificate.PrivateKey.(interface{ Close() }); ok {
			c.Close()
		}
		return nil, fmt.Errorf("remote-bridge mTLS config: %w", err)
	}
	return tlsCfg, nil
}

func remoteBridgeCertFilter(cfg config.Config) (autoenroll.CertFilter, error) {
	filter := autoenroll.DefaultCertFilter()
	filter.SubjectSuffix = firstNonBlank(cfg.RemoteBridgeMTLSCertSubjectSuffix, cfg.AutoEnrollCertSubjectSuffix)
	filter.SANURIPrefix = firstNonBlank(cfg.RemoteBridgeMTLSCertSANURIPrefix, cfg.AutoEnrollCertSANURIPrefix)
	if strings.TrimSpace(filter.SubjectSuffix) == "" && strings.TrimSpace(filter.SANURIPrefix) == "" {
		return autoenroll.CertFilter{}, errors.New("remote-bridge operations require an mTLS cert subject suffix or SAN URI prefix")
	}
	return filter, nil
}

func remoteBridgeServerName(cfg config.Config) (string, error) {
	if s := strings.TrimSpace(cfg.RemoteBridgeTLSServerName); s != "" {
		return s, nil
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(cfg.RemoteBridgeBrokerAddr))
	if err != nil {
		host = strings.TrimSpace(cfg.RemoteBridgeBrokerAddr)
	}
	if host == "" {
		return "", errors.New("remote-bridge TLS server name cannot be derived from an empty broker address")
	}
	return strings.Trim(host, "[]"), nil
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// deviceBoundAuthorizerProvider builds and caches ONE device-bound *operation.Authorizer, rebuilding it when the
// device identity changes (re-enrollment). The CONSTRAINED_PTY path and the VIEW_ONLY path both fetch from this
// single provider, so for a given device id they share ONE *operation.Authorizer — and therefore ONE per-session
// seq replay guard. The broker's per-session seq is monotonic ACROSS capabilities, so two separate Authorizers
// would let a VIEW_ONLY permit replay a seq a PTY op already consumed (and vice-versa). Safe for concurrent use.
type deviceBoundAuthorizerProvider struct {
	brokerPublicKeyB64 string
	kid                string
	deviceIDProvider   func() string

	mu       sync.Mutex
	deviceID string
	authz    *operation.Authorizer
}

func newDeviceBoundAuthorizerProvider(brokerPublicKeyB64, kid string, deviceIDProvider func() string) *deviceBoundAuthorizerProvider {
	return &deviceBoundAuthorizerProvider{
		brokerPublicKeyB64: brokerPublicKeyB64,
		kid:                kid,
		deviceIDProvider:   deviceIDProvider,
	}
}

// authorizerFor returns the device-bound Authorizer for deviceID, building it on first use and rebuilding it when
// the device identity changes. Every caller for the same device id receives the SAME *operation.Authorizer, so
// the per-session seq guard is shared across capabilities. deviceID must be non-empty.
func (p *deviceBoundAuthorizerProvider) authorizerFor(deviceID string) (*operation.Authorizer, error) {
	if deviceID == "" {
		return nil, errors.New("remote-bridge authorizer provider: empty device id")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.authz != nil && p.deviceID == deviceID {
		return p.authz, nil
	}
	verifier, err := operation.NewVerifier(p.brokerPublicKeyB64, p.kid, deviceID)
	if err != nil {
		return nil, fmt.Errorf("remote-bridge authorizer provider verifier: %w", err)
	}
	p.authz = operation.NewAuthorizer(verifier)
	p.deviceID = deviceID
	return p.authz, nil
}

type deviceBoundPTYDispatcher struct {
	provider *deviceBoundAuthorizerProvider

	mu       sync.Mutex
	deviceID string
	handler  *ptyexec.PtyOperationHandler
}

func newDeviceBoundPTYDispatcher(provider *deviceBoundAuthorizerProvider) harness.PTYDispatcher {
	return &deviceBoundPTYDispatcher{provider: provider}
}

func (d *deviceBoundPTYDispatcher) Handle(ctx context.Context, permit operation.OperationPermit, commandLine, streamID string,
	send func(*pb.DataFrame) error, nowEpochMillis int64) (ptyexec.ExecResult, error) {
	if d == nil || d.provider == nil || d.provider.deviceIDProvider == nil {
		return ptyexec.ExecResult{}, errors.New("remote-bridge pty dispatcher: missing device identity provider")
	}
	deviceID := strings.TrimSpace(d.provider.deviceIDProvider())
	if deviceID == "" || permit.DeviceID != deviceID {
		return ptyexec.ExecResult{}, errors.New("remote-bridge pty dispatcher: device mismatch")
	}
	handler, err := d.handlerFor(deviceID)
	if err != nil {
		return ptyexec.ExecResult{}, err
	}
	return handler.Handle(ctx, permit, commandLine, streamID, send, nowEpochMillis)
}

func (d *deviceBoundPTYDispatcher) handlerFor(deviceID string) (*ptyexec.PtyOperationHandler, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handler != nil && d.deviceID == deviceID {
		return d.handler, nil
	}
	// Fetch the SHARED device-bound Authorizer (the same instance the VIEW_ONLY adapter uses) so the seq guard
	// is shared across capabilities, then build the executor over it (NewExecutorWithAuthorizer, NOT NewExecutor
	// — the latter would mint a second, unshared Authorizer).
	authz, err := d.provider.authorizerFor(deviceID)
	if err != nil {
		return nil, fmt.Errorf("remote-bridge pty dispatcher authorizer: %w", err)
	}
	exec := ptyexec.NewExecutorWithAuthorizer(authz, ptyexec.DefaultAllowlist(), 0, 0)
	handler, err := ptyexec.NewPtyOperationHandler(exec, 0, 0)
	if err != nil {
		return nil, err
	}
	d.deviceID = deviceID
	d.handler = handler
	return handler, nil
}

// providerViewOnlyAuthorizer adapts the shared device-bound authorizer provider to screenview.ViewOnlyAuthorizer.
// It mirrors the PTY dispatcher's re-enrollment-aware device check (live deviceID snapshot, fail-closed on a
// blank or mismatched device) and then delegates to the SAME *operation.Authorizer the PTY path uses for that
// device — so VIEW_ONLY and PTY advance ONE per-session seq window.
type providerViewOnlyAuthorizer struct {
	provider *deviceBoundAuthorizerProvider
}

func newProviderViewOnlyAuthorizer(provider *deviceBoundAuthorizerProvider) *providerViewOnlyAuthorizer {
	return &providerViewOnlyAuthorizer{provider: provider}
}

func (a *providerViewOnlyAuthorizer) AuthorizeViewOnly(permit operation.OperationPermit, nowEpochMillis int64) operation.Decision {
	if a == nil || a.provider == nil || a.provider.deviceIDProvider == nil {
		return operation.Decision{Reason: operation.ReasonPermitVerifierUnavailable}
	}
	deviceID := strings.TrimSpace(a.provider.deviceIDProvider())
	if deviceID == "" || permit.DeviceID != deviceID {
		return operation.Decision{Reason: operation.ReasonPermitDeviceMismatch}
	}
	authz, err := a.provider.authorizerFor(deviceID)
	if err != nil {
		return operation.Decision{Reason: operation.ReasonPermitVerifierUnavailable}
	}
	return authz.AuthorizeViewOnly(permit, nowEpochMillis)
}
