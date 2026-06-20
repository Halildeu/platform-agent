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
	"platform-agent/internal/remotebridge/harness"
	"platform-agent/internal/remotebridge/operation"
	pb "platform-agent/internal/remotebridge/pb"
	"platform-agent/internal/remotebridge/ptyexec"
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
}

func remoteBridgeHarnessConfig(ctx context.Context, cfg config.Config, deviceID func() string, deps remoteBridgeDeps) (harness.Config, error) {
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
		AttestationEvidenceB64: cfg.RemoteBridgeAttestationEvidenceB64,
	}
	if !cfg.RemoteBridgeOperationsEnabled {
		if cfg.RemoteBridgePilotAutoConsent {
			return harness.Config{}, errors.New("remote-bridge pilot auto-consent requires ENDPOINT_AGENT_REMOTE_BRIDGE_OPERATIONS_ENABLED")
		}
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
	hcfg.PTYDispatcher = newDeviceBoundPTYDispatcher(
		cfg.RemoteBridgePermitBrokerPublicKeyB64,
		cfg.RemoteBridgePermitKeyID,
		deviceID,
	)
	if cfg.RemoteBridgePilotAutoConsent {
		hcfg.ConsentResponder = pilotAutoConsentResponder
	}
	return hcfg, nil
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

type deviceBoundPTYDispatcher struct {
	brokerPublicKeyB64 string
	kid                string
	deviceIDProvider   func() string

	mu       sync.Mutex
	deviceID string
	handler  *ptyexec.PtyOperationHandler
}

func newDeviceBoundPTYDispatcher(brokerPublicKeyB64, kid string, deviceIDProvider func() string) harness.PTYDispatcher {
	return &deviceBoundPTYDispatcher{
		brokerPublicKeyB64: brokerPublicKeyB64,
		kid:                kid,
		deviceIDProvider:   deviceIDProvider,
	}
}

func (d *deviceBoundPTYDispatcher) Handle(ctx context.Context, permit operation.OperationPermit, commandLine, streamID string,
	send func(*pb.DataFrame) error, nowEpochMillis int64) (ptyexec.ExecResult, error) {
	if d == nil || d.deviceIDProvider == nil {
		return ptyexec.ExecResult{}, errors.New("remote-bridge pty dispatcher: missing device identity provider")
	}
	deviceID := strings.TrimSpace(d.deviceIDProvider())
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
	verifier, err := operation.NewVerifier(d.brokerPublicKeyB64, d.kid, deviceID)
	if err != nil {
		return nil, fmt.Errorf("remote-bridge pty dispatcher verifier: %w", err)
	}
	exec := ptyexec.NewExecutor(verifier, ptyexec.DefaultAllowlist(), 0, 0)
	handler, err := ptyexec.NewPtyOperationHandler(exec, 0, 0)
	if err != nil {
		return nil, err
	}
	d.deviceID = deviceID
	d.handler = handler
	return handler, nil
}
