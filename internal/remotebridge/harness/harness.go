// Package harness is the Faz 22.6 T-3 remote-bridge idle transport harness:
// an OUTBOUND-ONLY gRPC client that dials the broker (platform-backend
// endpoint-admin-service RemoteBridge service, T-2b), opens the long-lived
// CONTROL bidi stream, introduces itself with an advisory AgentHello, obeys
// server-push heartbeats and KILL envelopes, and reconnects with jittered
// exponential backoff. It deliberately carries NO capture/PTY machinery by
// default; those paths are T-4 and owner-pilot-gated (ADR-0034 §13/D10). A
// broker-authoritative payload arriving while idle is a protocol defect and
// closes the stream (Codex T-3 revision: defect-close, never silently
// consume).
//
// The harness never opens a listening socket (outbound-only, NAT-friendly)
// and never dials before the local device identity exists (Codex T-3
// revision: an enabled flag alone must not produce anonymous-ish streams).
// The whole package is inert unless the explicit config flag
// ENDPOINT_AGENT_REMOTE_BRIDGE_ENABLED is set (default off).
package harness

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	pb "platform-agent/internal/remotebridge/pb"
)

const (
	// ProtocolVersion is the rb-v1 wire contract revision sent in AgentHello.
	ProtocolVersion = "rb-v1"

	// TransportKillSessionID is the broker's sentinel for a transport-scoped
	// kill (no broker session yet) — it terminates the whole connection, not
	// one session (T-2b ControlStreamRegistry.TRANSPORT_KILL_SESSION).
	TransportKillSessionID = "transport-kill"

	// minHeartbeatInterval / maxHeartbeatInterval clamp the server-announced
	// heartbeat interval before it drives the local watchdog, so a corrupt or
	// hostile announcement can neither spin the agent (too small) nor disable
	// liveness detection (too large).
	minHeartbeatInterval = time.Second
	maxHeartbeatInterval = 5 * time.Minute

	// helloCertFingerprintUnavailable / helloAttestationPlaceholder are the
	// honest T-3 advisory values: the HMAC-mode agent has no mTLS leaf to
	// fingerprint and no live attestation evidence (both T-4). AgentHello is
	// advisory-only — the broker re-derives every authoritative fact — but
	// its decoder requires non-blank text, so the placeholders are explicit
	// rather than empty. The base64 decodes to "t3-idle-no-attestation".
	helloCertFingerprintUnavailable = "unavailable"
	helloAttestationPlaceholder     = "dDMtaWRsZS1uby1hdHRlc3RhdGlvbg=="

	// maxAttestationEvidenceB64Len bounds the configured evidence blob before
	// it is copied into every AgentHello. The live broker re-verifies the
	// content; this guard catches obvious operator/config mistakes locally.
	maxAttestationEvidenceB64Len = 16 * 1024
)

// Config parameterises the harness. Zero values take the documented
// defaults; BrokerAddr (or a Dialer override) and DeviceIDProvider are
// mandatory.
type Config struct {
	// BrokerAddr is the gRPC target (host:port) of the broker.
	BrokerAddr string
	// DeviceIDProvider returns the enrolled device id, or "" while the agent
	// has no identity yet. The harness polls it and NEVER dials while it is
	// empty (no anonymous-ish streams).
	DeviceIDProvider func() string
	// AgentVersion is the advisory hello version string.
	AgentVersion string
	// InsecurePlaintext dials without TLS. Lab/loopback ONLY and ENFORCED:
	// New refuses an InsecurePlaintext config whose BrokerAddr is not a
	// loopback target (mirrors the broker's own non-loopback-plaintext
	// refusal), so the "loopback only" promise is machine-enforced, not just
	// documented. The default is TLS with system roots; real mTLS client
	// identity is T-4.
	InsecurePlaintext bool
	// TLSConfig optionally overrides the client TLS configuration used for the
	// broker connection. When PTYDispatcher is configured for real network use,
	// this MUST include client certificate material (Certificates or
	// GetClientCertificate), making operation-capable remote-ops outbound mTLS
	// rather than server-auth-only TLS. InsecureSkipVerify is always rejected.
	TLSConfig *tls.Config
	// AttestationEvidenceB64 optionally carries broker-verifiable provenance
	// evidence for AgentHello. Empty keeps the explicit T-3 placeholder. The
	// agent never receives or uses the signing private key; callers provide
	// only the already-signed, standard-base64 evidence blob.
	AttestationEvidenceB64 string
	// FirstHeartbeatDeadline bounds how long a fresh stream may stay silent
	// before the harness treats the connection as dead (default 15s).
	FirstHeartbeatDeadline time.Duration
	// HeartbeatMissFactor times the server-announced interval gives the
	// steady-state watchdog timeout (default 3).
	HeartbeatMissFactor int
	// BackoffMin/BackoffMax bound the jittered exponential reconnect backoff
	// (defaults 1s / 5m, ×2 growth, ±20% jitter, reset on a healthy stream —
	// healthy = at least one valid heartbeat observed).
	BackoffMin time.Duration
	BackoffMax time.Duration
	// IdentityPollInterval is the wait cadence while DeviceIDProvider returns
	// "" (default 5s).
	IdentityPollInterval time.Duration
	// DialTimeout caps a single transport connect attempt (default 10s).
	DialTimeout time.Duration
	// Dialer overrides the gRPC connection factory (bufconn test seam). When
	// set, BrokerAddr is not required AND the insecure-plaintext loopback guard
	// is bypassed (in-process, no real network). MUST remain test/in-process
	// only — production wiring (internal/app) never sets it; a real-network
	// Dialer would inherit this bypass.
	Dialer func(ctx context.Context) (*grpc.ClientConn, error)
	// PTYDispatcher, when non-nil, ENABLES CONSTRAINED_PTY operation handling:
	// an inbound operation_dispatch is decoded + executed + its output streamed
	// on a fresh per-operation DATA stream. nil (the default) keeps the harness
	// idle — an inbound operation_dispatch is a protocol defect (disabled-by-
	// default; LIVE activation is owner-gated, ADR-0034 §13/D10).
	PTYDispatcher PTYDispatcher
	// ConsentResponder, when non-nil, may answer a broker ConsentPrompt with a
	// ConsentResult. nil keeps the idle harness fail-closed: consent_prompt is a
	// protocol defect unless an owner-gated product path explicitly wires a
	// responder.
	ConsentResponder ConsentResponder
}

// ConsentResponder is the endpoint-side policy hook for broker consent prompts.
// It is intentionally absent by default; production UI/attended consent and
// bounded pilot auto-consent must opt in through app-level config.
type ConsentResponder func(ctx context.Context, prompt *pb.ConsentPrompt) (*pb.ConsentResult, error)

func (c Config) withDefaults() Config {
	if c.FirstHeartbeatDeadline <= 0 {
		c.FirstHeartbeatDeadline = 15 * time.Second
	}
	if c.HeartbeatMissFactor <= 0 {
		c.HeartbeatMissFactor = 3
	}
	if c.BackoffMin <= 0 {
		c.BackoffMin = time.Second
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = 5 * time.Minute
	}
	if c.BackoffMax < c.BackoffMin {
		c.BackoffMax = c.BackoffMin
	}
	if c.IdentityPollInterval <= 0 {
		c.IdentityPollInterval = 5 * time.Second
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 10 * time.Second
	}
	return c
}

// SessionState records a KILL-obeyed session. T-3 has no live sessions; the
// table exists so a kill is observable (audit + tests) and so T-4 inherits
// the obey semantics.
type SessionState struct {
	Killed     bool
	KillReason string
	KilledAt   time.Time
}

// Harness owns the reconnect loop for ONE broker. Construct with New, drive
// with Run (blocking; returns when ctx ends).
type Harness struct {
	cfg    Config
	logger *log.Logger

	mu       sync.Mutex
	sessions map[string]SessionState

	connects int64 // streams that reached AgentHello
	healthy  int64 // streams that saw >=1 valid heartbeat
	kills    int64 // kill envelopes obeyed
	defects  int64 // protocol defects that closed a stream
}

// New validates the config. It refuses a config that could only produce
// anonymous or undialable streams.
func New(cfg Config, logger *log.Logger) (*Harness, error) {
	cfg = cfg.withDefaults()
	if cfg.Dialer == nil && strings.TrimSpace(cfg.BrokerAddr) == "" {
		return nil, errors.New("remote-bridge harness requires a broker address")
	}
	// Insecure plaintext is lab/loopback ONLY — enforce it, do not merely
	// document it. dial() would otherwise hand any BrokerAddr to
	// insecure.NewCredentials(), sending gRPC in cleartext over the network
	// against what the config comment promises. The broker refuses
	// non-loopback plaintext server-side; this is the matching client-side
	// fail-closed. (A Dialer override is the in-process bufconn test seam — no
	// real network dial — so the guard does not apply there.)
	if cfg.Dialer == nil && cfg.InsecurePlaintext && !isLoopbackBrokerAddr(cfg.BrokerAddr) {
		return nil, fmt.Errorf("remote-bridge harness refuses insecure plaintext to non-loopback broker %q "+
			"(insecure plaintext is lab/loopback only; use TLS for any remote broker)", cfg.BrokerAddr)
	}
	if cfg.Dialer == nil && cfg.TLSConfig != nil && cfg.TLSConfig.InsecureSkipVerify {
		return nil, errors.New("remote-bridge harness refuses TLS config with InsecureSkipVerify")
	}
	if err := validateAttestationEvidenceB64(cfg.AttestationEvidenceB64); err != nil {
		return nil, err
	}
	if cfg.Dialer == nil && cfg.PTYDispatcher != nil {
		if cfg.InsecurePlaintext {
			return nil, errors.New("remote-bridge operation dispatch requires TLS/mTLS; plaintext dispatch is test-only")
		}
		if !hasClientCertificateMaterial(cfg.TLSConfig) {
			return nil, errors.New("remote-bridge operation dispatch requires outbound mTLS client certificate")
		}
	}
	if cfg.DeviceIDProvider == nil {
		return nil, errors.New("remote-bridge harness requires a device id provider")
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Harness{cfg: cfg, logger: logger, sessions: make(map[string]SessionState)}, nil
}

// isLoopbackBrokerAddr reports whether addr targets a loopback interface — the
// ONLY destination for which InsecurePlaintext (no TLS) is permitted. Decided
// deterministically from the LITERAL address with NO DNS resolution (a name
// could resolve to a different host at dial time — TOCTOU): the literal
// "localhost" or an IP that parses as loopback. A hostname or a non-loopback
// IP is rejected (fail-closed), mirroring the broker's server-side
// non-loopback-plaintext refusal. NOTE (Codex review): the literal "localhost"
// is accepted for lab ergonomics; it resolves via the local resolver at dial
// time, so a hosts-file-poisoned "localhost" is a theoretical bypass — a
// stricter posture (post-pilot) would accept only IP literals.
func isLoopbackBrokerAddr(addr string) bool {
	addr = strings.TrimSpace(addr)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No "host:port" form (e.g. a bare host) — treat the whole string as host.
		host = addr
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Run drives the connect/reconnect loop until ctx is cancelled. It never
// returns a non-ctx error: every stream failure is absorbed into backoff.
func (h *Harness) Run(ctx context.Context) {
	backoff := h.cfg.BackoffMin
	for {
		deviceID := strings.TrimSpace(h.cfg.DeviceIDProvider())
		if deviceID == "" {
			// No identity yet — wait, NEVER dial (Codex T-3 revision #2).
			if !sleepCtx(ctx, h.cfg.IdentityPollInterval) {
				return
			}
			continue
		}

		healthy, err := h.connectOnce(ctx, deviceID)
		if ctx.Err() != nil {
			return
		}
		if healthy {
			backoff = h.cfg.BackoffMin
		} else {
			backoff = nextBackoff(backoff, h.cfg.BackoffMin, h.cfg.BackoffMax)
		}
		if err != nil {
			h.logger.Printf("remote-bridge: stream ended: %v (reconnect in ~%s)", err, backoff)
		}
		if !sleepCtx(ctx, jitter(backoff)) {
			return
		}
	}
}

// errTransportKilled marks a broker-initiated transport-scoped kill; the
// stream is gone by design, reconnect follows the NORMAL backoff path
// (Codex T-3 Q2: a forced max backoff would punish broker-side rotation).
var errTransportKilled = errors.New("transport killed by broker")

// connectOnce runs one full stream lifetime: dial → CONTROL stream →
// AgentHello → obey loop. healthy reports whether at least one valid
// heartbeat arrived (backoff reset signal).
func (h *Harness) connectOnce(ctx context.Context, deviceID string) (healthy bool, err error) {
	// DialTimeout is a REAL cap on the whole connect phase (Codex 019ebb18
	// P2): grpc.NewClient is lazy and ConnectParams.MinConnectTimeout is a
	// minimum, not a maximum — without this bound an unreachable/wedged
	// broker would park the harness outside its tested reconnect/backoff
	// path. The custom Dialer seam gets the same bounded context.
	dctx, dcancel := context.WithTimeout(ctx, h.cfg.DialTimeout)
	defer dcancel()
	conn, err := h.dial(dctx)
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.Connect()
	for {
		st := conn.GetState()
		if st == connectivity.Ready {
			break
		}
		if !conn.WaitForStateChange(dctx, st) {
			return false, fmt.Errorf("broker not reachable within %s", h.cfg.DialTimeout)
		}
	}

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := pb.NewRemoteBridgeClient(conn).Connect(sctx)
	if err != nil {
		return false, fmt.Errorf("open control stream: %w", err)
	}

	sender := &controlSender{stream: stream}
	if err := sender.sendHello(&pb.AgentHello{
		AgentVersion:           h.cfg.AgentVersion,
		DeviceId:               deviceID,
		CertFingerprint:        helloCertFingerprint(h.cfg.TLSConfig),
		AttestationEvidenceB64: configuredAttestationEvidenceB64(h.cfg),
		ProtocolVersion:        ProtocolVersion,
		AdvertisedCapabilities: advertisedCapabilities(h.cfg),
	}); err != nil {
		return false, fmt.Errorf("send agent hello: %w", err)
	}
	h.mu.Lock()
	h.connects++
	h.mu.Unlock()

	// Watchdog: the missed-heartbeat / idle-timeout policy T-2b left to the
	// agent. Bounded silence on a fresh stream, then interval×missFactor.
	watchdog := time.NewTimer(h.cfg.FirstHeartbeatDeadline)
	defer watchdog.Stop()

	recvCh := make(chan recvResult, 1)
	go recvLoop(stream, recvCh)

	var seqGuard inboundSeqGuard // forward-compatible mode guard (see handleInbound)
	for {
		select {
		case <-ctx.Done():
			return healthy, ctx.Err()
		case <-watchdog.C:
			return healthy, errors.New("heartbeat watchdog expired")
		case r := <-recvCh:
			if r.err != nil {
				if errors.Is(r.err, io.EOF) {
					return healthy, errors.New("broker closed the control stream")
				}
				return healthy, fmt.Errorf("control recv: %w", r.err)
			}
			action, defectReason := h.handleInbound(r.env, &seqGuard)
			switch action {
			case actionContinue:
				// nothing to do — recvLoop pipelines the next frame
			case actionHeartbeat:
				interval := clampInterval(time.Duration(r.env.GetHeartbeat().GetHeartbeatIntervalMillis()) * time.Millisecond)
				resetTimer(watchdog, interval*time.Duration(h.cfg.HeartbeatMissFactor))
				if !healthy {
					healthy = true
					h.mu.Lock()
					h.healthy++
					h.mu.Unlock()
				}
			case actionTransportKill:
				return healthy, errTransportKilled
			case actionDispatch:
				// A broker-authorized CONSTRAINED_PTY operation. Decode SYNCHRONOUSLY (a malformed broker
				// frame is a protocol defect → close the stream), then execute + stream the output OFF the
				// recv loop so a long-running command never blocks heartbeats or a KILL.
				permit, commandLine, derr := decodeDispatch(r.env.GetOperationDispatch())
				if derr != nil {
					h.mu.Lock()
					h.defects++
					h.mu.Unlock()
					_ = sender.sendError(derr.Error(), false)
					_ = stream.CloseSend()
					return healthy, fmt.Errorf("protocol defect: %s", derr.Error())
				}
				go h.dispatchOperation(sctx, conn, permit, commandLine, deviceID, sender)
			case actionConsentPrompt:
				go h.respondToConsent(sctx, r.env.GetConsentPrompt(), sender)
			case actionDefectClose:
				h.mu.Lock()
				h.defects++
				h.mu.Unlock()
				// Best-effort structured error so the broker sees WHY, then
				// close. ErrorFrame is on the agent-allowed outbound set.
				_ = sender.sendError(defectReason, false)
				_ = stream.CloseSend()
				return healthy, fmt.Errorf("protocol defect: %s", defectReason)
			}
		}
	}
}

func (h *Harness) dial(ctx context.Context) (*grpc.ClientConn, error) {
	if h.cfg.Dialer != nil {
		return h.cfg.Dialer(ctx)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if h.cfg.TLSConfig != nil {
		tlsConfig = h.cfg.TLSConfig.Clone()
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	if tlsConfig.InsecureSkipVerify {
		return nil, errors.New("remote-bridge refuses TLS config with InsecureSkipVerify")
	}
	creds := credentials.NewTLS(tlsConfig)
	if h.cfg.InsecurePlaintext {
		// Defense-in-depth (Codex review): New already refuses InsecurePlaintext
		// to a non-loopback broker, but re-assert at the actual transport point
		// so the no-cleartext-to-remote invariant holds regardless of how the
		// Harness was constructed (a future intra-package caller or test). Run
		// absorbs this error into backoff; it can never fire via New.
		if !isLoopbackBrokerAddr(h.cfg.BrokerAddr) {
			return nil, fmt.Errorf("remote-bridge refuses insecure plaintext to non-loopback broker %q", h.cfg.BrokerAddr)
		}
		creds = insecure.NewCredentials()
	}
	return grpc.NewClient(h.cfg.BrokerAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithConnectParams(grpc.ConnectParams{MinConnectTimeout: h.cfg.DialTimeout}),
	)
}

func hasClientCertificateMaterial(cfg *tls.Config) bool {
	return cfg != nil && (len(cfg.Certificates) > 0 || cfg.GetClientCertificate != nil)
}

type inboundAction int

const (
	actionContinue inboundAction = iota
	actionHeartbeat
	actionTransportKill
	actionDefectClose
	// actionDispatch: a broker-authorized CONSTRAINED_PTY operation_dispatch arrived and a PTY dispatcher is
	// wired — connectOnce decodes it and runs it off the recv loop. Without a dispatcher this never occurs
	// (handleInbound defect-closes operation_dispatch — disabled-by-default).
	actionDispatch
	actionConsentPrompt
)

// inboundSeqGuard tracks the broker-push sequencing mode of one stream. The
// T-2b broker does NOT stamp its outbound pushes (they all carry the proto3
// default 0), so strict contiguity would break against the live broker. The
// forward-compatible rule (Codex T-3 revision #4 + mixed-mode tightening):
// a stream starts in unsequenced-legacy mode where ONLY 0 is accepted; the
// first positive seq switches the stream to sequenced mode permanently —
// from then on every frame must carry a strictly-increasing positive seq (a
// repeat/rewind is a replayed frame, and a 0 after sequenced mode is a mode
// regression). Both close the stream.
type inboundSeqGuard struct {
	sequenced bool
	last      int64
}

// admit validates one frame's seq; non-empty reason = defect.
func (g *inboundSeqGuard) admit(seq int64) string {
	switch {
	case seq < 0:
		return "negative-frame-seq"
	case seq == 0:
		if g.sequenced {
			return "frame-seq-mode-regression"
		}
		return ""
	default:
		if g.sequenced && seq <= g.last {
			return "frame-seq-replay"
		}
		g.sequenced = true
		g.last = seq
		return ""
	}
}

// handleInbound validates ONE broker envelope and dispatches it. The agent
// mirrors the broker's directional discipline: on the CONTROL stream it
// accepts only what the broker legitimately pushes while idle — heartbeat,
// kill, error, and consent_prompt only when a responder is explicitly wired.
// Everything else (operation_permit, the
// operator-console payloads, data_frame, a reflected agent_hello…) is a
// protocol defect: T-3 has no machinery to honour them, and silently
// consuming them would hide a broker bug or a premature enablement
// (Codex T-3 revision #3 — defect-close, not inert-log).
func (h *Harness) handleInbound(env *pb.Envelope, seqGuard *inboundSeqGuard) (inboundAction, string) {
	if env == nil {
		return actionDefectClose, "nil-envelope"
	}
	if env.GetChannelType() != pb.ChannelType_CONTROL {
		return actionDefectClose, "non-control-channel"
	}
	if reason := seqGuard.admit(env.GetFrameSeq()); reason != "" {
		return actionDefectClose, reason
	}

	switch {
	case env.GetHeartbeat() != nil:
		if env.GetHeartbeat().GetHeartbeatIntervalMillis() <= 0 {
			return actionDefectClose, "heartbeat-invalid-interval"
		}
		return actionHeartbeat, ""
	case env.GetKill() != nil:
		kill := env.GetKill()
		h.obeyKill(kill.GetSessionId(), kill.GetKillReason())
		if kill.GetSessionId() == TransportKillSessionID {
			return actionTransportKill, ""
		}
		// Session-scoped kill: the session state is dead, the transport
		// stays up (the broker decides stream lifetime).
		return actionContinue, ""
	case env.GetError() != nil:
		h.logger.Printf("remote-bridge: broker error frame code=%q retryable=%v",
			env.GetError().GetCode(), env.GetError().GetRetryable())
		return actionContinue, ""
	case env.GetConsentPrompt() != nil:
		if h.cfg.ConsentResponder == nil {
			return actionDefectClose, "unsupported-payload-in-idle"
		}
		return actionConsentPrompt, ""
	case env.GetOperationDispatch() != nil:
		// A CONSTRAINED_PTY operation push (T-4). DISABLED-BY-DEFAULT: with no PTY dispatcher wired the agent
		// has no execution machinery, so — like any other broker payload in idle mode — it is a protocol
		// defect. When a dispatcher IS configured, connectOnce decodes + executes it off the recv loop.
		if h.cfg.PTYDispatcher == nil {
			return actionDefectClose, "unsupported-payload-in-idle"
		}
		return actionDispatch, ""
	default:
		return actionDefectClose, "unsupported-payload-in-idle"
	}
}

func (h *Harness) respondToConsent(ctx context.Context, prompt *pb.ConsentPrompt, sender *controlSender) {
	if prompt == nil {
		_ = sender.sendError("nil-consent-prompt", false)
		return
	}
	result, err := h.cfg.ConsentResponder(ctx, prompt)
	if err != nil {
		h.logger.Printf("remote-bridge: consent responder failed session=%q err=%v", prompt.GetSessionId(), err)
		_ = sender.sendError("consent-responder-failed", false)
		return
	}
	if result == nil {
		_ = sender.sendError("consent-responder-empty-result", false)
		return
	}
	if result.GetSessionId() != prompt.GetSessionId() {
		_ = sender.sendError("consent-result-session-mismatch", false)
		return
	}
	if err := sender.sendConsentResult(result); err != nil {
		h.logger.Printf("remote-bridge: send consent result failed session=%q err=%v", result.GetSessionId(), err)
	}
}

func advertisedCapabilities(cfg Config) []pb.Capability {
	if cfg.PTYDispatcher == nil {
		return nil
	}
	return []pb.Capability{pb.Capability_CONSTRAINED_PTY}
}

func helloCertFingerprint(cfg *tls.Config) string {
	if cfg == nil || len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
		return helloCertFingerprintUnavailable
	}
	sum := sha256.Sum256(cfg.Certificates[0].Certificate[0])
	return hex.EncodeToString(sum[:])
}

func configuredAttestationEvidenceB64(cfg Config) string {
	value := strings.TrimSpace(cfg.AttestationEvidenceB64)
	if value == "" {
		return helloAttestationPlaceholder
	}
	return value
}

func validateAttestationEvidenceB64(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil
	}
	if len(value) > maxAttestationEvidenceB64Len {
		return fmt.Errorf("remote-bridge attestation evidence exceeds %d bytes", maxAttestationEvidenceB64Len)
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return errors.New("remote-bridge attestation evidence must be single-line standard base64")
	}
	if _, err := base64.StdEncoding.DecodeString(value); err != nil {
		return fmt.Errorf("remote-bridge attestation evidence must be valid standard base64: %w", err)
	}
	return nil
}

// obeyKill terminates local session state immediately. T-3 keeps no live
// sessions, so "terminate" = record the killed state (sub-second by
// construction: this runs synchronously in the recv path, before any other
// frame is looked at).
func (h *Harness) obeyKill(sessionID, reason string) {
	if reason == "" {
		reason = "killed"
	}
	h.mu.Lock()
	h.sessions[sessionID] = SessionState{Killed: true, KillReason: reason, KilledAt: time.Now()}
	h.kills++
	h.mu.Unlock()
}

// Session returns the recorded state for a session id.
func (h *Harness) Session(id string) (SessionState, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[id]
	return s, ok
}

// Counters returns (streams connected, streams that turned healthy, kills
// obeyed, defect closes) — test/observability snapshot.
func (h *Harness) Counters() (connects, healthy, kills, defects int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.connects, h.healthy, h.kills, h.defects
}

type recvResult struct {
	env *pb.Envelope
	err error
}

// recvLoop pipelines stream frames into out. It exits on the first stream
// error; the stream-context select keeps it from leaking when the consumer
// has already abandoned the stream (defect-close path).
func recvLoop(stream pb.RemoteBridge_ConnectClient, out chan<- recvResult) {
	for {
		env, err := stream.Recv()
		select {
		case out <- recvResult{env: env, err: err}:
		case <-stream.Context().Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

func clampInterval(d time.Duration) time.Duration {
	if d < minHeartbeatInterval {
		return minHeartbeatInterval
	}
	if d > maxHeartbeatInterval {
		return maxHeartbeatInterval
	}
	return d
}

// nextBackoff doubles toward hi (pure, unit-tested).
func nextBackoff(cur, lo, hi time.Duration) time.Duration {
	next := cur * 2
	if next > hi {
		next = hi
	}
	if next < lo {
		next = lo
	}
	return next
}

// jitter spreads a delay ±20% so a broker restart does not see a synchronized
// reconnect stampede.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	f := 0.8 + 0.4*rand.Float64()
	return time.Duration(float64(d) * f)
}
