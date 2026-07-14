package harness

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "platform-agent/internal/remotebridge/pb"
)

// fakeBroker scripts the server side of the CONTROL stream over bufconn —
// in-process, no listening socket on any real interface.
type fakeBroker struct {
	pb.UnimplementedRemoteBridgeServer
	script func(stream pb.RemoteBridge_ConnectServer) error
}

func (f *fakeBroker) Connect(stream pb.RemoteBridge_ConnectServer) error {
	return f.script(stream)
}

type fixture struct {
	h     *Harness
	dials *atomic.Int64
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// start spins a bufconn broker + a running harness. The returned dials
// counter counts harness connect ATTEMPTS (the Dialer seam), which is the
// reconnect observable.
func start(t *testing.T, script func(stream pb.RemoteBridge_ConnectServer) error, mutate func(*Config)) fixture {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterRemoteBridgeServer(srv, &fakeBroker{script: script})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	dials := &atomic.Int64{}
	cfg := Config{
		DeviceIDProvider:       func() string { return "device-test" },
		AgentVersion:           "0.0.0-test",
		FirstHeartbeatDeadline: 2 * time.Second,
		BackoffMin:             10 * time.Millisecond,
		BackoffMax:             50 * time.Millisecond,
		IdentityPollInterval:   10 * time.Millisecond,
		Dialer: func(ctx context.Context) (*grpc.ClientConn, error) {
			dials.Add(1)
			return grpc.NewClient("passthrough:///bufnet",
				grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
					return lis.DialContext(ctx)
				}),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	h, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.Run(ctx)
	return fixture{h: h, dials: dials}
}

func TestRunLogsIdentityWaitReadyAndDialWithoutRawDeviceID(t *testing.T) {
	var deviceID atomic.Value
	deviceID.Store("")

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterRemoteBridgeServer(srv, &fakeBroker{script: func(stream pb.RemoteBridge_ConnectServer) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	}})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	dials := &atomic.Int64{}
	logs := &lockedBuffer{}
	cfg := Config{
		BrokerAddr:             "broker.test:9444",
		DeviceIDProvider:       func() string { return deviceID.Load().(string) },
		AgentVersion:           "0.0.0-test",
		FirstHeartbeatDeadline: 2 * time.Second,
		BackoffMin:             10 * time.Millisecond,
		BackoffMax:             50 * time.Millisecond,
		IdentityPollInterval:   10 * time.Millisecond,
		Dialer: func(ctx context.Context) (*grpc.ClientConn, error) {
			dials.Add(1)
			return grpc.NewClient("passthrough:///bufnet",
				grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
					return lis.DialContext(ctx)
				}),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
		},
	}
	h, err := New(cfg, log.New(logs, "", 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.Run(ctx)

	waitFor(t, time.Second, "identity wait log", func() bool {
		return strings.Contains(logs.String(), "remote-bridge: waiting for device identity")
	})
	if got := dials.Load(); got != 0 {
		t.Fatalf("dials before device identity = %d, want 0", got)
	}

	deviceID.Store("device-late")
	wantFingerprint := deviceIDFingerprint("device-late")
	waitFor(t, time.Second, "identity ready + dial logs", func() bool {
		logText := logs.String()
		return strings.Contains(logText, "remote-bridge: device identity ready device_id_sha256_12="+wantFingerprint) &&
			strings.Contains(logText, "remote-bridge: dialing broker broker_addr=\"broker.test:9444\" device_id_sha256_12="+wantFingerprint)
	})
	if strings.Contains(logs.String(), "device-late") {
		t.Fatalf("remote-bridge logs leaked raw device id: %s", logs.String())
	}
}

func heartbeatEnv(intervalMillis, frameSeq int64) *pb.Envelope {
	return &pb.Envelope{
		ChannelType: pb.ChannelType_CONTROL,
		FrameSeq:    frameSeq,
		Payload: &pb.Envelope_Heartbeat{Heartbeat: &pb.Heartbeat{
			HeartbeatIntervalMillis: intervalMillis,
			ProtocolVersion:         ProtocolVersion,
		}},
	}
}

func killEnv(sessionID, reason string) *pb.Envelope {
	return &pb.Envelope{
		ChannelType: pb.ChannelType_CONTROL,
		SessionId:   sessionID,
		Payload: &pb.Envelope_Kill{Kill: &pb.Kill{
			SessionId:           sessionID,
			KillReason:          reason,
			IssuedAtEpochMillis: time.Now().UnixMilli(),
		}},
	}
}

func consentPromptEnv() *pb.Envelope {
	return &pb.Envelope{
		ChannelType: pb.ChannelType_CONTROL,
		Payload: &pb.Envelope_ConsentPrompt{ConsentPrompt: &pb.ConsentPrompt{
			SessionId:           "sess-early",
			OperatorDisplayName: "op",
		}},
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestConfiguredAttestationEvidenceIsSentInHello(t *testing.T) {
	configured := base64.StdEncoding.EncodeToString([]byte("digest|builder|policy|signature"))
	hellos := make(chan *pb.Envelope, 1)
	script := func(s pb.RemoteBridge_ConnectServer) error {
		env, err := s.Recv()
		if err != nil {
			return err
		}
		hellos <- env
		return io.EOF
	}
	start(t, script, func(cfg *Config) {
		cfg.AttestationEvidenceB64 = configured
	})

	select {
	case env := <-hellos:
		if got := env.GetAgentHello().GetAttestationEvidenceB64(); got != configured {
			t.Fatalf("attestation evidence %q, want configured value", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no AgentHello within 3s")
	}
}

func TestConfiguredPTYDispatcherAdvertisesConstrainedPTY(t *testing.T) {
	hellos := make(chan *pb.Envelope, 1)
	script := func(s pb.RemoteBridge_ConnectServer) error {
		env, err := s.Recv()
		if err != nil {
			return err
		}
		hellos <- env
		return io.EOF
	}
	start(t, script, func(cfg *Config) {
		cfg.PTYDispatcher = noopPTYDispatcher{}
	})

	select {
	case env := <-hellos:
		caps := env.GetAgentHello().GetAdvertisedCapabilities()
		if len(caps) != 1 || caps[0] != pb.Capability_CONSTRAINED_PTY {
			t.Fatalf("advertised capabilities = %v, want [CONSTRAINED_PTY]", caps)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no AgentHello within 3s")
	}
}

func TestNewRejectsMalformedConfiguredAttestationEvidence(t *testing.T) {
	_, err := New(Config{
		BrokerAddr:             "localhost:8443",
		DeviceIDProvider:       func() string { return "device" },
		InsecurePlaintext:      true,
		AttestationEvidenceB64: "not base64",
		FirstHeartbeatDeadline: time.Second,
		HeartbeatMissFactor:    3,
	}, log.New(io.Discard, "", 0))
	if err == nil {
		t.Fatal("New accepted malformed attestation evidence")
	}
}

// TestHelloFirstSeqContiguousAndDefectClose covers the contract test: the
// FIRST outbound frame is AgentHello at frameSeq 0 on CONTROL with the
// advisory fields populated and capabilities empty; a broker-authoritative
// payload (consent_prompt) while idle triggers an ErrorFrame at the NEXT
// contiguous seq (1) and a stream close (Codex T-3 revision #3).
func TestHelloFirstSeqContiguousAndDefectClose(t *testing.T) {
	hellos := make(chan *pb.Envelope, 16)
	agentFrames := make(chan *pb.Envelope, 16)
	closes := make(chan error, 16)
	script := func(s pb.RemoteBridge_ConnectServer) error {
		env, err := s.Recv()
		if err != nil {
			return err
		}
		hellos <- env
		_ = s.Send(heartbeatEnv(60_000, 0))
		_ = s.Send(consentPromptEnv())
		for {
			frame, err := s.Recv()
			if err != nil {
				closes <- err
				return nil
			}
			agentFrames <- frame
		}
	}
	fx := start(t, script, nil)

	var hello *pb.Envelope
	select {
	case hello = <-hellos:
	case <-time.After(3 * time.Second):
		t.Fatal("no AgentHello within 3s")
	}
	if hello.GetAgentHello() == nil {
		t.Fatalf("first frame is %T, want AgentHello", hello.GetPayload())
	}
	if hello.GetChannelType() != pb.ChannelType_CONTROL {
		t.Errorf("hello channel %v, want CONTROL", hello.GetChannelType())
	}
	if hello.GetFrameSeq() != 0 {
		t.Errorf("hello frameSeq %d, want 0", hello.GetFrameSeq())
	}
	ah := hello.GetAgentHello()
	if ah.GetDeviceId() != "device-test" {
		t.Errorf("hello deviceId %q", ah.GetDeviceId())
	}
	if ah.GetProtocolVersion() != ProtocolVersion {
		t.Errorf("hello protocolVersion %q, want %q", ah.GetProtocolVersion(), ProtocolVersion)
	}
	if ah.GetAgentVersion() == "" || ah.GetCertFingerprint() == "" || ah.GetAttestationEvidenceB64() == "" {
		t.Error("advisory hello text fields must be non-blank (broker decode requires them)")
	}
	if len(ah.GetAdvertisedCapabilities()) != 0 {
		t.Errorf("idle harness advertised %v, want none", ah.GetAdvertisedCapabilities())
	}

	var errFrame *pb.Envelope
	select {
	case errFrame = <-agentFrames:
	case <-time.After(3 * time.Second):
		t.Fatal("no defect ErrorFrame within 3s")
	}
	if errFrame.GetError() == nil {
		t.Fatalf("agent frame is %T, want ErrorFrame", errFrame.GetPayload())
	}
	if got := errFrame.GetError().GetCode(); got != "unsupported-payload-in-idle" {
		t.Errorf("defect code %q", got)
	}
	if errFrame.GetFrameSeq() != 1 {
		t.Errorf("error frameSeq %d, want 1 (contiguous after hello)", errFrame.GetFrameSeq())
	}
	if errFrame.GetChannelType() != pb.ChannelType_CONTROL {
		t.Errorf("error channel %v, want CONTROL", errFrame.GetChannelType())
	}
	select {
	case err := <-closes:
		// The agent half-closes (CloseSend) and then tears the conn down;
		// depending on which the server observes first this surfaces as
		// io.EOF or a Canceled status — both prove the defective stream
		// ENDED, which is the invariant under test.
		if err == nil {
			t.Error("agent close err nil, want a terminal stream error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not close the defective stream")
	}
	waitFor(t, time.Second, "defect counter", func() bool {
		_, _, _, defects := fx.h.Counters()
		return defects >= 1
	})
}

func TestConfiguredConsentResponderSendsConsentResult(t *testing.T) {
	agentFrames := make(chan *pb.Envelope, 16)
	script := func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(heartbeatEnv(60_000, 0))
		_ = s.Send(&pb.Envelope{
			ChannelType: pb.ChannelType_CONTROL,
			Payload: &pb.Envelope_ConsentPrompt{ConsentPrompt: &pb.ConsentPrompt{
				SessionId:           "sess-consent",
				OperatorDisplayName: "pilot-operator",
				Capabilities:        []pb.Capability{pb.Capability_CONSTRAINED_PTY},
				ExpiryEpochMillis:   time.Now().Add(time.Minute).UnixMilli(),
			}},
		})
		frame, err := s.Recv()
		if err != nil {
			return err
		}
		agentFrames <- frame
		return io.EOF
	}
	start(t, script, func(cfg *Config) {
		cfg.ConsentResponder = func(ctx context.Context, prompt *pb.ConsentPrompt) (*pb.ConsentResult, error) {
			return &pb.ConsentResult{
				SessionId:                 prompt.GetSessionId(),
				Granted:                   true,
				WindowsInteractiveSession: "pilot-auto-consent",
				GrantedAtEpochMillis:      time.Now().UnixMilli(),
				ExpiryEpochMillis:         prompt.GetExpiryEpochMillis(),
			}, nil
		}
	})

	var result *pb.Envelope
	select {
	case result = <-agentFrames:
	case <-time.After(3 * time.Second):
		t.Fatal("no ConsentResult within 3s")
	}
	if result.GetConsentResult() == nil {
		t.Fatalf("agent frame is %T, want ConsentResult", result.GetPayload())
	}
	if got := result.GetConsentResult().GetSessionId(); got != "sess-consent" {
		t.Fatalf("ConsentResult sessionId = %q", got)
	}
	if !result.GetConsentResult().GetGranted() {
		t.Fatal("ConsentResult granted=false, want true")
	}
	if result.GetFrameSeq() != 1 {
		t.Fatalf("ConsentResult frameSeq = %d, want 1", result.GetFrameSeq())
	}
}

// Faz 22.6 #548: a wired DeviceKeyResponder answers a broker DeviceKeyChallenge with a
// DeviceKeyAttestationResponse on CONTROL, echoing the session id (the broker correlates by it).
func TestConfiguredDeviceKeyResponderSendsAttestationResponse(t *testing.T) {
	agentFrames := make(chan *pb.Envelope, 16)
	const sid = "sess-dk"
	const cid = "00112233445566778899aabbccddeeff"
	script := func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(heartbeatEnv(60_000, 0))
		_ = s.Send(&pb.Envelope{
			ChannelType: pb.ChannelType_CONTROL,
			SessionId:   sid,
			Payload: &pb.Envelope_DeviceKeyChallenge{DeviceKeyChallenge: &pb.DeviceKeyChallenge{
				ChallengeId:          cid,
				NonceB64:             base64.StdEncoding.EncodeToString([]byte("broker-nonce-32-bytes-exactly!!!")),
				IssuedAtEpochMillis:  time.Now().UnixMilli(),
				ExpiresAtEpochMillis: time.Now().Add(3 * time.Minute).UnixMilli(),
				TransportPeerKey:     "ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
				ProtocolVersion:      "device-key-session-v1",
			}},
		})
		frame, err := s.Recv()
		if err != nil {
			return err
		}
		agentFrames <- frame
		return io.EOF
	}
	start(t, script, func(cfg *Config) {
		cfg.DeviceKeyResponder = func(_ context.Context, ch *pb.DeviceKeyChallenge, sessionID string) (*pb.DeviceKeyAttestationResponse, error) {
			// the harness only proves the wire seam; devkeysession.Respond (TPM-backed) is tested separately
			return &pb.DeviceKeyAttestationResponse{
				ChallengeId:         ch.GetChallengeId(),
				Schema:              "faz22.6.device-key-session.v1",
				DeviceKeyPubB64:     "AQ==",
				BindingContextB64:   base64.StdEncoding.EncodeToString([]byte(sessionID)),
				DeviceKeySigB64:     "AQ==",
				SignedAtEpochMillis: time.Now().UnixMilli(),
			}, nil
		}
	})

	var result *pb.Envelope
	select {
	case result = <-agentFrames:
	case <-time.After(3 * time.Second):
		t.Fatal("no DeviceKeyAttestationResponse within 3s")
	}
	if result.GetDeviceKeyAttestationResponse() == nil {
		t.Fatalf("agent frame is %T, want DeviceKeyAttestationResponse", result.GetPayload())
	}
	if got := result.GetSessionId(); got != sid {
		t.Fatalf("response envelope sessionId = %q, want %q", got, sid)
	}
	if got := result.GetDeviceKeyAttestationResponse().GetChallengeId(); got != cid {
		t.Fatalf("response challengeId = %q, want %q", got, cid)
	}
	if result.GetChannelType() != pb.ChannelType_CONTROL {
		t.Fatalf("response must be on CONTROL, got %v", result.GetChannelType())
	}
}

// Faz 22.6 #548: with NO DeviceKeyResponder wired (the default), an inbound DeviceKeyChallenge is a protocol
// defect — the agent sends an error frame (never a forged attestation) and closes the stream.
func TestDeviceKeyChallengeWithoutResponderIsAProtocolDefect(t *testing.T) {
	agentFrames := make(chan *pb.Envelope, 16)
	script := func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(heartbeatEnv(60_000, 0))
		_ = s.Send(&pb.Envelope{
			ChannelType: pb.ChannelType_CONTROL,
			SessionId:   "sess-dk",
			Payload: &pb.Envelope_DeviceKeyChallenge{DeviceKeyChallenge: &pb.DeviceKeyChallenge{
				ChallengeId: "00112233445566778899aabbccddeeff", ProtocolVersion: "device-key-session-v1",
			}},
		})
		for {
			frame, err := s.Recv()
			if err != nil {
				return err
			}
			agentFrames <- frame
		}
	}
	start(t, script, nil) // nil DeviceKeyResponder = default-off

	select {
	case frame := <-agentFrames:
		if frame.GetDeviceKeyAttestationResponse() != nil {
			t.Fatal("an unwired agent must NOT answer a device-key challenge")
		}
		if frame.GetError() == nil {
			t.Fatalf("expected an error frame for the unsupported payload, got %T", frame.GetPayload())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no defect/error frame within 3s")
	}
}

// TestKillObeySubSecond: a session-scoped kill mutates local session state
// in well under a second and does NOT tear down the transport.
func TestKillObeySubSecond(t *testing.T) {
	killSent := make(chan time.Time, 16)
	killApplied := make(chan *pb.AuditEvent, 1)
	script := func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(heartbeatEnv(60_000, 0))
		killSent <- time.Now()
		_ = s.Send(killEnv("sess-x", "policy-revoked"))
		for {
			env, err := s.Recv()
			if err != nil {
				return err
			}
			if event := env.GetAuditEvent(); event != nil && event.GetEventType() == "AGENT_KILL_APPLIED" {
				killApplied <- event
				<-s.Context().Done() // hold the stream open: session kill ≠ stream end
				return nil
			}
		}
	}
	fx := start(t, script, nil)

	var sentAt time.Time
	select {
	case sentAt = <-killSent:
	case <-time.After(3 * time.Second):
		t.Fatal("broker never sent the kill")
	}
	waitFor(t, time.Second, "session killed", func() bool {
		st, ok := fx.h.Session("sess-x")
		return ok && st.Killed
	})
	elapsed := time.Since(sentAt)
	if elapsed >= time.Second {
		t.Fatalf("kill obeyed in %s, want sub-second", elapsed)
	}
	st, _ := fx.h.Session("sess-x")
	if st.KillReason != "policy-revoked" {
		t.Errorf("kill reason %q", st.KillReason)
	}
	select {
	case event := <-killApplied:
		if event.GetSessionId() != "sess-x" {
			t.Fatalf("kill-applied session = %q, want sess-x", event.GetSessionId())
		}
		if len(event.GetContentHash()) != 64 || event.GetEpochMillis() <= 0 {
			t.Fatalf("kill-applied provenance missing: hash=%q epoch=%d",
				event.GetContentHash(), event.GetEpochMillis())
		}
	case <-time.After(time.Second):
		t.Fatal("session KILL was applied but no AGENT_KILL_APPLIED acknowledgement arrived")
	}
	// Transport must stay up after a session-scoped kill.
	time.Sleep(100 * time.Millisecond)
	if got := fx.dials.Load(); got != 1 {
		t.Errorf("dials after session kill = %d, want 1 (no reconnect)", got)
	}
	_, _, kills, _ := fx.h.Counters()
	if kills < 1 {
		t.Error("kill counter not incremented")
	}
}

// TestTransportKillClosesStreamAndReconnects: the "transport-kill" sentinel
// terminates the whole connection; the harness reconnects on the NORMAL
// backoff path (Codex T-3 Q2).
func TestTransportKillClosesStreamAndReconnects(t *testing.T) {
	script := func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(killEnv(TransportKillSessionID, "rotation"))
		return nil // broker completes after kill (sendAndClose semantics)
	}
	fx := start(t, script, nil)
	waitFor(t, 3*time.Second, "transport kill obeyed", func() bool {
		st, ok := fx.h.Session(TransportKillSessionID)
		return ok && st.Killed
	})
	waitFor(t, 3*time.Second, "reconnect after transport kill", func() bool {
		return fx.dials.Load() >= 2
	})
}

func TestRepeatedUnknownSessionKillsLeaveNoPendingAckState(t *testing.T) {
	h := &Harness{
		sessions:      make(map[string]SessionState),
		screenCancels: make(map[string]*screenCancelEntry),
		killAckReady:  make(map[string]<-chan struct{}),
	}
	for i := 0; i < 1000; i++ {
		sessionID := fmt.Sprintf("unknown-session-%d", i)
		h.obeyKill(sessionID, "stale-redelivery")
		select {
		case <-h.takeKillAckReady(sessionID):
		case <-time.After(time.Second):
			t.Fatalf("session %q did not expose an immediate no-screen ACK boundary", sessionID)
		}
	}
	h.mu.Lock()
	pending := len(h.killAckReady)
	h.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending kill ACK state leaked after repeated KILLs: %d", pending)
	}
}

// TestMissedFirstHeartbeatReconnects: a silent fresh stream trips the
// FirstHeartbeatDeadline watchdog and the harness redials with backoff —
// the agent-side idle policy T-2b deliberately left to T-3.
func TestMissedFirstHeartbeatReconnects(t *testing.T) {
	script := func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		<-s.Context().Done() // never send a heartbeat
		return nil
	}
	fx := start(t, script, func(c *Config) { c.FirstHeartbeatDeadline = 80 * time.Millisecond })
	waitFor(t, 5*time.Second, "watchdog-driven reconnects", func() bool {
		return fx.dials.Load() >= 3
	})
	_, healthy, _, _ := fx.h.Counters()
	if healthy != 0 {
		t.Errorf("healthy counter %d, want 0 (no heartbeat ever)", healthy)
	}
}

// TestSteadyStateMissedHeartbeatReconnects: after a valid heartbeat the
// watchdog re-arms at interval×missFactor; broker silence then forces a
// reconnect. Uses the minimum legal interval (1s clamp), so this test takes
// ~3s wall-clock by design.
func TestSteadyStateMissedHeartbeatReconnects(t *testing.T) {
	script := func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(heartbeatEnv(1_000, 0)) // 1s interval → watchdog 3s
		<-s.Context().Done()               // then silence
		return nil
	}
	fx := start(t, script, nil)
	waitFor(t, 2*time.Second, "stream healthy", func() bool {
		_, healthy, _, _ := fx.h.Counters()
		return healthy >= 1
	})
	waitFor(t, 6*time.Second, "steady-state watchdog reconnect", func() bool {
		return fx.dials.Load() >= 2
	})
}

// TestInboundSeqReplayDefectCloses: the broker today pushes unsequenced
// frames (seq 0, always accepted); once a POSITIVE seq appears it must
// strictly increase — a repeat is a replayed frame and closes the stream
// (Codex T-3 revision #4, forward-compatible form).
func TestInboundSeqReplayDefectCloses(t *testing.T) {
	codes := make(chan string, 16)
	script := func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(heartbeatEnv(60_000, 5))
		_ = s.Send(heartbeatEnv(60_000, 5)) // replay
		for {
			frame, err := s.Recv()
			if err != nil {
				return nil
			}
			if frame.GetError() != nil {
				codes <- frame.GetError().GetCode()
			}
		}
	}
	fx := start(t, script, nil)
	select {
	case code := <-codes:
		if code != "frame-seq-replay" {
			t.Errorf("defect code %q, want frame-seq-replay", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no replay defect ErrorFrame")
	}
	waitFor(t, 3*time.Second, "reconnect after replay defect", func() bool {
		return fx.dials.Load() >= 2
	})
}

// TestHeartbeatInvalidIntervalDefectCloses: a heartbeat without a positive
// interval cannot drive the watchdog — protocol defect.
func TestHeartbeatInvalidIntervalDefectCloses(t *testing.T) {
	codes := make(chan string, 16)
	script := func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(&pb.Envelope{
			ChannelType: pb.ChannelType_CONTROL,
			Payload:     &pb.Envelope_Heartbeat{Heartbeat: &pb.Heartbeat{}}, // interval 0
		})
		for {
			frame, err := s.Recv()
			if err != nil {
				return nil
			}
			if frame.GetError() != nil {
				codes <- frame.GetError().GetCode()
			}
		}
	}
	start(t, script, nil)
	select {
	case code := <-codes:
		if code != "heartbeat-invalid-interval" {
			t.Errorf("defect code %q", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no invalid-interval defect ErrorFrame")
	}
}

// TestNeverDialsWithoutDeviceID: an enabled harness with no enrolled
// identity must not produce a single dial (Codex T-3 revision #2); once the
// identity appears it connects and the hello carries it.
func TestNeverDialsWithoutDeviceID(t *testing.T) {
	var deviceID atomic.Value
	deviceID.Store("")
	hellos := make(chan *pb.Envelope, 16)
	script := func(s pb.RemoteBridge_ConnectServer) error {
		env, err := s.Recv()
		if err != nil {
			return err
		}
		hellos <- env
		_ = s.Send(heartbeatEnv(60_000, 0))
		<-s.Context().Done()
		return nil
	}
	fx := start(t, script, func(c *Config) {
		c.DeviceIDProvider = func() string { return deviceID.Load().(string) }
	})
	time.Sleep(150 * time.Millisecond)
	if got := fx.dials.Load(); got != 0 {
		t.Fatalf("harness dialed %d times without a device identity", got)
	}
	deviceID.Store("device-late")
	select {
	case hello := <-hellos:
		if hello.GetAgentHello().GetDeviceId() != "device-late" {
			t.Errorf("hello deviceId %q, want device-late", hello.GetAgentHello().GetDeviceId())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no hello after identity became available")
	}
}

// TestInboundSeqModeRegressionDefectCloses: once the broker has spoken in
// sequenced mode (a positive seq), a later unsequenced frame (seq 0) is a
// mode regression and closes the stream (Codex mixed-mode tightening).
func TestInboundSeqModeRegressionDefectCloses(t *testing.T) {
	codes := make(chan string, 16)
	script := func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(heartbeatEnv(60_000, 5)) // sequenced mode
		_ = s.Send(heartbeatEnv(60_000, 0)) // regression to unsequenced
		for {
			frame, err := s.Recv()
			if err != nil {
				return nil
			}
			if frame.GetError() != nil {
				codes <- frame.GetError().GetCode()
			}
		}
	}
	start(t, script, nil)
	select {
	case code := <-codes:
		if code != "frame-seq-mode-regression" {
			t.Errorf("defect code %q, want frame-seq-mode-regression", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no mode-regression defect ErrorFrame")
	}
}

// TestDialPhaseBoundedByDialTimeout: an unreachable/wedged broker (the
// transport never reaches Ready) must not park the harness outside its
// backoff loop — the connect phase is capped by DialTimeout (Codex 019ebb18
// P2) and redial continues.
func TestDialPhaseBoundedByDialTimeout(t *testing.T) {
	dials := &atomic.Int64{}
	blackHole := func(ctx context.Context) (*grpc.ClientConn, error) {
		dials.Add(1)
		return grpc.NewClient("passthrough:///black-hole",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				<-ctx.Done() // never produces a connection
				return nil, ctx.Err()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	}
	h, err := New(Config{
		DeviceIDProvider:     func() string { return "device-test" },
		DialTimeout:          50 * time.Millisecond,
		BackoffMin:           10 * time.Millisecond,
		BackoffMax:           30 * time.Millisecond,
		IdentityPollInterval: 10 * time.Millisecond,
		Dialer:               blackHole,
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.Run(ctx)
	waitFor(t, 5*time.Second, "redials despite a wedged broker", func() bool {
		return dials.Load() >= 3
	})
	_, healthy, _, _ := h.Counters()
	if healthy != 0 {
		t.Errorf("healthy %d, want 0", healthy)
	}
}

func TestInboundSeqGuardTable(t *testing.T) {
	cases := []struct {
		name string
		seqs []int64
		want []string
	}{
		{"legacy all-zero", []int64{0, 0, 0}, []string{"", "", ""}},
		{"sequenced strictly increasing", []int64{1, 2, 9}, []string{"", "", ""}},
		{"replay equal", []int64{5, 5}, []string{"", "frame-seq-replay"}},
		{"replay rewind", []int64{5, 3}, []string{"", "frame-seq-replay"}},
		{"mode regression", []int64{5, 0}, []string{"", "frame-seq-mode-regression"}},
		{"negative", []int64{-1}, []string{"negative-frame-seq"}},
		{"legacy then sequenced", []int64{0, 7, 8}, []string{"", "", ""}},
	}
	for _, c := range cases {
		var g inboundSeqGuard
		for i, seq := range c.seqs {
			if got := g.admit(seq); got != c.want[i] {
				t.Errorf("%s[%d]: admit(%d) = %q, want %q", c.name, i, seq, got, c.want[i])
			}
		}
	}
}

// --- pure-function and sender unit tests ---

func TestNextBackoff(t *testing.T) {
	lo, hi := time.Second, 5*time.Minute
	cases := []struct{ cur, want time.Duration }{
		{time.Second, 2 * time.Second},
		{2 * time.Second, 4 * time.Second},
		{4 * time.Minute, 5 * time.Minute}, // capped
		{5 * time.Minute, 5 * time.Minute}, // stays capped
		{0, lo},                            // floor
	}
	for _, c := range cases {
		if got := nextBackoff(c.cur, lo, hi); got != c.want {
			t.Errorf("nextBackoff(%s) = %s, want %s", c.cur, got, c.want)
		}
	}
}

func TestJitterBounds(t *testing.T) {
	d := 100 * time.Millisecond
	for i := 0; i < 1000; i++ {
		j := jitter(d)
		if j < 80*time.Millisecond || j > 120*time.Millisecond {
			t.Fatalf("jitter(%s) = %s outside ±20%%", d, j)
		}
	}
}

func TestClampInterval(t *testing.T) {
	if got := clampInterval(10 * time.Millisecond); got != minHeartbeatInterval {
		t.Errorf("clamp low: %s", got)
	}
	if got := clampInterval(time.Hour); got != maxHeartbeatInterval {
		t.Errorf("clamp high: %s", got)
	}
	if got := clampInterval(30 * time.Second); got != 30*time.Second {
		t.Errorf("clamp passthrough: %s", got)
	}
}

// fakeClientStream records sends; the embedded nil ClientStream would panic
// if any unexpected method were touched.
type fakeClientStream struct {
	grpc.ClientStream
	mu   sync.Mutex
	sent []*pb.Envelope
}

func (f *fakeClientStream) Send(e *pb.Envelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, e)
	return nil
}

func (f *fakeClientStream) Recv() (*pb.Envelope, error) { return nil, io.EOF }

// TestOutboundAllowlistRefusesBrokerAuthority: the sender locally refuses
// payloads outside the agent-allowed CONTROL set — a kill (broker authority)
// can never even be attempted from the endpoint.
func TestOutboundAllowlistRefusesBrokerAuthority(t *testing.T) {
	fs := &fakeClientStream{}
	s := &controlSender{stream: fs}
	err := s.send(&pb.Envelope{Payload: &pb.Envelope_Kill{Kill: &pb.Kill{SessionId: "x"}}})
	if err == nil {
		t.Fatal("sender accepted a broker-authority payload")
	}
	if len(fs.sent) != 0 {
		t.Fatal("refused payload still reached the stream")
	}
	// Allowed frames pass and the seq stays contiguous.
	if err := s.sendError("e1", false); err != nil {
		t.Fatalf("sendError: %v", err)
	}
	if err := s.sendError("e2", true); err != nil {
		t.Fatalf("sendError: %v", err)
	}
	if err := s.sendSessionError("sess-1", "e3", false); err != nil {
		t.Fatalf("sendSessionError: %v", err)
	}
	if len(fs.sent) != 3 || fs.sent[0].GetFrameSeq() != 0 || fs.sent[1].GetFrameSeq() != 1 ||
		fs.sent[2].GetFrameSeq() != 2 {
		t.Fatalf("outbound seq not contiguous: %v", fs.sent)
	}
	if fs.sent[0].GetSessionId() != "" || fs.sent[1].GetSessionId() != "" {
		t.Fatalf("generic errors unexpectedly carried session ids: %q %q",
			fs.sent[0].GetSessionId(), fs.sent[1].GetSessionId())
	}
	if fs.sent[2].GetSessionId() != "sess-1" {
		t.Fatalf("session error session_id %q, want sess-1", fs.sent[2].GetSessionId())
	}
	for _, e := range fs.sent {
		if e.GetChannelType() != pb.ChannelType_CONTROL {
			t.Errorf("outbound channel %v, want CONTROL", e.GetChannelType())
		}
		if e.GetSentAtEpochMillis() <= 0 {
			t.Error("sentAt not stamped")
		}
	}
}
