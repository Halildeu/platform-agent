package harness

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"platform-agent/internal/remotebridge/dataplane"
	"platform-agent/internal/remotebridge/operation"
	pb "platform-agent/internal/remotebridge/pb"
)

// fakeScreenDispatcher is an injected ScreenViewDispatcher: it records the call + runs a scripted body over the
// DATA send func, so the harness VIEW_ONLY dispatch WIRING (route → DATA stream → frames → cancel) is exercised
// without a display or the Windows capture code.
type fakeScreenDispatcher struct {
	mu           sync.Mutex
	called       bool
	gotStream    string
	gotCap       string
	ctxCancelled bool
	invoked      chan struct{}
	run          func(ctx context.Context, send func(*pb.DataFrame) error) error
}

func (d *fakeScreenDispatcher) Handle(ctx context.Context, permit operation.OperationPermit, streamID string,
	send func(*pb.DataFrame) error, _ int64) error {
	d.mu.Lock()
	d.called = true
	d.gotStream = streamID
	d.gotCap = permit.Capability
	inv := d.invoked
	d.invoked = nil
	d.mu.Unlock()
	if inv != nil {
		close(inv)
	}
	if d.run == nil {
		return nil
	}
	return d.run(ctx, send)
}

func (d *fakeScreenDispatcher) snapshot() (called bool, stream, cap string, cancelled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.called, d.gotStream, d.gotCap, d.ctxCancelled
}

func viewOnlyPermitProto() *pb.OperationPermit {
	return &pb.OperationPermit{
		Alg: operation.PermitAlg, Kid: "kid-1", PermitVersion: 1, PolicyVersion: "policy-1",
		DecisionId: "sess-1:op-1", SessionId: "sess-1", OperationId: "op-1", DeviceId: "device-test",
		OperatorSubject: "operator@x", Capability: pb.Capability_VIEW_ONLY,
		IssuedAtEpochMillis: 1000, ExpiresAtEpochMillis: 1300, Seq: 1, SignatureB64: "sig",
	}
}

func operationPermitEnv(p *pb.OperationPermit) *pb.Envelope {
	return &pb.Envelope{
		ChannelType: pb.ChannelType_CONTROL,
		Payload:     &pb.Envelope_OperationPermit{OperationPermit: p},
	}
}

func startDispatchScreenView(t *testing.T, broker *dispatchBroker, dispatcher ScreenViewDispatcher) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterRemoteBridgeServer(srv, broker)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	cfg := Config{
		DeviceIDProvider:       func() string { return "device-test" },
		AgentVersion:           "0.0.0-test",
		FirstHeartbeatDeadline: 2 * time.Second,
		BackoffMin:             10 * time.Millisecond,
		BackoffMax:             50 * time.Millisecond,
		IdentityPollInterval:   10 * time.Millisecond,
		ScreenViewDispatcher:   dispatcher, // nil = disabled-by-default
		Dialer: func(ctx context.Context) (*grpc.ClientConn, error) {
			return grpc.NewClient("passthrough:///bufnet",
				grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
					return lis.DialContext(ctx)
				}),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
		},
	}
	h, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.Run(ctx)
}

// --- handleInbound routing (unit) -----------------------------------------------------------------

func newHarnessWithScreenDispatcher(t *testing.T, disp ScreenViewDispatcher) *Harness {
	t.Helper()
	h, err := New(Config{
		DeviceIDProvider:     func() string { return "device-test" },
		ScreenViewDispatcher: disp,
		Dialer:               func(ctx context.Context) (*grpc.ClientConn, error) { return nil, nil },
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func TestHandleInboundViewOnlyPermitRouting(t *testing.T) {
	// disabled-by-default: no dispatcher → a VIEW_ONLY permit is a protocol defect
	hNil := newHarnessWithScreenDispatcher(t, nil)
	if act, reason := hNil.handleInbound(operationPermitEnv(viewOnlyPermitProto()), &inboundSeqGuard{}); act != actionDefectClose || reason != "unsupported-payload-in-idle" {
		t.Fatalf("nil dispatcher: act=%v reason=%q, want defect-close/unsupported-payload-in-idle", act, reason)
	}

	disp := &fakeScreenDispatcher{}
	// wired + VIEW_ONLY → actionScreenView
	if act, reason := newHarnessWithScreenDispatcher(t, disp).handleInbound(operationPermitEnv(viewOnlyPermitProto()), &inboundSeqGuard{}); act != actionScreenView || reason != "" {
		t.Fatalf("VIEW_ONLY permit: act=%v reason=%q, want actionScreenView", act, reason)
	}
	// wired but a non-VIEW_ONLY bare permit → defect (the broker pushes PTY as operation_dispatch, never bare)
	ptyBare := viewOnlyPermitProto()
	ptyBare.Capability = pb.Capability_CONSTRAINED_PTY
	if act, reason := newHarnessWithScreenDispatcher(t, disp).handleInbound(operationPermitEnv(ptyBare), &inboundSeqGuard{}); act != actionDefectClose || reason != "operation-permit-not-view-only" {
		t.Fatalf("non-VIEW_ONLY bare permit: act=%v reason=%q, want defect/operation-permit-not-view-only", act, reason)
	}
}

func TestAdvertisedCapabilitiesViewOnly(t *testing.T) {
	if caps := advertisedCapabilities(Config{}); len(caps) != 0 {
		t.Fatalf("no dispatchers wired → no advertised capabilities, got %v", caps)
	}
	caps := advertisedCapabilities(Config{ScreenViewDispatcher: &fakeScreenDispatcher{}})
	if len(caps) != 1 || caps[0] != pb.Capability_VIEW_ONLY {
		t.Fatalf("only ScreenViewDispatcher wired → [VIEW_ONLY], got %v", caps)
	}
}

// --- e2e: routing → DATA stream + KILL cancellation -----------------------------------------------

func TestScreenViewHappyStreamsToData(t *testing.T) {
	disp := &fakeScreenDispatcher{run: func(_ context.Context, send func(*pb.DataFrame) error) error {
		if err := send(&pb.DataFrame{StreamId: "op-1", FrameSeq: 0, ContentType: "image/png", Payload: []byte("PNGDATA")}); err != nil {
			return err
		}
		return send(&pb.DataFrame{StreamId: "op-1", FrameSeq: 1, ContentType: "image/png", EndStream: true})
	}}
	broker := &dispatchBroker{connect: func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil { // AgentHello
			return err
		}
		_ = s.Send(heartbeatEnv(60_000, 0))
		_ = s.Send(operationPermitEnv(viewOnlyPermitProto()))
		for {
			if _, err := s.Recv(); err != nil {
				return nil
			}
		}
	}}
	startDispatchScreenView(t, broker, disp)

	waitFor(t, 3*time.Second, "screen dispatcher invocation", func() bool {
		called, _, _, _ := disp.snapshot()
		return called
	})
	_, stream, cap, _ := disp.snapshot()
	if stream != "op-1" {
		t.Errorf("stream id %q, want the permit operationId op-1", stream)
	}
	if cap != "VIEW_ONLY" {
		t.Errorf("capability %q, want VIEW_ONLY", cap)
	}

	waitFor(t, 3*time.Second, "DATA frames at the broker", func() bool {
		return len(broker.dataFrames()) >= 2
	})
	frames := broker.dataFrames()
	for i, env := range frames {
		if env.GetChannelType() != pb.ChannelType_DATA {
			t.Errorf("frame %d channel %v, want DATA", i, env.GetChannelType())
		}
		if env.GetSessionId() != "sess-1" || env.GetStreamId() != "op-1" {
			t.Errorf("frame %d ids session=%q stream=%q, want sess-1/op-1", i, env.GetSessionId(), env.GetStreamId())
		}
		if df := env.GetDataFrame(); df == nil || df.GetContentType() != "image/png" {
			t.Errorf("frame %d must be an image/png data_frame, got %+v", i, env.GetPayload())
		}
	}
	if got := string(frames[0].GetDataFrame().GetPayload()); got != "PNGDATA" {
		t.Errorf("first DATA payload %q, want PNGDATA", got)
	}
	if !frames[len(frames)-1].GetDataFrame().GetEndStream() {
		t.Error("the last DATA frame must be the terminal EndStream")
	}
}

// TestScreenViewSessionKillCancelsDispatch is the security-critical #4 invariant: a session-scoped KILL (which
// keeps the transport up) must actively cancel a running screen-view dispatch so no frame egresses after a kill.
func TestScreenViewSessionKillCancelsDispatch(t *testing.T) {
	invoked := make(chan struct{})
	done := make(chan struct{})
	disp := &fakeScreenDispatcher{invoked: invoked}
	disp.run = func(ctx context.Context, _ func(*pb.DataFrame) error) error {
		<-ctx.Done() // block until the harness cancels this dispatch
		disp.mu.Lock()
		disp.ctxCancelled = true
		disp.mu.Unlock()
		close(done)
		return ctx.Err()
	}
	broker := &dispatchBroker{connect: func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(heartbeatEnv(60_000, 0))
		_ = s.Send(operationPermitEnv(viewOnlyPermitProto()))
		<-invoked                                 // wait until the dispatch is actually running
		_ = s.Send(killEnv("sess-1", "operator")) // session-scoped KILL for the running session
		for {
			if _, err := s.Recv(); err != nil {
				return nil
			}
		}
	}}
	startDispatchScreenView(t, broker, disp)

	select {
	case <-done:
		// the dispatch observed ctx cancellation
	case <-time.After(3 * time.Second):
		t.Fatal("a session-scoped KILL did not cancel the running screen-view dispatch within 3s")
	}
	if _, _, _, cancelled := disp.snapshot(); !cancelled {
		t.Fatal("the dispatch must have observed ctx cancellation after the KILL")
	}
}

func TestKillAppliedAckWaitsForExactScreenDispatchToStop(t *testing.T) {
	invoked := make(chan struct{})
	cancelObserved := make(chan struct{})
	allowReturn := make(chan struct{})
	ackReceived := make(chan *pb.AuditEvent, 1)
	disp := &fakeScreenDispatcher{invoked: invoked}
	disp.run = func(ctx context.Context, _ func(*pb.DataFrame) error) error {
		<-ctx.Done()
		close(cancelObserved)
		<-allowReturn // model bounded in-flight DATA cleanup after cancellation
		return nil
	}
	broker := &dispatchBroker{connect: func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(heartbeatEnv(60_000, 0))
		_ = s.Send(operationPermitEnv(viewOnlyPermitProto()))
		<-invoked
		_ = s.Send(killEnv("sess-1", "OPERATOR_CLOSE"))
		for {
			env, err := s.Recv()
			if err != nil {
				return nil
			}
			if event := env.GetAuditEvent(); event != nil && event.GetEventType() == "AGENT_KILL_APPLIED" {
				ackReceived <- event
				return nil
			}
		}
	}}
	startDispatchScreenView(t, broker, disp)

	select {
	case <-cancelObserved:
	case <-time.After(3 * time.Second):
		t.Fatal("screen dispatch did not observe KILL cancellation")
	}
	select {
	case <-ackReceived:
		t.Fatal("KILL ACK arrived before the exact screen dispatch returned")
	case <-time.After(100 * time.Millisecond):
	}
	close(allowReturn)
	select {
	case event := <-ackReceived:
		if event.GetSessionId() != "sess-1" || event.GetEventType() != "AGENT_KILL_APPLIED" {
			t.Fatalf("ack = session %q type %q", event.GetSessionId(), event.GetEventType())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("KILL ACK did not arrive after the screen dispatch stopped")
	}
}

func TestScreenViewTypedTerminationEmitsAllowlistedAuditEvent(t *testing.T) {
	tests := []struct {
		name        string
		dispatchErr error
		wantEvent   string
	}{
		{"local-abort", dataplane.ErrLocalAbort, "LOCAL_ABORT"},
		{"indicator-lost", dataplane.ErrIndicatorLost, "AGENT_INDICATOR_LOST"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := make(chan *pb.AuditEvent, 1)
			disp := &fakeScreenDispatcher{run: func(context.Context, func(*pb.DataFrame) error) error {
				return tc.dispatchErr
			}}
			broker := &dispatchBroker{connect: func(s pb.RemoteBridge_ConnectServer) error {
				if _, err := s.Recv(); err != nil {
					return err
				}
				_ = s.Send(heartbeatEnv(60_000, 0))
				_ = s.Send(operationPermitEnv(viewOnlyPermitProto()))
				for {
					env, err := s.Recv()
					if err != nil {
						return nil
					}
					if event := env.GetAuditEvent(); event != nil {
						received <- event
						return nil
					}
				}
			}}
			startDispatchScreenView(t, broker, disp)
			select {
			case event := <-received:
				if event.GetSessionId() != "sess-1" || event.GetEventType() != tc.wantEvent {
					t.Fatalf("audit event = session %q type %q", event.GetSessionId(), event.GetEventType())
				}
				if len(event.GetContentHash()) != 64 || event.GetEpochMillis() <= 0 {
					t.Fatalf("audit provenance missing: hash=%q epoch=%d", event.GetContentHash(), event.GetEpochMillis())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("typed termination did not reach CONTROL as an audit event")
			}
		})
	}
}

// TestScreenCancelRegistryRefusesDuplicateAndPreservesKill is the regression for the same-session orphan bug
// (Codex 019f1112): a second VIEW_ONLY dispatch for an already-active session must be REFUSED (no overwrite),
// so the first running stream stays registered and a later session-scoped KILL still cancels it. An overwrite
// would orphan the first stream's cancel → a KILL would miss it → a frame could egress after the kill.
func TestScreenCancelRegistryRefusesDuplicateAndPreservesKill(t *testing.T) {
	h := newHarnessWithScreenDispatcher(t, &fakeScreenDispatcher{})

	aCancelled, bCancelled := false, false
	entryA, okA := h.registerScreenCancel("sess-dup", func() { aCancelled = true })
	if !okA || entryA == nil {
		t.Fatalf("first registration must succeed: ok=%v entry=%v", okA, entryA)
	}
	// a second concurrent stream for the SAME session must be refused — never overwrite the live entry
	entryB, okB := h.registerScreenCancel("sess-dup", func() { bCancelled = true })
	if okB || entryB != nil {
		t.Fatalf("a duplicate same-session registration must be refused: ok=%v entry=%v", okB, entryB)
	}
	// the refused duplicate's deferred (identity-guarded) cleanup must NOT evict the live entry A
	h.unregisterScreenCancel("sess-dup", entryB)

	// a session-scoped KILL must still reach the FIRST (live) stream
	h.obeyKill("sess-dup", "operator")
	if !aCancelled {
		t.Fatal("session KILL must cancel the first (still-registered) screen stream — overwrite would have orphaned it")
	}
	if bCancelled {
		t.Fatal("the refused duplicate was never registered, so it must never be cancellable")
	}
}
