package harness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"platform-agent/internal/remotebridge/operation"
	pb "platform-agent/internal/remotebridge/pb"
	"platform-agent/internal/remotebridge/ptyexec"
)

// fakeDispatcher is an injected PTYDispatcher: it records the call and runs a scripted body over the DATA send
// func, so the harness dispatch WIRING (decode → DATA stream → frames → CONTROL error) is exercised without a
// real pseudo-console (the crypto/gate/ConPTY are tested in the operation + ptyexec packages).
type fakeDispatcher struct {
	mu        sync.Mutex
	called    bool
	gotCmd    string
	gotStream string
	gotCap    string
	run       func(send func(*pb.DataFrame) error) error // scripted: stream frames, return handler error
}

func (d *fakeDispatcher) Handle(_ context.Context, permit operation.OperationPermit, commandLine, streamID string,
	send func(*pb.DataFrame) error, _ int64) (ptyexec.ExecResult, error) {
	d.mu.Lock()
	d.called = true
	d.gotCmd = commandLine
	d.gotStream = streamID
	d.gotCap = permit.Capability
	d.mu.Unlock()
	if d.run == nil {
		return ptyexec.ExecResult{}, nil
	}
	return ptyexec.ExecResult{}, d.run(send)
}

func (d *fakeDispatcher) snapshot() (bool, string, string, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.called, d.gotCmd, d.gotStream, d.gotCap
}

// dispatchBroker implements BOTH Connect (push an operation_dispatch + observe the agent's CONTROL replies)
// and Data (capture the agent's streamed frames).
type dispatchBroker struct {
	pb.UnimplementedRemoteBridgeServer
	connect  func(stream pb.RemoteBridge_ConnectServer) error
	mu       sync.Mutex
	dataEnvs []*pb.Envelope
}

func (b *dispatchBroker) Connect(stream pb.RemoteBridge_ConnectServer) error {
	return b.connect(stream)
}

func (b *dispatchBroker) Data(stream pb.RemoteBridge_DataServer) error {
	for {
		env, err := stream.Recv()
		if err != nil {
			return nil
		}
		b.mu.Lock()
		b.dataEnvs = append(b.dataEnvs, env)
		b.mu.Unlock()
	}
}

func (b *dispatchBroker) dataFrames() []*pb.Envelope {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*pb.Envelope(nil), b.dataEnvs...)
}

func startDispatch(t *testing.T, broker *dispatchBroker, dispatcher PTYDispatcher) {
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
		PTYDispatcher:          dispatcher, // nil = disabled-by-default
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

func ptyPermitProto() *pb.OperationPermit {
	return &pb.OperationPermit{
		Alg: operation.PermitAlg, Kid: "kid-1", PermitVersion: 1, PolicyVersion: "policy-1",
		// DeviceId MUST match the harness DeviceIDProvider ("device-test") — the
		// dispatch device-binding guard refuses a permit minted for another device.
		DecisionId: "sess-1:op-1", SessionId: "sess-1", OperationId: "op-1", DeviceId: "device-test",
		OperatorSubject: "operator@x", Capability: pb.Capability_CONSTRAINED_PTY,
		CommandHash: "abc123", IssuedAtEpochMillis: 1000, ExpiresAtEpochMillis: 1300, Seq: 1, SignatureB64: "sig",
	}
}

func operationDispatchEnv(commandLine string, permit *pb.OperationPermit) *pb.Envelope {
	return &pb.Envelope{
		ChannelType: pb.ChannelType_CONTROL,
		Payload: &pb.Envelope_OperationDispatch{OperationDispatch: &pb.OperationDispatch{
			Permit:      permit,
			CommandLine: commandLine,
		}},
	}
}

func TestDecodeDispatch(t *testing.T) {
	if _, _, err := decodeDispatch(nil); err == nil {
		t.Error("nil dispatch must fail-closed")
	}
	if _, _, err := decodeDispatch(&pb.OperationDispatch{CommandLine: "hostname"}); err == nil {
		t.Error("nil permit must fail-closed")
	}
	noOp := ptyPermitProto()
	noOp.OperationId = ""
	if _, _, err := decodeDispatch(&pb.OperationDispatch{Permit: noOp, CommandLine: "hostname"}); err == nil {
		t.Error("empty operationId must fail-closed (no DATA-stream correlation key)")
	}
	noSession := ptyPermitProto()
	noSession.SessionId = ""
	if _, _, err := decodeDispatch(&pb.OperationDispatch{Permit: noSession, CommandLine: "hostname"}); err == nil {
		t.Error("empty sessionId must fail-closed (no broker/WORM recording boundary)")
	}
	permit, cmd, err := decodeDispatch(&pb.OperationDispatch{Permit: ptyPermitProto(), CommandLine: "hostname"})
	if err != nil {
		t.Fatalf("valid dispatch: %v", err)
	}
	if cmd != "hostname" {
		t.Errorf("command %q, want hostname (carried raw)", cmd)
	}
	if permit.OperationID != "op-1" || permit.Capability != "CONSTRAINED_PTY" ||
		permit.SignatureB64 != "sig" || permit.CommandHash != "abc123" {
		t.Errorf("permit fields not mapped: %+v", permit)
	}
}

// TestDispatchHappyStreamsToDataAndCallsHandler: an enabled harness decodes an operation_dispatch, invokes the
// dispatcher with the raw command + a per-operation stream id, and the dispatcher's frames reach the broker's
// DATA stream as data_frame envelopes on the DATA channel.
func TestDispatchHappyStreamsToDataAndCallsHandler(t *testing.T) {
	disp := &fakeDispatcher{run: func(send func(*pb.DataFrame) error) error {
		if err := send(&pb.DataFrame{StreamId: "op-1", FrameSeq: 0, ContentType: "application/x-conpty-stream",
			Payload: []byte("RENDERED")}); err != nil {
			return err
		}
		return send(&pb.DataFrame{StreamId: "op-1", FrameSeq: 1, ContentType: "application/x-conpty-stream",
			EndStream: true})
	}}
	broker := &dispatchBroker{connect: func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil { // the AgentHello
			return err
		}
		_ = s.Send(heartbeatEnv(60_000, 0)) // keep the harness healthy — no watchdog reconnect mid-dispatch
		_ = s.Send(operationDispatchEnv("hostname", ptyPermitProto()))
		for { // keep the CONTROL stream (and thus the conn) open while the dispatch runs
			if _, err := s.Recv(); err != nil {
				return nil
			}
		}
	}}
	startDispatch(t, broker, disp)

	waitFor(t, 3*time.Second, "dispatcher invocation", func() bool {
		called, _, _, _ := disp.snapshot()
		return called
	})
	called, cmd, streamID, cap := disp.snapshot()
	if !called || cmd != "hostname" {
		t.Fatalf("dispatcher called=%v cmd=%q, want true/\"hostname\"", called, cmd)
	}
	if streamID != "op-1" {
		t.Errorf("stream id %q, want the permit operationId \"op-1\"", streamID)
	}
	if cap != "CONSTRAINED_PTY" {
		t.Errorf("decoded capability %q, want CONSTRAINED_PTY (enum name)", cap)
	}

	waitFor(t, 3*time.Second, "DATA frames at the broker", func() bool {
		return len(broker.dataFrames()) >= 2
	})
	frames := broker.dataFrames()
	for i, env := range frames {
		if env.GetChannelType() != pb.ChannelType_DATA {
			t.Errorf("frame %d channel %v, want DATA", i, env.GetChannelType())
		}
		if env.GetSessionId() != "sess-1" {
			t.Errorf("frame %d session_id %q, want sess-1", i, env.GetSessionId())
		}
		if env.GetStreamId() != "op-1" {
			t.Errorf("frame %d envelope stream_id %q, want op-1", i, env.GetStreamId())
		}
		if env.GetSentAtEpochMillis() <= 0 {
			t.Errorf("frame %d sent_at_epoch_millis %d, want positive", i, env.GetSentAtEpochMillis())
		}
		if env.GetDataFrame() == nil {
			t.Errorf("frame %d payload %T, want data_frame", i, env.GetPayload())
			continue
		}
		if env.GetDataFrame().GetStreamId() != "op-1" {
			t.Errorf("frame %d data_frame stream_id %q, want op-1", i, env.GetDataFrame().GetStreamId())
		}
	}
	if got := string(frames[0].GetDataFrame().GetPayload()); got != "RENDERED" {
		t.Errorf("first DATA payload %q, want RENDERED", got)
	}
	if !frames[len(frames)-1].GetDataFrame().GetEndStream() {
		t.Error("the last DATA frame must be the terminal EndStream")
	}
}

// TestDispatchDisabledDefectCloses: with NO dispatcher wired (disabled-by-default) an inbound operation_dispatch
// is a protocol defect — the agent sends an ErrorFrame on CONTROL and closes the stream (never executes).
func TestDispatchDisabledDefectCloses(t *testing.T) {
	agentFrames := make(chan *pb.Envelope, 16)
	broker := &dispatchBroker{connect: func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(operationDispatchEnv("hostname", ptyPermitProto()))
		for {
			env, err := s.Recv()
			if err != nil {
				return nil
			}
			agentFrames <- env
		}
	}}
	startDispatch(t, broker, nil) // disabled

	assertControlError(t, agentFrames, "unsupported-payload-in-idle")
}

// TestDispatchDecodeFailureDefectCloses: an enabled harness given a structurally-broken operation_dispatch (no
// permit) treats it as a protocol defect — ErrorFrame + close, the dispatcher is never invoked.
func TestDispatchDecodeFailureDefectCloses(t *testing.T) {
	disp := &fakeDispatcher{}
	agentFrames := make(chan *pb.Envelope, 16)
	broker := &dispatchBroker{connect: func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(operationDispatchEnv("hostname", nil)) // nil permit → decode fails
		for {
			env, err := s.Recv()
			if err != nil {
				return nil
			}
			agentFrames <- env
		}
	}}
	startDispatch(t, broker, disp)

	assertControlError(t, agentFrames, "operation-dispatch-decode-failed")
	if called, _, _, _ := disp.snapshot(); called {
		t.Error("a decode failure must NOT reach the dispatcher (no execution)")
	}
}

// TestDispatchHandlerErrorSendsControlErrorFrame: a valid dispatch whose handler FAILS (gate-deny / exec error)
// surfaces a bounded CONTROL ErrorFrame — the transport stays up (NOT a defect-close).
func TestDispatchHandlerErrorSendsControlErrorFrame(t *testing.T) {
	disp := &fakeDispatcher{run: func(func(*pb.DataFrame) error) error {
		return errors.New("gate denied") // the operation failed
	}}
	agentFrames := make(chan *pb.Envelope, 16)
	broker := &dispatchBroker{connect: func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		_ = s.Send(operationDispatchEnv("hostname", ptyPermitProto()))
		for {
			env, err := s.Recv()
			if err != nil {
				return nil
			}
			agentFrames <- env
		}
	}}
	startDispatch(t, broker, disp)

	assertControlError(t, agentFrames, "operation-dispatch-failed:exec-failed")
}

func TestDispatchErrorCodeClassifiesBoundedReasons(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "generic exec failure",
			err:  errors.New("spawn failed"),
			want: "operation-dispatch-failed:exec-failed",
		},
		{
			name: "permit invalid",
			err:  fmt.Errorf("%w: %s", ptyexec.ErrNotAuthorized, operation.ReasonPermitInvalid),
			want: "operation-dispatch-failed:permit-invalid",
		},
		{
			name: "command mismatch",
			err:  fmt.Errorf("%w: %s", ptyexec.ErrNotAuthorized, operation.ReasonCommandMismatch),
			want: "operation-dispatch-failed:command-mismatch",
		},
		{
			name: "not allowlisted",
			err:  fmt.Errorf("%w: hostname", ptyexec.ErrNotAllowlisted),
			want: "operation-dispatch-failed:not-allowlisted",
		},
		{
			name: "arg policy",
			err:  fmt.Errorf("%w: bad arg", ptyexec.ErrArgPolicy),
			want: "operation-dispatch-failed:arg-policy",
		},
		{
			name: "invalid operation",
			err:  fmt.Errorf("%w: unsupported", ptyexec.ErrInvalidOperation),
			want: "operation-dispatch-failed:invalid-operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dispatchErrorCode(tt.err); got != tt.want {
				t.Fatalf("dispatchErrorCode() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDispatchDeviceMismatchRefuses: a broker-signed permit minted for ANOTHER device (DeviceId != this
// agent's enrolled id) is refused at the harness device-binding guard — the dispatcher is NEVER invoked (no
// execution, no DATA stream) and a bounded CONTROL ErrorFrame is returned, transport stays up. Defense-in-depth
// against a misrouted/leaked permit: the agent holds the broker's public key, so the signature alone would
// otherwise verify and the (DeviceID-less) operation verifier + gate would let it through.
func TestDispatchDeviceMismatchRefuses(t *testing.T) {
	disp := &fakeDispatcher{run: func(func(*pb.DataFrame) error) error {
		t.Error("dispatcher must NOT run for a device-mismatched permit")
		return nil
	}}
	agentFrames := make(chan *pb.Envelope, 16)
	broker := &dispatchBroker{connect: func(s pb.RemoteBridge_ConnectServer) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		mismatched := ptyPermitProto()
		mismatched.DeviceId = "some-other-device" // != harness DeviceIDProvider "device-test"
		_ = s.Send(operationDispatchEnv("hostname", mismatched))
		for {
			env, err := s.Recv()
			if err != nil {
				return nil
			}
			agentFrames <- env
		}
	}}
	startDispatch(t, broker, disp)

	assertControlError(t, agentFrames, "operation-device-mismatch")
	if called, _, _, _ := disp.snapshot(); called {
		t.Error("a device-mismatched permit must NOT reach the dispatcher (no execution)")
	}
}

// assertControlError waits for an agent→broker CONTROL ErrorFrame with the given code.
func assertControlError(t *testing.T, frames <-chan *pb.Envelope, wantCode string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case env := <-frames:
			if env.GetError() != nil {
				if got := env.GetError().GetCode(); got != wantCode {
					t.Fatalf("CONTROL error code %q, want %q", got, wantCode)
				}
				if env.GetChannelType() != pb.ChannelType_CONTROL {
					t.Errorf("error channel %v, want CONTROL", env.GetChannelType())
				}
				return
			}
			// skip non-error agent frames (none expected, but be tolerant)
		case <-deadline:
			t.Fatalf("no CONTROL ErrorFrame %q within 3s", wantCode)
		}
	}
}
