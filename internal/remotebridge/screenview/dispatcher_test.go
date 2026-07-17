package screenview

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"platform-agent/internal/remotebridge/dataplane"
	"platform-agent/internal/remotebridge/operation"
	pb "platform-agent/internal/remotebridge/pb"
)

type fakeAuthorizer struct {
	allow  bool
	reason string
	calls  int
}

func (f *fakeAuthorizer) AuthorizeViewOnly(operation.OperationPermit, int64) operation.Decision {
	f.calls++
	return operation.Decision{Allowed: f.allow, Reason: f.reason}
}

func viewOnlyPermit() operation.OperationPermit {
	now := time.Now().UnixMilli()
	return operation.OperationPermit{
		Capability: operation.CapabilityViewOnly, SessionID: "s", OperationID: "op-1", Seq: 1,
		IssuedAtEpochMillis: now - 1_000, ExpiresAtEpochMillis: now + 60_000,
	}
}

type frameSink struct {
	mu     sync.Mutex
	frames []*pb.DataFrame
	err    error
}

func (s *frameSink) send(f *pb.DataFrame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.frames = append(s.frames, f)
	return nil
}

func (s *frameSink) snapshot() []*pb.DataFrame {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*pb.DataFrame(nil), s.frames...)
}

func mockFactory(max int64, payload []byte) ProducerFactory {
	return func(context.Context, string, string) (dataplane.FrameProducer, error) {
		return dataplane.NewMockFrameProducer(max, payload), nil
	}
}

type terminatingProducer struct{ err error }

func (p *terminatingProducer) Next() (dataplane.Frame, bool) { return dataplane.Frame{}, false }
func (p *terminatingProducer) Close() error                  { return nil }
func (p *terminatingProducer) Err() error                    { return p.err }

func TestDispatchDeniedAuthorizationFailsClosed(t *testing.T) {
	factoryCalled := false
	factory := func(context.Context, string, string) (dataplane.FrameProducer, error) {
		factoryCalled = true
		return nil, nil
	}
	d, err := New(&fakeAuthorizer{allow: false, reason: "seq-replay"}, factory, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sink := &frameSink{}
	herr := d.Handle(context.Background(), viewOnlyPermit(), "op-1", sink.send, 1)
	if herr == nil || !strings.Contains(herr.Error(), "view-only-authorize-denied:seq-replay") {
		t.Fatalf("denied authorize must return view-only-authorize-denied:seq-replay, got %v", herr)
	}
	if factoryCalled {
		t.Error("a denied authorization must NOT start capture (no gate, no producer)")
	}
	if len(sink.snapshot()) != 0 {
		t.Error("a denied authorization must emit no frames")
	}
}

func TestDispatchCaptureStartFailureFailsClosed(t *testing.T) {
	factory := func(context.Context, string, string) (dataplane.FrameProducer, error) {
		return nil, errors.New("no display")
	}
	d, _ := New(&fakeAuthorizer{allow: true}, factory, Options{})
	sink := &frameSink{}
	herr := d.Handle(context.Background(), viewOnlyPermit(), "op-1", sink.send, 1)
	if herr == nil || !strings.Contains(herr.Error(), "view-only-capture-start-failed") {
		t.Fatalf("a capture-start failure must fail-closed, got %v", herr)
	}
	if len(sink.snapshot()) != 0 {
		t.Error("a capture-start failure must emit no frames")
	}
}

func TestDispatchCancelDuringCaptureStartupReturnsCleanly(t *testing.T) {
	factoryStarted := make(chan struct{})
	factory := func(ctx context.Context, _, _ string) (dataplane.FrameProducer, error) {
		close(factoryStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	d, _ := New(&fakeAuthorizer{allow: true}, factory, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Handle(ctx, viewOnlyPermit(), "op-1", (&frameSink{}).send, 1) }()
	<-factoryStarted
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("startup cancellation must be a clean teardown, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup cancellation did not stop promptly")
	}
}

func TestDispatchPermitExpiryDuringCaptureStartupPreservesCause(t *testing.T) {
	permit := viewOnlyPermit()
	permit.ExpiresAtEpochMillis = time.Now().Add(30 * time.Millisecond).UnixMilli()
	factory := func(ctx context.Context, _, _ string) (dataplane.FrameProducer, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	d, _ := New(&fakeAuthorizer{allow: true}, factory, Options{})
	err := d.Handle(context.Background(), permit, "op-1", (&frameSink{}).send, time.Now().UnixMilli())
	if !errors.Is(err, dataplane.ErrPermitExpired) {
		t.Fatalf("startup expiry err = %v, want ErrPermitExpired", err)
	}
}

func TestDispatchHappyStreamsImageFramesThenEndStream(t *testing.T) {
	d, _ := New(&fakeAuthorizer{allow: true}, mockFactory(3, []byte("PNG")), Options{})
	sink := &frameSink{}
	if herr := d.Handle(context.Background(), viewOnlyPermit(), "op-1", sink.send, 1); herr != nil {
		t.Fatalf("happy dispatch returned %v", herr)
	}
	frames := sink.snapshot()
	if len(frames) != 4 { // 3 captured + the terminal EndStream
		t.Fatalf("expected 3 frames + EndStream = 4, got %d", len(frames))
	}
	for i := 0; i < 3; i++ {
		if frames[i].GetStreamId() != "op-1" {
			t.Errorf("frame %d stream id %q, want op-1", i, frames[i].GetStreamId())
		}
		if frames[i].GetContentType() != "image/png" {
			t.Errorf("frame %d content-type %q, want image/png", i, frames[i].GetContentType())
		}
		if frames[i].GetFrameSeq() != int64(i) {
			t.Errorf("frame %d frame_seq %d, want %d (monotonic)", i, frames[i].GetFrameSeq(), i)
		}
		if string(frames[i].GetPayload()) != "PNG" {
			t.Errorf("frame %d payload %q, want PNG", i, frames[i].GetPayload())
		}
		if frames[i].GetEndStream() {
			t.Errorf("frame %d must not be EndStream", i)
		}
	}
	last := frames[3]
	if !last.GetEndStream() || last.GetFrameSeq() != 3 {
		t.Errorf("the last frame must be the terminal EndStream with seq 3, got endStream=%v seq=%d", last.GetEndStream(), last.GetFrameSeq())
	}
}

func TestDispatchContextCancelReturnsCleanly(t *testing.T) {
	d, _ := New(&fakeAuthorizer{allow: true}, mockFactory(0, []byte("PNG")), Options{DrainInterval: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	sink := &frameSink{}
	done := make(chan error, 1)
	go func() { done <- d.Handle(ctx, viewOnlyPermit(), "op-1", sink.send, 1) }()
	time.Sleep(15 * time.Millisecond) // let a few frames stream
	cancel()
	select {
	case herr := <-done:
		if herr != nil {
			t.Fatalf("ctx cancellation is a clean teardown, want nil, got %v", herr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Handle did not return within 3s of ctx cancellation")
	}
	// a cancelled dispatch must NOT emit a terminal EndStream (the gate was aborted, not drained to completion)
	for _, f := range sink.snapshot() {
		if f.GetEndStream() {
			t.Error("a cancelled dispatch must not send a terminal EndStream")
		}
	}
}

func TestDispatchSendErrorAbortsAndReturnsError(t *testing.T) {
	d, _ := New(&fakeAuthorizer{allow: true}, mockFactory(5, []byte("PNG")), Options{DrainInterval: time.Millisecond})
	sink := &frameSink{err: errors.New("broker stream broken")}
	herr := d.Handle(context.Background(), viewOnlyPermit(), "op-1", sink.send, 1)
	if herr == nil || !strings.Contains(herr.Error(), "broker stream broken") {
		t.Fatalf("a broken DATA send must surface the error, got %v", herr)
	}
}

func TestDispatchPermitExpiryAbortsWithoutTerminalFrame(t *testing.T) {
	permit := viewOnlyPermit()
	permit.ExpiresAtEpochMillis = time.Now().Add(40 * time.Millisecond).UnixMilli()
	d, _ := New(&fakeAuthorizer{allow: true}, mockFactory(0, []byte("PNG")), Options{
		DrainInterval: time.Millisecond,
	})
	sink := &frameSink{}
	started := time.Now()
	err := d.Handle(context.Background(), permit, "op-1", sink.send, time.Now().UnixMilli())
	if !errors.Is(err, dataplane.ErrPermitExpired) {
		t.Fatalf("expiry err = %v, want ErrPermitExpired", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("permit expiry took %v, want a bounded prompt stop", elapsed)
	}
	for _, frame := range sink.snapshot() {
		if frame.GetEndStream() {
			t.Fatal("permit expiry is an abort and must not emit a normal EndStream")
		}
	}
}

func TestDispatchPropagatesTypedSourceTerminationWithoutEndStream(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"local-abort", dataplane.ErrLocalAbort},
		{"indicator-lost", dataplane.ErrIndicatorLost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factory := func(context.Context, string, string) (dataplane.FrameProducer, error) {
				return &terminatingProducer{err: tc.err}, nil
			}
			d, _ := New(&fakeAuthorizer{allow: true}, factory, Options{})
			sink := &frameSink{}
			err := d.Handle(context.Background(), viewOnlyPermit(), "op-1", sink.send, time.Now().UnixMilli())
			if !errors.Is(err, tc.err) {
				t.Fatalf("termination err = %v, want %v", err, tc.err)
			}
			if len(sink.snapshot()) != 0 {
				t.Fatal("typed fail-closed termination must emit no frame or normal EndStream")
			}
		})
	}
}

func TestNewValidatesDependencies(t *testing.T) {
	if _, err := New(nil, mockFactory(1, nil), Options{}); err == nil {
		t.Error("nil authorizer must be rejected")
	}
	if _, err := New(&fakeAuthorizer{allow: true}, nil, Options{}); err == nil {
		t.Error("nil producer factory must be rejected")
	}
}
