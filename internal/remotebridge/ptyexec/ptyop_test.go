package ptyexec

import (
	"context"
	"errors"
	"testing"
	"time"

	"platform-agent/internal/remotebridge/operation"
	pb "platform-agent/internal/remotebridge/pb"
)

// authorizedHandler builds a handler whose gated executor authorizes the embedded vector's command (real
// ECDSA verify + DefaultAllowlist), with an injected runner so the test controls the captured output.
func authorizedHandler(t *testing.T, rec *recorderRun, chunk int, timeout time.Duration) (*PtyOperationHandler, operation.OperationPermit, execVector) {
	t.Helper()
	permit, ver, v := loadExecVector(t)
	e := NewExecutor(ver, DefaultAllowlist(), 0, 0)
	e.run = rec.fn
	h, err := NewPtyOperationHandler(e, chunk, timeout)
	if err != nil {
		t.Fatalf("NewPtyOperationHandler: %v", err)
	}
	return h, permit, v
}

func TestNewPtyOperationHandlerValidation(t *testing.T) {
	if _, err := NewPtyOperationHandler(nil, 0, 0); err == nil {
		t.Error("nil executor must be rejected (nothing would gate the command)")
	}
	e := NewExecutor(nil, DefaultAllowlist(), 0, 0)
	h, err := NewPtyOperationHandler(e, 0, 0)
	if err != nil {
		t.Fatalf("valid: %v", err)
	}
	if h.chunk != DefaultDataFrameChunk || h.execTimeout != DefaultExecTimeout {
		t.Errorf("defaults not applied: chunk=%d timeout=%s", h.chunk, h.execTimeout)
	}
}

func TestPtyOperationHandlerHappyStreamsOutputThenEnd(t *testing.T) {
	rec := &recorderRun{retOut: []byte("RENDERED-OUTPUT"), retCode: 7}
	h, permit, v := authorizedHandler(t, rec, 4, 0) // chunk 4 → 15 bytes = 4 data frames + EndStream
	c := &collector{}

	res, err := h.Handle(context.Background(), permit, v.CommandLine, "stream-1", c.send, execFreshNow)
	if err != nil {
		t.Fatalf("authorized command should stream cleanly: %v", err)
	}
	if !rec.called {
		t.Fatal("the runner was not invoked for an authorized command")
	}
	if string(res.Output) != "RENDERED-OUTPUT" || res.ExitCode != 7 {
		t.Errorf("ExecResult not propagated: out=%q code=%d", res.Output, res.ExitCode)
	}
	if got := len(c.frames); got != 5 { // 4 data + 1 end
		t.Fatalf("frame count = %d, want 5", got)
	}
	for i, f := range c.frames {
		if f.StreamId != "stream-1" {
			t.Errorf("frame %d streamId=%q", i, f.StreamId)
		}
		if f.FrameSeq != int64(i) {
			t.Errorf("frame %d seq=%d", i, f.FrameSeq)
		}
		if f.ContentType != PTYContentType {
			t.Errorf("frame %d contentType=%q", i, f.ContentType)
		}
	}
	last := c.frames[4]
	if !last.EndStream || len(last.Payload) != 0 {
		t.Errorf("last frame must be empty EndStream: end=%v len=%d", last.EndStream, len(last.Payload))
	}
	if got := string(reassemble(c.frames)); got != "RENDERED-OUTPUT" {
		t.Errorf("reassembled = %q", got)
	}
}

func TestPtyOperationHandlerDeniedStreamsOnlyEndStreamNoSpawn(t *testing.T) {
	rec := &recorderRun{retOut: []byte("SHOULD-NEVER-RUN")}
	h, permit, _ := authorizedHandler(t, rec, 0, 0)
	c := &collector{}

	// "whoami" hashes differently from the permit-bound "hostname" → gate deny (hash mismatch).
	res, err := h.Handle(context.Background(), permit, "whoami", "stream-deny", c.send, execFreshNow)
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("denied command must return ErrNotAuthorized, got %v", err)
	}
	if rec.called {
		t.Error("a DENIED command reached execution — fail-closed violated")
	}
	if len(res.Output) != 0 {
		t.Errorf("deny must yield no output, got %q", res.Output)
	}
	// DATA stream is well-formed: a single terminal EndStream, NO payload frame (no oracle).
	if len(c.frames) != 1 || !c.frames[0].EndStream || c.frames[0].FrameSeq != 0 || len(c.frames[0].Payload) != 0 {
		t.Fatalf("deny must emit exactly one empty EndStream, got %+v", c.frames)
	}
	if len(reassemble(c.frames)) != 0 {
		t.Error("deny leaked output payload onto DATA")
	}
}

func TestPtyOperationHandlerNilVerifierDenies(t *testing.T) {
	permit, _, v := loadExecVector(t)
	rec := &recorderRun{retOut: []byte("NO")}
	e := NewExecutor(nil, DefaultAllowlist(), 0, 0) // nil verifier ⇒ deny-everything gate
	e.run = rec.fn
	h, err := NewPtyOperationHandler(e, 0, 0)
	if err != nil {
		t.Fatalf("NewPtyOperationHandler: %v", err)
	}
	c := &collector{}
	if _, err := h.Handle(context.Background(), permit, v.CommandLine, "s", c.send, execFreshNow); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("nil verifier must deny: %v", err)
	}
	if rec.called {
		t.Error("nil verifier allowed execution — fail-closed violated")
	}
	if len(c.frames) != 1 || !c.frames[0].EndStream {
		t.Errorf("deny must still close the DATA stream with a lone EndStream, got %+v", c.frames)
	}
}

func TestPtyOperationHandlerBlankCommandRefusedBeforeExecute(t *testing.T) {
	rec := &recorderRun{retOut: []byte("NO")}
	h, permit, _ := authorizedHandler(t, rec, 0, 0)
	c := &collector{}

	_, err := h.Handle(context.Background(), permit, "   ", "stream-blank", c.send, execFreshNow)
	if !errors.Is(err, ErrInvalidOperation) {
		t.Fatalf("blank command must return ErrInvalidOperation, got %v", err)
	}
	if rec.called {
		t.Error("a blank command reached the executor — must be refused BEFORE Execute")
	}
	if len(c.frames) != 1 || !c.frames[0].EndStream || len(c.frames[0].Payload) != 0 {
		t.Errorf("blank command must emit a lone empty EndStream, got %+v", c.frames)
	}
}

func TestPtyOperationHandlerBlankStreamIDEmitsNoFrames(t *testing.T) {
	rec := &recorderRun{retOut: []byte("NO")}
	h, permit, v := authorizedHandler(t, rec, 0, 0)
	c := &collector{}

	_, err := h.Handle(context.Background(), permit, v.CommandLine, "  ", c.send, execFreshNow)
	if !errors.Is(err, ErrInvalidOperation) {
		t.Fatalf("blank streamID must return ErrInvalidOperation, got %v", err)
	}
	if rec.called {
		t.Error("blank streamID reached the executor")
	}
	if len(c.frames) != 0 {
		t.Errorf("blank streamID must emit NO frames (no safe sink id), got %d", len(c.frames))
	}
}

func TestPtyOperationHandlerNilSendRejected(t *testing.T) {
	rec := &recorderRun{retOut: []byte("NO")}
	h, permit, v := authorizedHandler(t, rec, 0, 0)
	if _, err := h.Handle(context.Background(), permit, v.CommandLine, "s", nil, execFreshNow); err == nil {
		t.Error("nil send must be rejected")
	}
	if rec.called {
		t.Error("nil send reached the executor")
	}
}

func TestPtyOperationHandlerExecErrorStreamsPartialThenEnd(t *testing.T) {
	sentinel := errors.New("conpty boom")
	rec := &recorderRun{retOut: []byte("PARTIAL"), retCode: 0, retErr: sentinel}
	h, permit, v := authorizedHandler(t, rec, 4, 0) // gate+allowlist pass, run returns partial output + error
	c := &collector{}

	res, err := h.Handle(context.Background(), permit, v.CommandLine, "stream-err", c.send, execFreshNow)
	if !errors.Is(err, sentinel) {
		t.Fatalf("exec error must propagate (joined), got %v", err)
	}
	if !rec.called {
		t.Error("the runner should have been invoked (gate + allowlist passed)")
	}
	if string(res.Output) != "PARTIAL" {
		t.Errorf("partial output not returned: %q", res.Output)
	}
	// The partial output was streamed BEFORE the terminal EndStream (output → EndStream → error).
	if got := string(reassemble(c.frames)); got != "PARTIAL" {
		t.Errorf("partial output not streamed: %q", got)
	}
	if last := c.frames[len(c.frames)-1]; !last.EndStream {
		t.Error("stream must still end with a terminal EndStream on exec error")
	}
}

func TestPtyOperationHandlerSendErrorNotSwallowed(t *testing.T) {
	boom := errors.New("send boom")
	rec := &recorderRun{retOut: []byte("X"), retCode: 0}
	h, permit, v := authorizedHandler(t, rec, 0, 0)

	calls := 0
	send := func(*pb.DataFrame) error {
		calls++
		if calls == 1 {
			return boom // fail the first (data) frame
		}
		return nil
	}
	if _, err := h.Handle(context.Background(), permit, v.CommandLine, "s", send, execFreshNow); !errors.Is(err, boom) {
		t.Fatalf("a DATA send failure must be surfaced, got %v", err)
	}
}

func TestPtyOperationHandlerExecTimeoutBoundsWedgedChild(t *testing.T) {
	permit, ver, v := loadExecVector(t)
	started := make(chan struct{})
	// A runner that wedges until its ctx is cancelled, then reports ctx.Err() (a real child is terminated).
	run := func(ctx context.Context, _, _ string, _, _ int16) ([]byte, uint32, error) {
		close(started)
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}
	e := NewExecutor(ver, DefaultAllowlist(), 0, 0)
	e.run = run
	h, err := NewPtyOperationHandler(e, 0, 50*time.Millisecond) // tight deadline
	if err != nil {
		t.Fatalf("NewPtyOperationHandler: %v", err)
	}
	c := &collector{}

	done := make(chan error, 1)
	go func() {
		_, herr := h.Handle(context.Background(), permit, v.CommandLine, "s", c.send, execFreshNow)
		done <- herr
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("runner never started")
	}
	select {
	case herr := <-done:
		if !errors.Is(herr, context.DeadlineExceeded) {
			t.Fatalf("execTimeout must bound the run with DeadlineExceeded, got %v", herr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("execTimeout did not bound the wedged child (Handle hung)")
	}
	// Even on a timed-out execution the DATA stream is closed with a lone EndStream (no payload).
	if len(c.frames) != 1 || !c.frames[0].EndStream {
		t.Errorf("timeout must still emit a lone EndStream, got %+v", c.frames)
	}
}
