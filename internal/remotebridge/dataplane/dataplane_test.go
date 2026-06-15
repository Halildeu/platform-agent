package dataplane

import (
	"context"
	"sync"
	"testing"
	"time"
)

func frame(seq int64) Frame { return Frame{Seq: seq, Payload: []byte{byte(seq)}} }

// A fresh session is fail-closed: nothing egresses until BOTH recording-ready
// AND active, and never after abort.
func TestGateFailClosedDefault(t *testing.T) {
	s := NewViewSession(0)
	if s.CanSend() {
		t.Fatal("fresh session must be CLOSED (fail-closed)")
	}
	if got := s.Offer(frame(1)); got != OutcomeDroppedGate {
		t.Fatalf("offer on closed gate = %v, want DroppedGate", got)
	}
	// recording-ready alone is not enough
	s.SetRecordingReady(true)
	if s.CanSend() {
		t.Fatal("recording-ready alone must not open the gate")
	}
	// active alone is not enough (reset, then only active)
	s2 := NewViewSession(0)
	s2.Activate()
	if s2.CanSend() {
		t.Fatal("active alone must not open the gate")
	}
}

func TestGateOpensOnlyWhenBoth(t *testing.T) {
	s := NewViewSession(0)
	s.SetRecordingReady(true)
	s.Activate()
	if !s.CanSend() {
		t.Fatal("recording-ready AND active must open the gate")
	}
	if got := s.Offer(frame(1)); got != OutcomeQueued {
		t.Fatalf("offer on open gate = %v, want Queued", got)
	}
	if s.QueueLen() != 1 {
		t.Fatalf("queue len = %d, want 1", s.QueueLen())
	}
}

func TestRecordingFalseShutsAndFlushes(t *testing.T) {
	s := NewViewSession(0)
	s.SetRecordingReady(true)
	s.Activate()
	s.Offer(frame(1))
	s.Offer(frame(2))
	s.SetRecordingReady(false) // recording lost → gate shut + flush
	if s.CanSend() {
		t.Fatal("gate must be shut after recording-false")
	}
	if s.QueueLen() != 0 {
		t.Fatalf("queue must be flushed on recording-false, len=%d", s.QueueLen())
	}
	if got := s.Offer(frame(3)); got != OutcomeDroppedGate {
		t.Fatalf("offer after recording-false = %v, want DroppedGate", got)
	}
	_, _, _, flushed, _ := s.Counters()
	if flushed != 2 {
		t.Fatalf("flushed = %d, want 2", flushed)
	}
}

func TestDeactivateShutsAndFlushes(t *testing.T) {
	s := NewViewSession(0)
	s.SetRecordingReady(true)
	s.Activate()
	s.Offer(frame(1))
	s.Deactivate()
	if s.CanSend() || s.QueueLen() != 0 {
		t.Fatal("deactivate must shut the gate and flush the queue")
	}
}

func TestAbortIsPermanentAndFlushes(t *testing.T) {
	s := NewViewSession(0)
	s.SetRecordingReady(true)
	s.Activate()
	s.Offer(frame(1))
	s.Abort()
	if !s.Aborted() {
		t.Fatal("Aborted() must report true")
	}
	if s.CanSend() || s.QueueLen() != 0 {
		t.Fatal("abort must shut the gate and flush")
	}
	// abort is irreversible for this session: re-enabling preconditions must
	// NOT reopen the gate.
	s.SetRecordingReady(true)
	s.Activate()
	if s.CanSend() {
		t.Fatal("abort must be permanent — gate cannot reopen")
	}
	if got := s.Offer(frame(2)); got != OutcomeDroppedGate {
		t.Fatalf("offer after abort = %v, want DroppedGate", got)
	}
}

func TestBackpressureEvictsOldestNeverBlocks(t *testing.T) {
	s := NewViewSession(2) // tiny cap
	s.SetRecordingReady(true)
	s.Activate()
	if got := s.Offer(frame(1)); got != OutcomeQueued {
		t.Fatalf("f1 = %v", got)
	}
	if got := s.Offer(frame(2)); got != OutcomeQueued {
		t.Fatalf("f2 = %v", got)
	}
	if got := s.Offer(frame(3)); got != OutcomeDroppedBackpressure {
		t.Fatalf("f3 = %v, want DroppedBackpressure", got)
	}
	if s.QueueLen() != 2 {
		t.Fatalf("queue must stay at cap=2, got %d", s.QueueLen())
	}
	// oldest (f1) evicted → drained order is f2, f3
	got := s.Drain(10)
	if len(got) != 2 || got[0][0] != 2 || got[1][0] != 3 {
		t.Fatalf("drain after backpressure = %v, want [f2,f3]", got)
	}
	_, _, dbp, _, drained := s.Counters()
	if dbp != 1 || drained != 2 {
		t.Fatalf("droppedBackpressure=%d drained=%d, want 1,2", dbp, drained)
	}
}

func TestDrainFIFOAndEmpty(t *testing.T) {
	s := NewViewSession(0)
	s.SetRecordingReady(true)
	s.Activate()
	for i := int64(1); i <= 3; i++ {
		s.Offer(frame(i))
	}
	got := s.Drain(2)
	if len(got) != 2 || got[0][0] != 1 || got[1][0] != 2 {
		t.Fatalf("drain(2) = %v, want [f1,f2]", got)
	}
	if s.QueueLen() != 1 {
		t.Fatalf("queue len after drain(2) = %d, want 1", s.QueueLen())
	}
	if got := s.Drain(0); got != nil {
		t.Fatalf("drain(0) = %v, want nil", got)
	}
}

// Pump: a CLOSED gate drops every produced frame (fail-closed end-to-end);
// the producer is Closed exactly once.
func TestPumpClosedGateDropsAll(t *testing.T) {
	s := NewViewSession(0) // closed
	mp := NewMockFrameProducer(5, []byte("x"))
	p := NewPump(mp, s)
	if err := p.Run(context.Background()); err != nil {
		t.Fatalf("pump run err: %v", err)
	}
	if s.QueueLen() != 0 {
		t.Fatal("closed gate must drop all produced frames")
	}
	_, droppedGate, _, _, _ := s.Counters()
	if droppedGate != 5 {
		t.Fatalf("droppedGate = %d, want 5", droppedGate)
	}
	// Close idempotency: a second Next after exhaustion returns ok=false.
	if _, ok := mp.Next(); ok {
		t.Fatal("producer must report exhausted after Close")
	}
}

// Pump: an OPEN gate queues produced frames (bounded).
func TestPumpOpenGateQueues(t *testing.T) {
	s := NewViewSession(100)
	s.SetRecordingReady(true)
	s.Activate()
	mp := NewMockFrameProducer(10, []byte("y"))
	if err := NewPump(mp, s).Run(context.Background()); err != nil {
		t.Fatalf("pump run err: %v", err)
	}
	if s.QueueLen() != 10 {
		t.Fatalf("open gate queue len = %d, want 10", s.QueueLen())
	}
}

// Pump: abort stops the pump promptly and the queue ends empty.
func TestPumpAbortStops(t *testing.T) {
	s := NewViewSession(100)
	s.SetRecordingReady(true)
	s.Activate()
	s.Abort() // abort before run
	mp := NewMockFrameProducer(1000, []byte("z"))
	if err := NewPump(mp, s).Run(context.Background()); err != nil {
		t.Fatalf("pump run err: %v", err)
	}
	if s.QueueLen() != 0 {
		t.Fatal("aborted session must hold no frames")
	}
}

// Pump: a cancelled context stops the pump.
func TestPumpContextCancelStops(t *testing.T) {
	s := NewViewSession(100)
	s.SetRecordingReady(true)
	s.Activate()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mp := NewMockFrameProducer(0, []byte("c")) // unbounded
	if err := NewPump(mp, s).Run(ctx); err != nil {
		t.Fatalf("pump run err: %v", err)
	}
}

// Drain refuses after abort (sender-side defense-in-depth — no egress post-abort).
func TestDrainRefusedAfterAbort(t *testing.T) {
	s := NewViewSession(0)
	s.SetRecordingReady(true)
	s.Activate()
	s.Offer(frame(1))
	s.Offer(frame(2))
	s.Abort()
	if got := s.Drain(10); got != nil {
		t.Fatalf("Drain after abort = %v, want nil (no egress post-abort)", got)
	}
}

// blockingProducer blocks in Next until Close — models the real DXGI capture
// waiting on the next frame. Used to prove immediate abort.
type blockingProducer struct {
	ch   chan struct{}
	once sync.Once
}

func newBlockingProducer() *blockingProducer { return &blockingProducer{ch: make(chan struct{})} }

func (b *blockingProducer) Next() (Frame, bool) {
	<-b.ch // block until Close unblocks us
	return Frame{}, false
}

func (b *blockingProducer) Close() error {
	b.once.Do(func() { close(b.ch) })
	return nil
}

// Local-abort must interrupt a BLOCKING producer immediately (the watcher
// Closes it), not wait for Next to return on its own.
func TestPumpImmediateAbortUnblocksBlockingProducer(t *testing.T) {
	s := NewViewSession(0)
	s.SetRecordingReady(true)
	s.Activate()
	bp := newBlockingProducer()
	done := make(chan error, 1)
	go func() { done <- NewPump(bp, s).Run(context.Background()) }()
	// The pump is now parked in Next(); abort must release it via the watcher.
	s.Abort()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pump run err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pump did not stop promptly on abort — blocking producer not interrupted")
	}
}

// Same, but via context cancel interrupting a blocking producer.
func TestPumpImmediateCtxCancelUnblocksBlockingProducer(t *testing.T) {
	s := NewViewSession(0)
	s.SetRecordingReady(true)
	s.Activate()
	bp := newBlockingProducer()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- NewPump(bp, s).Run(ctx) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pump did not stop promptly on ctx-cancel with a blocking producer")
	}
}
