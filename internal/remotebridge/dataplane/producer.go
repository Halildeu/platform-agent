package dataplane

import (
	"errors"
	"sync"
)

// Typed VIEW_ONLY termination causes propagated from the interactive helper to
// the service and then to the broker. They are deliberately distinct from EOF:
// EOF is a normal producer completion, while these events must terminate the
// session fail-closed and leave an auditable reason.
var (
	ErrLocalAbort    = errors.New("dataplane: endpoint user aborted the view-only session")
	ErrIndicatorLost = errors.New("dataplane: endpoint awareness indicator was lost")
	ErrPermitExpired = errors.New("dataplane: view-only permit expired")
	ErrCaptureFailed = errors.New("dataplane: screen capture failed closed")
)

// Frame is one captured VIEW_ONLY frame as a domain value. Payload is opaque
// already-encoded bytes (the encoding is the producer's concern). The harness
// maps Frame to the proto DataFrame at send time, so this package keeps NO
// dependency on the frozen wire contract.
type Frame struct {
	// Seq is the producer's monotonically increasing frame counter (the wire
	// frame_seq is assigned by the sender; this is the capture-order tag).
	Seq int64
	// Payload is the encoded frame body. "No frame" is signalled by Next
	// returning ok=false — NOT by an empty Payload: a Frame returned with
	// ok=true is always a real frame and is queued, even if Payload is
	// nil/zero-length (a valid keepalive / no-change frame).
	Payload []byte
}

// FrameProducer is the pluggable VIEW_ONLY capture source. The real
// implementation is the Windows DXGI / Desktop-Duplication producer (T-4
// next slice, build-tag _windows.go); MockFrameProducer drives unit tests
// with no display. A producer is single-consumer: Next is called from one
// pump goroutine until it returns ok=false, then Close is called once.
type FrameProducer interface {
	// Next returns the next captured frame. ok=false means the producer is
	// exhausted or stopped; the pump then stops and Closes it.
	Next() (frame Frame, ok bool)
	// Close releases capture resources. Safe to call once after Next returns
	// ok=false (or to stop early). Idempotent implementations are preferred.
	Close() error
	// Err distinguishes clean exhaustion/cancellation (nil) from a source failure.
	// Every producer implements it so a capture failure cannot accidentally become
	// a normal EndStream.
	Err() error
}

// MockFrameProducer is a deterministic synthetic producer for wiring + guard
// tests. It is NOT a real capture and is NOT a security boundary — it exists
// so the fail-closed gate, bounded queue, and abort/flush semantics can be
// exercised end-to-end without a display or the (later) Windows capture code.
type MockFrameProducer struct {
	mu      sync.Mutex
	seq     int64
	max     int64 // emit this many frames then ok=false (0 = unbounded)
	payload []byte
	closed  bool
}

// NewMockFrameProducer emits up to max frames (0 = unbounded), each carrying a
// copy of payload. A nil payload yields zero-length (keepalive) frames.
func NewMockFrameProducer(max int64, payload []byte) *MockFrameProducer {
	cp := append([]byte(nil), payload...)
	return &MockFrameProducer{max: max, payload: cp}
}

// Next implements FrameProducer.
func (m *MockFrameProducer) Next() (Frame, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Frame{}, false
	}
	if m.max > 0 && m.seq >= m.max {
		return Frame{}, false
	}
	m.seq++
	return Frame{Seq: m.seq, Payload: append([]byte(nil), m.payload...)}, true
}

// Close implements FrameProducer (idempotent).
func (m *MockFrameProducer) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// Err reports clean synthetic exhaustion.
func (m *MockFrameProducer) Err() error { return nil }
