package dataplane

import "sync"

// DefaultQueueCap is the default bounded in-flight frame queue depth. The
// queue is drop-tolerant (DATA frames are best-effort, ADR-0038): on overflow
// the OLDEST queued frame is dropped so the freshest screen state survives and
// Offer never blocks (the DATA path must never delay the CONTROL-plane KILL).
const DefaultQueueCap = 32

// Outcome reports what Offer did with a frame.
type Outcome int

const (
	// OutcomeDroppedGate: the fail-closed gate was shut (recording not ready,
	// not the active screen-view, or aborted) — the frame never entered the
	// queue and can never egress.
	OutcomeDroppedGate Outcome = iota
	// OutcomeQueued: the frame passed the gate and is queued for the sender.
	OutcomeQueued
	// OutcomeDroppedBackpressure: the gate was open but the bounded queue was
	// full; the oldest queued frame was evicted to admit this one.
	OutcomeDroppedBackpressure
)

// ViewSession is the fail-closed source gate + bounded drop-tolerant queue for
// one VIEW_ONLY screen-view. A fresh session is CLOSED (recording not ready,
// not active): nothing egresses until BOTH SetRecordingReady(true) AND
// Activate() are called, and not after Abort(). When the gate closes for any
// reason the queue is flushed (no in-flight frame survives a gate close).
type ViewSession struct {
	mu sync.Mutex

	recordingReady bool
	active         bool
	aborted        bool

	queue [][]byte // FIFO of admitted frame payloads awaiting the sender
	cap   int

	// abortCh is closed once on Abort so a blocking producer/pump can be
	// interrupted immediately (not only between Next calls — Codex review #2).
	abortCh chan struct{}

	// counters (observability + tests)
	queued          int64
	droppedGate     int64
	droppedBackpres int64
	flushed         int64
	drained         int64
}

// NewViewSession returns a CLOSED session (fail-closed default) with the given
// queue cap (<=0 uses DefaultQueueCap).
func NewViewSession(queueCap int) *ViewSession {
	if queueCap <= 0 {
		queueCap = DefaultQueueCap
	}
	return &ViewSession{cap: queueCap, abortCh: make(chan struct{})}
}

// AbortChan is closed when Abort fires — a select-able signal so a blocking
// producer/pump aborts immediately rather than only between Next calls.
func (s *ViewSession) AbortChan() <-chan struct{} { return s.abortCh }

// canSendLocked is the single source-of-truth gate predicate. Fail-closed:
// ALL three must hold. Any false → no egress.
func (s *ViewSession) canSendLocked() bool {
	return s.recordingReady && s.active && !s.aborted
}

// CanSend reports whether the gate is currently open.
func (s *ViewSession) CanSend() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.canSendLocked()
}

// Offer presents one captured frame to the gate. Non-blocking. If the gate is
// shut the frame is dropped (never queued). If open it is queued; on a full
// queue the oldest frame is evicted (drop-tolerant backpressure). Offer never
// blocks so it cannot delay the CONTROL-plane KILL path.
func (s *ViewSession) Offer(f Frame) Outcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.canSendLocked() {
		s.droppedGate++
		return OutcomeDroppedGate
	}
	out := OutcomeQueued
	if len(s.queue) >= s.cap {
		// evict oldest (freshest screen state wins)
		s.queue = s.queue[1:]
		s.droppedBackpres++
		out = OutcomeDroppedBackpressure
	}
	// store a copy so the producer may reuse its buffer
	s.queue = append(s.queue, append([]byte(nil), f.Payload...))
	s.queued++
	return out
}

// Drain removes and returns up to n queued frames for the sender (FIFO). A
// closed gate does NOT block draining of already-admitted frames — but in
// practice the gate-close paths flush the queue first, so a drained frame was
// admitted while the gate was open. Returns nil when empty.
func (s *ViewSession) Drain(n int) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Defense-in-depth (Codex review #2): never egress after local-abort, even
	// if a flush somehow raced. The gate-close paths already flush, so this is
	// a second sender-side kill-safe stop, not the primary one.
	if s.aborted {
		return nil
	}
	if n <= 0 || len(s.queue) == 0 {
		return nil
	}
	if n > len(s.queue) {
		n = len(s.queue)
	}
	out := s.queue[:n:n]
	s.queue = s.queue[n:]
	s.drained += int64(n)
	return out
}

// flushLocked drops every queued frame (no egress) and counts them.
func (s *ViewSession) flushLocked() {
	if len(s.queue) > 0 {
		s.flushed += int64(len(s.queue))
		s.queue = nil
	}
}

// SetRecordingReady toggles the recording-ready precondition. Going false
// shuts the gate AND flushes the queue (no unrecorded frame may egress —
// ADR-0034 D3 fail-closed recording mandate).
func (s *ViewSession) SetRecordingReady(ready bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordingReady = ready
	if !ready {
		s.flushLocked()
	}
}

// Activate marks this the active VIEW_ONLY screen-view (gate precondition).
func (s *ViewSession) Activate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = true
}

// Deactivate ends the active screen-view: shuts the gate AND flushes the
// queue (the view ended, nothing more egresses).
func (s *ViewSession) Deactivate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = false
	s.flushLocked()
}

// Abort is the user/endpoint LOCAL-ABORT: permanently shuts the gate AND
// flushes the queue. Idempotent and irreversible for this session (a new
// session is required to resume) — the strongest exfil stop.
func (s *ViewSession) Abort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.aborted {
		s.aborted = true
		close(s.abortCh) // signal blocking producer/pump exactly once
	}
	s.flushLocked()
}

// Aborted reports whether local-abort fired.
func (s *ViewSession) Aborted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.aborted
}

// Counters snapshots (queued, droppedGate, droppedBackpressure, flushed,
// drained) for telemetry + tests.
func (s *ViewSession) Counters() (queued, droppedGate, droppedBackpressure, flushed, drained int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queued, s.droppedGate, s.droppedBackpres, s.flushed, s.drained
}

// QueueLen is the current in-flight queue depth.
func (s *ViewSession) QueueLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue)
}
