package dataplane

import "context"

// Pump drives a FrameProducer into a ViewSession's fail-closed gate. It runs
// until the context is cancelled, the producer is exhausted, or the session is
// aborted — then it Closes the producer exactly once. The gate (not the pump)
// decides egress: the pump merely offers every captured frame; a shut gate
// drops it. Offer is non-blocking, so the pump never wedges.
//
// This is the SAFETY-CORE pump (T-4 slice-1). The real Windows capture
// producer and the harness Data-stream sender that Drains the session are
// later slices; here a producer (incl. MockFrameProducer) is gated end-to-end.
type Pump struct {
	producer FrameProducer
	session  *ViewSession
}

// NewPump binds a producer to a session.
func NewPump(producer FrameProducer, session *ViewSession) *Pump {
	return &Pump{producer: producer, session: session}
}

// Run offers frames until ctx is done, the producer ends, or the session is
// aborted. A watcher goroutine Closes the producer on ctx-cancel or local-abort
// so a producer whose Next() BLOCKS (e.g. the real DXGI capture waiting on the
// next vsync) is interrupted IMMEDIATELY, not only between Next calls (Codex
// review #2 — instant local-abort). The producer is always Closed once before
// Run returns (Close must be idempotent); Run returns the Close error.
func (p *Pump) Run(ctx context.Context) (err error) {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
		case <-p.session.AbortChan():
		case <-stop:
			return
		}
		_ = p.producer.Close() // unblocks a blocking Next → it must return ok=false
	}()
	defer func() { err = p.producer.Close() }()
	for {
		// Cheap pre-checks so an aborted/cancelled pump stops promptly without
		// pulling another frame (the watcher covers an already-blocked Next).
		if ctx.Err() != nil {
			return
		}
		if p.session.Aborted() {
			return
		}
		frame, ok := p.producer.Next()
		if !ok {
			return
		}
		// Offer is non-blocking; a shut gate drops the frame fail-closed.
		p.session.Offer(frame)
	}
}
