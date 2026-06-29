// Package screenview implements the agent-side VIEW_ONLY screen-observation dispatcher (Faz 22.6 #1580
// slice-2). On a broker-authorized VIEW_ONLY permit it authorizes (sharing the PTY per-session seq guard),
// opens a recording-OFF fail-closed source gate (dataplane.ViewSession), drives a pluggable FrameProducer into
// the gate (dataplane.Pump), and CONCURRENTLY drains admitted frames to the DATA stream as image DataFrames —
// a live feed, not a buffer dump. The instant the context is cancelled (a session KILL / transport teardown,
// wired by the harness) the gate is aborted and no further frame egresses (ADR-0034 D3 + D8; recording-OFF per
// ADR-0044 D3; Codex 019f10e2).
//
// This package owns the dispatch ORCHESTRATION + the recording-OFF policy decision; it does NOT own screen
// capture — the FrameProducer is injected (a Session-0 active-desktop helper in production, a mock in tests),
// so the dispatcher is testable without a display.
package screenview

import (
	"context"
	"fmt"
	"time"

	"platform-agent/internal/remotebridge/dataplane"
	"platform-agent/internal/remotebridge/operation"
	pb "platform-agent/internal/remotebridge/pb"
)

// defaults
const (
	defaultDrainInterval = 16 * time.Millisecond // ~60fps drain cadence; the gate is drop-tolerant
	defaultDrainBatch    = 8                     // max frames pulled per drain tick
	defaultContentType   = "image/png"
)

// ProducerFactory builds a fresh FrameProducer for one screen-view stream (the stream id correlates the DATA
// frames). The production factory is the Session-0 active-desktop capture helper (a later sub-slice); tests
// inject a mock. An error fails the dispatch fail-closed (no gate opened, no frames).
type ProducerFactory func(ctx context.Context, streamID string) (dataplane.FrameProducer, error)

// ViewOnlyAuthorizer is the VIEW_ONLY permit gate the dispatcher consults. The production implementation is
// *operation.Authorizer (whose AuthorizeViewOnly shares the per-session seq guard with the PTY path — pass the
// SAME instance both dispatchers use); the interface keeps the dispatcher testable without real crypto.
type ViewOnlyAuthorizer interface {
	AuthorizeViewOnly(permit operation.OperationPermit, nowEpochMillis int64) operation.Decision
}

// Dispatcher implements harness.ScreenViewDispatcher for the recording-OFF VIEW_ONLY pilot.
type Dispatcher struct {
	authorizer    ViewOnlyAuthorizer
	newProducer   ProducerFactory
	queueCap      int
	drainInterval time.Duration
	drainBatch    int
	contentType   string
	clock         func() int64
}

// Options tunes a Dispatcher; the zero value uses safe defaults.
type Options struct {
	QueueCap      int
	DrainInterval time.Duration
	DrainBatch    int
	ContentType   string
	Clock         func() int64
}

// New builds a recording-OFF VIEW_ONLY dispatcher. authorizer and newProducer are required; pass the SAME
// operation.Authorizer the PTY dispatcher uses so PTY and VIEW_ONLY share one per-session seq window.
func New(authorizer ViewOnlyAuthorizer, newProducer ProducerFactory, opts Options) (*Dispatcher, error) {
	if authorizer == nil {
		return nil, fmt.Errorf("screenview: authorizer is required")
	}
	if newProducer == nil {
		return nil, fmt.Errorf("screenview: producer factory is required")
	}
	d := &Dispatcher{
		authorizer:    authorizer,
		newProducer:   newProducer,
		queueCap:      opts.QueueCap,
		drainInterval: opts.DrainInterval,
		drainBatch:    opts.DrainBatch,
		contentType:   opts.ContentType,
		clock:         opts.Clock,
	}
	if d.drainInterval <= 0 {
		d.drainInterval = defaultDrainInterval
	}
	if d.drainBatch <= 0 {
		d.drainBatch = defaultDrainBatch
	}
	if d.contentType == "" {
		d.contentType = defaultContentType
	}
	if d.clock == nil {
		d.clock = func() int64 { return time.Now().UnixMilli() }
	}
	return d, nil
}

// Handle implements harness.ScreenViewDispatcher: authorize the VIEW_ONLY permit, then stream screen frames to
// send until the producer ends or ctx is cancelled. A failed authorization (or a capture-start failure) returns
// an error WITHOUT opening the gate or emitting any frame (fail-closed). On a clean producer-end it emits a
// terminal EndStream and returns nil; on ctx cancellation it aborts the gate (flush, no post-abort egress) and
// returns nil (a KILL/teardown is intentional, not a handler failure). A broken DATA send aborts + returns the
// error.
func (d *Dispatcher) Handle(ctx context.Context, permit operation.OperationPermit, streamID string,
	send func(*pb.DataFrame) error, nowEpochMillis int64) error {
	if decision := d.authorizer.AuthorizeViewOnly(permit, nowEpochMillis); !decision.Allowed {
		return fmt.Errorf("view-only-authorize-denied:%s", decision.Reason)
	}

	session := dataplane.NewViewSession(d.queueCap)
	// recording-OFF mode (ADR-0044 D3): no WORM recorder — the gate egresses on the explicit recording-OFF
	// acknowledgement, never a faked recordingReady. Then mark this the active screen-view.
	session.SetRecordingNotRequired(true)
	session.Activate()

	producer, err := d.newProducer(ctx, streamID)
	if err != nil {
		session.Abort()
		return fmt.Errorf("view-only-capture-start-failed")
	}

	pump := dataplane.NewPump(producer, session)
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		_ = pump.Run(ctx) // Pump closes the producer once; offers frames to the gate (drop-tolerant)
	}()

	var seq int64
	drain := func() error {
		for _, payload := range session.Drain(d.drainBatch) {
			if serr := send(&pb.DataFrame{
				StreamId:    streamID,
				FrameSeq:    seq,
				ContentType: d.contentType,
				Payload:     payload,
			}); serr != nil {
				return serr
			}
			seq++
		}
		return nil
	}

	ticker := time.NewTicker(d.drainInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// KILL / transport teardown: abort the gate (flush, no further egress) — intentional, not a failure.
			session.Abort()
			return nil
		case <-pumpDone:
			// The producer ended. When ctx is also cancelled, BOTH this case and the ctx.Done()
			// case are ready and select picks one at random — so the producer may have stopped
			// BECAUSE of the cancellation. Treat that as cancellation (abort, NO terminal
			// EndStream), matching the ctx.Done() branch, so a cancelled dispatch never emits an
			// EndStream regardless of select ordering (deterministic; was a -race flake).
			if ctx.Err() != nil {
				session.Abort()
				return nil
			}
			// clean producer-exhaustion: drain whatever the gate still holds, then a best-effort
			// terminal EndStream.
			if derr := drain(); derr != nil {
				session.Abort()
				return derr
			}
			_ = send(&pb.DataFrame{StreamId: streamID, FrameSeq: seq, ContentType: d.contentType, EndStream: true})
			return nil
		case <-ticker.C:
			if derr := drain(); derr != nil {
				session.Abort()
				return derr
			}
		}
	}
}
