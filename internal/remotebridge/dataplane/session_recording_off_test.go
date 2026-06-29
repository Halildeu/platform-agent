package dataplane

import "testing"

// Faz 22.6 #1580 slice-2 (Codex 019f10e2 option b) — the recording-OFF gate input. recordingNotRequired is a
// SEPARATE, default-false egress precondition; it never stands in for a ready WORM recorder.

func TestRecordingOffGateClosedByDefault(t *testing.T) {
	s := NewViewSession(0)
	s.Activate() // active alone is not enough
	if s.CanSend() {
		t.Fatal("a session with neither recordingReady nor recordingNotRequired must be gate-closed")
	}
	if out := s.Offer(Frame{Seq: 1, Payload: []byte("x")}); out != OutcomeDroppedGate {
		t.Fatalf("frame must be dropped by the closed gate, got %v", out)
	}
}

func TestRecordingNotRequiredAloneIsNotEnough(t *testing.T) {
	s := NewViewSession(0)
	s.SetRecordingNotRequired(true) // recording-OFF acknowledged, but NOT active
	if s.CanSend() {
		t.Fatal("recordingNotRequired without Activate must stay gate-closed (fail-closed)")
	}
}

func TestRecordingNotRequiredPlusActiveOpensGate(t *testing.T) {
	s := NewViewSession(0)
	s.SetRecordingNotRequired(true)
	s.Activate()
	if !s.CanSend() {
		t.Fatal("recordingNotRequired AND active must open the gate")
	}
	if out := s.Offer(Frame{Seq: 1, Payload: []byte("frame")}); out != OutcomeQueued {
		t.Fatalf("frame must be queued through the open recording-OFF gate, got %v", out)
	}
	if got := s.Drain(1); len(got) != 1 || string(got[0]) != "frame" {
		t.Fatalf("the admitted frame must drain, got %v", got)
	}
}

func TestRecordingNotRequiredFalseShutsGateAndFlushes(t *testing.T) {
	s := NewViewSession(0)
	s.SetRecordingNotRequired(true)
	s.Activate()
	s.Offer(Frame{Seq: 1, Payload: []byte("frame")})
	if s.QueueLen() != 1 {
		t.Fatalf("expected 1 queued frame, got %d", s.QueueLen())
	}

	s.SetRecordingNotRequired(false) // withdraw recording-OFF authorization

	if s.CanSend() {
		t.Fatal("gate must shut once recording-OFF authorization is withdrawn")
	}
	if s.QueueLen() != 0 {
		t.Fatal("withdrawing recording-OFF authorization must flush the queue (no unauthorized egress)")
	}
	if out := s.Offer(Frame{Seq: 2, Payload: []byte("y")}); out != OutcomeDroppedGate {
		t.Fatalf("post-withdrawal frame must be gate-dropped, got %v", out)
	}
}

func TestRecordingOffDoesNotImplyRecordingReady(t *testing.T) {
	// the two inputs are independent: recording-OFF must not flip the WORM-readiness bit.
	s := NewViewSession(0)
	s.SetRecordingNotRequired(true)
	s.Activate()
	// withdrawing recordingReady (which was never set) must not re-open anything; gate still open via not-required
	s.SetRecordingReady(false)
	if !s.CanSend() {
		t.Fatal("recordingReady(false) must not affect an open recording-OFF gate")
	}
	// but aborting still wins over both inputs
	s.Abort()
	if s.CanSend() {
		t.Fatal("abort must shut the gate regardless of the recording inputs")
	}
}

func TestAbortBeatsRecordingNotRequired(t *testing.T) {
	s := NewViewSession(0)
	s.SetRecordingNotRequired(true)
	s.Activate()
	s.Abort()
	if out := s.Offer(Frame{Seq: 1, Payload: []byte("x")}); out != OutcomeDroppedGate {
		t.Fatalf("an aborted session must drop frames even with recording-OFF + active, got %v", out)
	}
	// re-setting recording-OFF after abort must NOT resurrect egress (abort is irreversible)
	s.SetRecordingNotRequired(true)
	if s.CanSend() {
		t.Fatal("abort is irreversible — recording-OFF cannot re-open an aborted session")
	}
}
