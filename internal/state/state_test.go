package state

import (
	"testing"
	"time"
)

func TestTrackerTransitionsFromOnlineToDegradedAndOffline(t *testing.T) {
	tracker := NewTracker(StateOnline)
	now := time.Now()

	for i := 0; i < 2; i++ {
		if got := tracker.RecordFailure(now); got != StateOnline {
			t.Fatalf("failure %d state = %s, want %s", i+1, got, StateOnline)
		}
	}
	if got := tracker.RecordFailure(now); got != StateDegraded {
		t.Fatalf("third failure state = %s, want %s", got, StateDegraded)
	}
	for i := 0; i < 7; i++ {
		tracker.RecordFailure(now)
	}
	if got := tracker.State(); got != StateOffline {
		t.Fatalf("state = %s, want %s", got, StateOffline)
	}
}

func TestTrackerSuccessReturnsOnline(t *testing.T) {
	tracker := NewTracker(StateOnline)
	now := time.Now()
	for i := 0; i < 3; i++ {
		tracker.RecordFailure(now)
	}
	if got := tracker.State(); got != StateDegraded {
		t.Fatalf("state = %s, want %s", got, StateDegraded)
	}
	if got := tracker.RecordSuccess(); got != StateOnline {
		t.Fatalf("state after success = %s, want %s", got, StateOnline)
	}
	if tracker.ConsecutiveFailures() != 0 {
		t.Fatalf("failures after success = %d, want 0", tracker.ConsecutiveFailures())
	}
}
