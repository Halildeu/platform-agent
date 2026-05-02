package state

import "time"

type AgentState string

const (
	StateStarting         AgentState = "STARTING"
	StateEnrolling        AgentState = "ENROLLING"
	StateOnline           AgentState = "ONLINE"
	StateDegraded         AgentState = "DEGRADED"
	StateOffline          AgentState = "OFFLINE"
	StateReEnrollRequired AgentState = "RE_ENROLL_REQUIRED"
	StateStopping         AgentState = "STOPPING"
)

type Tracker struct {
	state               AgentState
	consecutiveFailures int
	lastErrorAt         time.Time
}

func NewTracker(initial AgentState) *Tracker {
	if initial == "" {
		initial = StateStarting
	}
	return &Tracker{state: initial}
}

func (t *Tracker) State() AgentState {
	return t.state
}

func (t *Tracker) RecordSuccess() AgentState {
	if t.state != StateStopping && t.state != StateReEnrollRequired {
		t.state = StateOnline
	}
	t.consecutiveFailures = 0
	t.lastErrorAt = time.Time{}
	return t.state
}

func (t *Tracker) RecordFailure(now time.Time) AgentState {
	t.consecutiveFailures++
	t.lastErrorAt = now
	if t.state == StateStopping || t.state == StateReEnrollRequired {
		return t.state
	}
	if t.consecutiveFailures >= 10 {
		t.state = StateOffline
		return t.state
	}
	if t.consecutiveFailures >= 3 {
		t.state = StateDegraded
		return t.state
	}
	return t.state
}

func (t *Tracker) RequireReEnrollment() AgentState {
	t.state = StateReEnrollRequired
	return t.state
}

func (t *Tracker) Stop() AgentState {
	t.state = StateStopping
	return t.state
}

func (t *Tracker) ConsecutiveFailures() int {
	return t.consecutiveFailures
}

func (t *Tracker) LastErrorAt() time.Time {
	return t.lastErrorAt
}
