package operation

import "sync"

// CapabilityConstrainedPTY is the only capability the PTY gate authorizes — the enum NAME, matching the
// broker's RemoteSessionCapability.CONSTRAINED_PTY.
const CapabilityConstrainedPTY = "CONSTRAINED_PTY"

// Decision is the gate verdict. Allowed is true ONLY when EVERY check passed. Reason is a stable,
// bounded-cardinality code (never raw input) for telemetry/audit; it is "" exactly when Allowed.
type Decision struct {
	Allowed bool
	Reason  string
}

// Stable Decision.Reason codes (bounded cardinality — safe as a metric/audit tag).
const (
	ReasonPermitInvalid    = "permit-invalid"     // signature/kid/alg/freshness failed, or no verifier
	ReasonCapabilityNotPTY = "capability-not-pty" // the permit does not grant CONSTRAINED_PTY
	ReasonEmptyCommand     = "empty-command"      // the command canonicalises to empty (no command)
	ReasonCommandMismatch  = "command-mismatch"   // hash(command) != the permit's commandHash
	ReasonSeqInvalid       = "seq-invalid"        // permit seq <= 0 (malformed; broker seq starts >= 1)
	ReasonSeqReplay        = "seq-replay"         // permit seq <= the last accepted seq for its session
)

// Authorizer is the agent-side CONSTRAINED_PTY execution gate: it admits a command ONLY against a valid,
// fresh, broker-signed permit that grants the CONSTRAINED_PTY capability for exactly that (canonicalised)
// command, with a strictly-increasing per-session seq (replay guard). It AUTHORIZES — it does not execute
// (the ConPTY executor is a later, owner-gated slice). Safe for concurrent use.
type Authorizer struct {
	verify func(OperationPermit, int64) bool // crypto verify (Verifier.Verify); nil ⇒ deny everything
	mu     sync.Mutex
	// lastSeq: sessionId -> last accepted permit seq. NOTE: this grows one entry per session; an
	// attended, named-roster pilot bounds it, but eviction on session-end (a lifecycle hook) is a follow-up
	// hardening slice, not a today concern.
	lastSeq map[string]int64
}

// NewAuthorizer builds the gate over a permit verifier. A nil verifier means "deny everything" (fail-closed).
func NewAuthorizer(verifier *Verifier) *Authorizer {
	var fn func(OperationPermit, int64) bool
	if verifier != nil {
		fn = verifier.Verify
	}
	return newAuthorizer(fn)
}

// newAuthorizer is the internal constructor (also used by tests to inject a verify func).
func newAuthorizer(verify func(OperationPermit, int64) bool) *Authorizer {
	return &Authorizer{verify: verify, lastSeq: make(map[string]int64)}
}

// Authorize runs the full fail-closed gate for executing commandLine under permit at nowEpochMillis. It
// returns Allowed=true ONLY if, IN ORDER: (1) the permit cryptographically verifies (sig/kid/alg/freshness)
// — never trust an unverified field; (2) it grants CONSTRAINED_PTY; (3) the canonicalised command is
// non-empty and its hash equals the permit's commandHash; (4) the permit's seq is strictly greater than the
// last accepted seq for its session. On allow, the session's last-seq advances atomically. Any failure →
// Allowed=false with a stable Reason and NO state change.
func (a *Authorizer) Authorize(permit OperationPermit, commandLine string, nowEpochMillis int64) Decision {
	if a == nil || a.verify == nil || !a.verify(permit, nowEpochMillis) {
		return Decision{Reason: ReasonPermitInvalid}
	}
	if permit.Capability != CapabilityConstrainedPTY {
		return Decision{Reason: ReasonCapabilityNotPTY}
	}
	cmd := ParseCommand(commandLine)
	if cmd.IsEmpty() {
		return Decision{Reason: ReasonEmptyCommand}
	}
	if cmd.Hash() != permit.CommandHash {
		return Decision{Reason: ReasonCommandMismatch}
	}
	// A non-positive seq is malformed (the broker's per-session seq starts >= 1) — distinct from a replay so
	// audit/metrics can tell them apart.
	if permit.Seq <= 0 {
		return Decision{Reason: ReasonSeqInvalid}
	}
	// NOTE (slice-5): binding permit.DeviceID to THIS agent's device identity is a harness concern (the gate
	// holds no device identity) — explicitly deferred to the harness-wiring slice, not silently skipped.
	// Replay guard LAST + under lock: a verified+bound permit advances the per-session window atomically; an
	// equal/older seq is a replay → deny with NO state change.
	a.mu.Lock()
	defer a.mu.Unlock()
	if permit.Seq <= a.lastSeq[permit.SessionID] {
		return Decision{Reason: ReasonSeqReplay}
	}
	a.lastSeq[permit.SessionID] = permit.Seq
	return Decision{Allowed: true}
}
