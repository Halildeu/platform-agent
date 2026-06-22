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
	ReasonPermitInvalid             = "permit-invalid"                         // fallback: permit verification failed
	ReasonPermitVerifierUnavailable = "permit-invalid:verifier-unavailable"    // verifier missing in the executor path
	ReasonPermitKidMismatch         = "permit-invalid:kid-mismatch"            // permit kid != configured broker kid
	ReasonPermitAlgMismatch         = "permit-invalid:alg-mismatch"            // permit alg != pinned alg
	ReasonPermitSignatureMissing    = "permit-invalid:signature-missing"       // signature field is empty
	ReasonPermitVersionMismatch     = "permit-invalid:version-mismatch"        // schema version is not pinned v1
	ReasonPermitDeviceMismatch      = "permit-invalid:device-mismatch"         // signed device id does not match this agent
	ReasonPermitNotFresh            = "permit-invalid:not-fresh"               // malformed/expired/not-yet-valid permit window
	ReasonPermitSignatureDecode     = "permit-invalid:signature-decode-failed" // signature is not valid base64/DER bytes
	ReasonPermitSignatureInvalid    = "permit-invalid:signature-invalid"       // ECDSA signature verification failed
	ReasonCapabilityNotPTY          = "capability-not-pty"                     // the permit does not grant CONSTRAINED_PTY
	ReasonCommandTooLong            = "command-too-long"                       // raw commandLine exceeds MaxCommandLine (broker MAX_LINE)
	ReasonEmptyCommand              = "empty-command"                          // the command canonicalises to empty (no command)
	ReasonCommandMismatch           = "command-mismatch"                       // hash(command) != the permit's commandHash
	ReasonSeqInvalid                = "seq-invalid"                            // permit seq <= 0 (malformed; broker seq starts >= 1)
	ReasonSeqReplay                 = "seq-replay"                             // permit seq <= the last accepted seq for its session
)

// MaxCommandLine mirrors broker PtyArgumentPolicy.MAX_LINE: the agent's "decide" layer (this gate, which
// holds the raw commandLine) bounds the whole RAW line exactly as the broker's decide() does BEFORE
// tokenising — the per-token + per-argument grammar is then enforced downstream (ptyexec arg policy,
// mirroring broker evaluate()). len() is a BYTE count; Java String.length() is UTF-16 code units. For the
// ASCII command surface the D-2 guard already enforces these coincide, and for any multi-byte input the byte
// count is >= the code-unit count, so the agent is stricter-or-equal — never more permissive — here.
const MaxCommandLine = 4096

// Authorizer is the agent-side CONSTRAINED_PTY execution gate: it admits a command ONLY against a valid,
// fresh, broker-signed permit that grants the CONSTRAINED_PTY capability for exactly that (canonicalised)
// command, with a strictly-increasing per-session seq (replay guard). It AUTHORIZES — it does not execute
// (the ConPTY executor is a later, owner-gated slice). Safe for concurrent use.
type Authorizer struct {
	verify func(OperationPermit, int64) (bool, string) // crypto verify; nil ⇒ deny everything
	mu     sync.Mutex
	// lastSeq: sessionId -> last accepted permit seq. NOTE: this grows one entry per session; an
	// attended, named-roster pilot bounds it, but eviction on session-end (a lifecycle hook) is a follow-up
	// hardening slice, not a today concern.
	lastSeq map[string]int64
}

// NewAuthorizer builds the gate over a permit verifier. A nil verifier means "deny everything" (fail-closed).
func NewAuthorizer(verifier *Verifier) *Authorizer {
	var fn func(OperationPermit, int64) (bool, string)
	if verifier != nil {
		fn = verifier.VerifyWithReason
	}
	return newReasonedAuthorizer(fn)
}

// newAuthorizer is the internal constructor (also used by tests to inject a verify func).
func newAuthorizer(verify func(OperationPermit, int64) bool) *Authorizer {
	if verify == nil {
		return newReasonedAuthorizer(nil)
	}
	return newReasonedAuthorizer(func(p OperationPermit, nowEpochMillis int64) (bool, string) {
		if verify(p, nowEpochMillis) {
			return true, ""
		}
		return false, ReasonPermitInvalid
	})
}

func newReasonedAuthorizer(verify func(OperationPermit, int64) (bool, string)) *Authorizer {
	return &Authorizer{verify: verify, lastSeq: make(map[string]int64)}
}

// Authorize runs the full fail-closed gate for executing commandLine under permit at nowEpochMillis. It
// returns Allowed=true ONLY if, IN ORDER: (1) the permit cryptographically verifies (sig/kid/alg/freshness)
// — never trust an unverified field; (2) it grants CONSTRAINED_PTY; (3) the canonicalised command is
// non-empty and its hash equals the permit's commandHash; (4) the permit's seq is strictly greater than the
// last accepted seq for its session. On allow, the session's last-seq advances atomically. Any failure →
// Allowed=false with a stable Reason and NO state change.
func (a *Authorizer) Authorize(permit OperationPermit, commandLine string, nowEpochMillis int64) Decision {
	if a == nil || a.verify == nil {
		return Decision{Reason: ReasonPermitVerifierUnavailable}
	}
	if ok, reason := a.verify(permit, nowEpochMillis); !ok {
		if reason == "" {
			reason = ReasonPermitInvalid
		}
		return Decision{Reason: reason}
	}
	if permit.Capability != CapabilityConstrainedPTY {
		return Decision{Reason: ReasonCapabilityNotPTY}
	}
	// Bound the RAW line before parsing it — mirrors broker PtyArgumentPolicy.decide()'s MAX_LINE check
	// (the broker tests the whole line, including extra whitespace, before tokenising). Placed after the
	// permit verifies (don't process input for an unverified permit) but before ParseCommand, so a
	// signed-but-pathological over-long line is refused at this layer rather than only its per-argument
	// fragments downstream. Fail-closed.
	if len(commandLine) > MaxCommandLine {
		return Decision{Reason: ReasonCommandTooLong}
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
	// Device binding is enforced TWICE: the dispatch harness refuses a wrong-device permit dynamically (the
	// re-enrollment-aware PRIMARY), and operation.Verifier rejects one whose signed DeviceID != its bound
	// expectedDeviceID (the static gate/executor-path backstop, checked above inside verify). The gate itself
	// holds no device identity — it relies on the bound verifier.
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
