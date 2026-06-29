package operation

import "testing"

// Faz 22.6 #1580 slice-2 (Codex 019f10e2) — the VIEW_ONLY authorize path, sharing the PTY per-session seq guard.

func viewOnlyPermit(sess, op string, seq int64) OperationPermit {
	return OperationPermit{Capability: CapabilityViewOnly, CommandHash: "", SessionID: sess, OperationID: op, Seq: seq}
}

func passVerify(OperationPermit, int64) bool { return true }

func TestAuthorizeViewOnlyHappy(t *testing.T) {
	if d := newAuthorizer(passVerify).AuthorizeViewOnly(viewOnlyPermit("s", "op-1", 1), 1); !d.Allowed || d.Reason != "" {
		t.Fatalf("a valid VIEW_ONLY permit must be allowed, got allowed=%v reason=%q", d.Allowed, d.Reason)
	}
}

func TestAuthorizeViewOnlyPolicyChecks(t *testing.T) {
	az := func() *Authorizer { return newAuthorizer(passVerify) }

	if d := az().AuthorizeViewOnly(OperationPermit{Capability: CapabilityConstrainedPTY, SessionID: "s", OperationID: "op", Seq: 1}, 1); d.Allowed || d.Reason != ReasonCapabilityNotViewOnly {
		t.Fatalf("non-VIEW_ONLY capability must reject capability-not-view-only, got %q", d.Reason)
	}
	if d := az().AuthorizeViewOnly(OperationPermit{Capability: CapabilityViewOnly, CommandHash: "deadbeef", SessionID: "s", OperationID: "op", Seq: 1}, 1); d.Allowed || d.Reason != ReasonCommandHashPresent {
		t.Fatalf("a VIEW_ONLY permit carrying a command hash must reject command-hash-present, got %q", d.Reason)
	}
	if d := az().AuthorizeViewOnly(viewOnlyPermit("", "op", 1), 1); d.Allowed || d.Reason != ReasonMissingSessionID {
		t.Fatalf("empty session id must reject missing-session-id, got %q", d.Reason)
	}
	if d := az().AuthorizeViewOnly(viewOnlyPermit("s", "", 1), 1); d.Allowed || d.Reason != ReasonMissingOperationID {
		t.Fatalf("empty operation id must reject missing-operation-id, got %q", d.Reason)
	}
	for _, badSeq := range []int64{0, -1} {
		if d := az().AuthorizeViewOnly(viewOnlyPermit("s", "op", badSeq), 1); d.Allowed || d.Reason != ReasonSeqInvalid {
			t.Fatalf("seq=%d must reject seq-invalid, got %q", badSeq, d.Reason)
		}
	}
}

func TestAuthorizeViewOnlyReplay(t *testing.T) {
	az := newAuthorizer(passVerify)
	if d := az.AuthorizeViewOnly(viewOnlyPermit("s", "op-1", 3), 1); !d.Allowed {
		t.Fatalf("seq=3 should be allowed, got %q", d.Reason)
	}
	if d := az.AuthorizeViewOnly(viewOnlyPermit("s", "op-2", 3), 1); d.Allowed || d.Reason != ReasonSeqReplay {
		t.Fatalf("a replayed seq=3 must reject seq-replay, got allowed=%v reason=%q", d.Allowed, d.Reason)
	}
	if d := az.AuthorizeViewOnly(viewOnlyPermit("s", "op-3", 2), 1); d.Allowed || d.Reason != ReasonSeqReplay {
		t.Fatalf("an older seq=2 must reject seq-replay, got %q", d.Reason)
	}
}

func TestAuthorizeViewOnlyFailClosed(t *testing.T) {
	if d := newAuthorizer(func(OperationPermit, int64) bool { return false }).AuthorizeViewOnly(viewOnlyPermit("s", "op", 1), 1); d.Allowed || d.Reason != ReasonPermitInvalid {
		t.Fatalf("a failing verifier must deny, got allowed=%v reason=%q", d.Allowed, d.Reason)
	}
	var nilAz *Authorizer
	if d := nilAz.AuthorizeViewOnly(viewOnlyPermit("s", "op", 1), 1); d.Allowed || d.Reason != ReasonPermitVerifierUnavailable {
		t.Fatalf("a nil authorizer must deny verifier-unavailable, got %q", d.Reason)
	}
	if d := newAuthorizer(nil).AuthorizeViewOnly(viewOnlyPermit("s", "op", 1), 1); d.Allowed || d.Reason != ReasonPermitVerifierUnavailable {
		t.Fatalf("a nil verifier must deny verifier-unavailable, got %q", d.Reason)
	}
}

// TestSharedSeqGuardAcrossCapabilities is the security-critical invariant (Codex 019f10e2): PTY and VIEW_ONLY
// MUST advance ONE per-session seq window. Two separate windows would let a VIEW_ONLY permit replay a seq a PTY
// operation already consumed (or vice-versa) — a cross-capability replay hole.
func TestSharedSeqGuardAcrossCapabilities(t *testing.T) {
	cmd := "hostname"
	h := ParseCommand(cmd).Hash()
	az := newAuthorizer(passVerify)

	// a PTY op consumes seq 5 for session s
	if d := az.Authorize(OperationPermit{Capability: CapabilityConstrainedPTY, CommandHash: h, SessionID: "s", Seq: 5}, cmd, 1); !d.Allowed {
		t.Fatalf("PTY seq=5 should be allowed, got %q", d.Reason)
	}
	// a VIEW_ONLY permit reusing seq 5 on the SAME session must be a replay (shared guard)
	if d := az.AuthorizeViewOnly(viewOnlyPermit("s", "op-1", 5), 1); d.Allowed || d.Reason != ReasonSeqReplay {
		t.Fatalf("VIEW_ONLY seq=5 after PTY seq=5 must be seq-replay, got allowed=%v reason=%q", d.Allowed, d.Reason)
	}
	// VIEW_ONLY advances the SHARED window to seq 6
	if d := az.AuthorizeViewOnly(viewOnlyPermit("s", "op-2", 6), 1); !d.Allowed {
		t.Fatalf("VIEW_ONLY seq=6 should be allowed, got %q", d.Reason)
	}
	// a PTY permit reusing seq 6 must now be a replay (reverse direction)
	if d := az.Authorize(OperationPermit{Capability: CapabilityConstrainedPTY, CommandHash: h, SessionID: "s", Seq: 6}, cmd, 1); d.Allowed || d.Reason != ReasonSeqReplay {
		t.Fatalf("PTY seq=6 after VIEW_ONLY seq=6 must be seq-replay, got allowed=%v reason=%q", d.Allowed, d.Reason)
	}
	// a different session has an independent window
	if d := az.AuthorizeViewOnly(viewOnlyPermit("s2", "op-1", 1), 1); !d.Allowed {
		t.Fatalf("VIEW_ONLY seq=1 on a fresh session should be allowed, got %q", d.Reason)
	}
}

// TestAuthorizeViewOnlyDenyDoesNotAdvanceSeq: a denied VIEW_ONLY permit must not advance the shared window.
func TestAuthorizeViewOnlyDenyDoesNotAdvanceSeq(t *testing.T) {
	az := newAuthorizer(passVerify)
	// a denied permit (command hash present) at seq 5 must NOT advance the window
	if d := az.AuthorizeViewOnly(OperationPermit{Capability: CapabilityViewOnly, CommandHash: "x", SessionID: "s", OperationID: "op", Seq: 5}, 1); d.Allowed {
		t.Fatal("a command-hash-present VIEW_ONLY permit must be denied")
	}
	// seq 5 is still available because the deny did not advance the window
	if d := az.AuthorizeViewOnly(viewOnlyPermit("s", "op", 5), 1); !d.Allowed {
		t.Fatalf("seq=5 must still be available after a denied permit, got %q", d.Reason)
	}
}
