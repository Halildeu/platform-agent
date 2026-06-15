package operation

import "testing"

// full stack: the real broker-signed fixture authorizes its bound command, and the gate enforces replay,
// command-binding, and freshness end-to-end (real ECDSA verify).
func TestAuthorizeFullStackWithBrokerVector(t *testing.T) {
	v := loadVector(t)
	ver, err := NewVerifier(v.BrokerPublicKeyB64, v.Kid)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	az := NewAuthorizer(ver)
	if d := az.Authorize(v.permit(), v.CommandLine, freshNow); !d.Allowed {
		t.Fatalf("fixture permit should authorize, got reason=%q", d.Reason)
	}
	// replay: the very same permit (same seq) is now denied
	if d := az.Authorize(v.permit(), v.CommandLine, freshNow); d.Allowed || d.Reason != ReasonSeqReplay {
		t.Fatalf("replay must be seq-replay, got allowed=%v reason=%q", d.Allowed, d.Reason)
	}
	// a valid permit but the WRONG command (hash mismatch) — fresh authorizer so seq is not consumed
	if d := NewAuthorizer(ver).Authorize(v.permit(), "whoami", freshNow); d.Allowed || d.Reason != ReasonCommandMismatch {
		t.Fatalf("wrong command must be command-mismatch, got allowed=%v reason=%q", d.Allowed, d.Reason)
	}
	// expired permit → the crypto gate (verify) fails first
	if d := NewAuthorizer(ver).Authorize(v.permit(), v.CommandLine, v.ExpiresAtEpochMillis); d.Allowed || d.Reason != ReasonPermitInvalid {
		t.Fatalf("expired must be permit-invalid, got allowed=%v reason=%q", d.Allowed, d.Reason)
	}
}

// policy checks (capability / command / seq) with an injected pass-through verify, so they can be exercised
// with hand-built permits independent of the crypto layer (which the full-stack test covers).
func TestAuthorizePolicyChecks(t *testing.T) {
	pass := func(OperationPermit, int64) bool { return true }
	hostnameHash := ParseCommand("hostname").Hash()
	mk := func(cap, cmdHash, sess string, seq int64) OperationPermit {
		return OperationPermit{Capability: cap, CommandHash: cmdHash, SessionID: sess, Seq: seq}
	}

	if d := newAuthorizer(pass).Authorize(mk("VIEW_ONLY", hostnameHash, "s", 1), "hostname", 1); d.Allowed || d.Reason != ReasonCapabilityNotPTY {
		t.Errorf("capability gate: allowed=%v reason=%q", d.Allowed, d.Reason)
	}
	if d := newAuthorizer(pass).Authorize(mk(CapabilityConstrainedPTY, "", "s", 1), "   ", 1); d.Allowed || d.Reason != ReasonEmptyCommand {
		t.Errorf("empty-command gate: allowed=%v reason=%q", d.Allowed, d.Reason)
	}
	if d := newAuthorizer(pass).Authorize(mk(CapabilityConstrainedPTY, hostnameHash, "s", 1), "whoami", 1); d.Allowed || d.Reason != ReasonCommandMismatch {
		t.Errorf("command-mismatch gate: allowed=%v reason=%q", d.Allowed, d.Reason)
	}
	for _, badSeq := range []int64{0, -1} {
		if d := newAuthorizer(pass).Authorize(mk(CapabilityConstrainedPTY, hostnameHash, "s", badSeq), "hostname", 1); d.Allowed || d.Reason != ReasonSeqInvalid {
			t.Errorf("seq=%d must be seq-invalid: allowed=%v reason=%q", badSeq, d.Allowed, d.Reason)
		}
	}

	// seq: strictly-increasing per session; replay (==) and regress (<) denied; sessions independent.
	az := newAuthorizer(pass)
	if d := az.Authorize(mk(CapabilityConstrainedPTY, hostnameHash, "sA", 1), "hostname", 1); !d.Allowed {
		t.Errorf("sA seq=1 first should allow: %q", d.Reason)
	}
	if d := az.Authorize(mk(CapabilityConstrainedPTY, hostnameHash, "sA", 1), "hostname", 1); d.Reason != ReasonSeqReplay {
		t.Errorf("sA seq=1 again must replay: %q", d.Reason)
	}
	if d := az.Authorize(mk(CapabilityConstrainedPTY, hostnameHash, "sA", 2), "hostname", 1); !d.Allowed {
		t.Errorf("sA seq=2 should allow: %q", d.Reason)
	}
	if d := az.Authorize(mk(CapabilityConstrainedPTY, hostnameHash, "sA", 1), "hostname", 1); d.Reason != ReasonSeqReplay {
		t.Errorf("sA seq=1 regress must replay: %q", d.Reason)
	}
	if d := az.Authorize(mk(CapabilityConstrainedPTY, hostnameHash, "sB", 1), "hostname", 1); !d.Allowed {
		t.Errorf("sB seq=1 (independent session) should allow: %q", d.Reason)
	}
}

func TestAuthorizeFailClosed(t *testing.T) {
	hostnameHash := ParseCommand("hostname").Hash()
	good := OperationPermit{Capability: CapabilityConstrainedPTY, CommandHash: hostnameHash, SessionID: "s", Seq: 1}

	if d := NewAuthorizer(nil).Authorize(good, "hostname", 1); d.Allowed || d.Reason != ReasonPermitInvalid {
		t.Errorf("nil verifier must deny permit-invalid: allowed=%v reason=%q", d.Allowed, d.Reason)
	}
	if d := newAuthorizer(func(OperationPermit, int64) bool { return false }).Authorize(good, "hostname", 1); d.Allowed || d.Reason != ReasonPermitInvalid {
		t.Errorf("verify-false must deny permit-invalid: allowed=%v reason=%q", d.Allowed, d.Reason)
	}
	var nilAz *Authorizer
	if d := nilAz.Authorize(good, "hostname", 1); d.Allowed {
		t.Error("nil authorizer must deny")
	}
}

// a denied (replayed/mismatched) permit must NOT advance the session's seq window — a later legitimate
// permit at the contested seq still succeeds (no state change on deny).
func TestAuthorizeDenyDoesNotAdvanceSeq(t *testing.T) {
	pass := func(OperationPermit, int64) bool { return true }
	hostnameHash := ParseCommand("hostname").Hash()
	az := newAuthorizer(pass)
	mk := func(seq int64) OperationPermit {
		return OperationPermit{Capability: CapabilityConstrainedPTY, CommandHash: hostnameHash, SessionID: "s", Seq: seq}
	}
	// a command-mismatch denial at seq=5 must not consume seq=5
	if d := az.Authorize(mk(5), "whoami", 1); d.Reason != ReasonCommandMismatch {
		t.Fatalf("expected command-mismatch, got %q", d.Reason)
	}
	// the legitimate seq=5 permit still authorizes (the denial above did not advance the window)
	if d := az.Authorize(mk(5), "hostname", 1); !d.Allowed {
		t.Fatalf("seq=5 should still authorize after a denied attempt, got %q", d.Reason)
	}
}
