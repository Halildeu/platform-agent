package ptyexec

import (
	"errors"
	"sort"
	"testing"

	"platform-agent/internal/remotebridge/operation"
)

// sortedKeys returns the lowercased set keys, sorted — for stable comparison in the drift guard.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPilotArgPolicyParity is the DRIFT GUARD. It re-states the broker PtyArgumentPolicy PILOT_DEFAULT_POLICY
// values explicitly (the authoritative endpoint-admin-service table) and asserts the agent mirror equals them
// EXHAUSTIVELY — exact valueless-flag set, exact value-flag KEY set, exact forbidden set, exact enum
// membership (size + contents), exact ranges, exact operand rule + max. The exhaustiveness matters: it
// catches an agent-side WIDENING (an extra flag/value-flag/enum value — the broker-compromise-bypass
// direction), not just a narrowing.
//
// SCOPE of the guard (honest): the broker repo is not present here, so this CANNOT auto-detect a broker-side
// change — it pins the AGENT side to the re-stated broker values, so any agent edit must update this test
// deliberately, and a reviewer comparing this table to the broker on a broker-side change sees the divergence.
// A fully automatic cross-repo guard (a committed broker-emitted policy golden vector, like the existing
// cross-language pty-permit-vector.json) is the permanent follow-up (PR #201 follow-up 2). The agent set is
// the broker pilot set MINUS the shell-only `ver`.
func TestPilotArgPolicyParity(t *testing.T) {
	p := pilotArgPolicies()

	wantCommands := []string{"hostname", "netstat", "ping", "tracert", "whoami"}
	gotCommands := make([]string, 0, len(p))
	for k := range p {
		gotCommands = append(gotCommands, k)
	}
	sort.Strings(gotCommands)
	if !eqStrings(gotCommands, wantCommands) {
		t.Fatalf("pilot policy commands = %v, want %v (broker pilot set minus shell-only `ver`)", gotCommands, wantCommands)
	}

	// hostname — no flags, no value-flags, no forbidden, no operand.
	if s := p["hostname"]; len(s.valuelessFlags) != 0 || len(s.valueFlags) != 0 || len(s.forbiddenFlags) != 0 ||
		s.operandRule != operandNone || s.maxOperands != 0 {
		t.Errorf("hostname spec drifted: %+v", s)
	}

	// whoami — 8 valueless identity flags; value-flags EXACTLY {/fo} with enum EXACTLY {csv,table,list}; no
	// forbidden; no operand.
	whoami := p["whoami"]
	if !eqStrings(sortedKeys(whoami.valuelessFlags), []string{"/all", "/fqdn", "/groups", "/logonid", "/nh", "/priv", "/upn", "/user"}) {
		t.Errorf("whoami valueless flags drifted: %v", sortedKeys(whoami.valuelessFlags))
	}
	if !eqStrings(valueFlagKeys(whoami), []string{"/fo"}) {
		t.Errorf("whoami value-flag keys drifted: %v", valueFlagKeys(whoami))
	}
	assertEnumExactly(t, whoami, "/fo", "csv", "table", "list")
	if len(whoami.forbiddenFlags) != 0 {
		t.Errorf("whoami must have no forbidden flags: %v", sortedKeys(whoami.forbiddenFlags))
	}
	if whoami.operandRule != operandNone {
		t.Errorf("whoami must take no operand, got rule %v", whoami.operandRule)
	}

	// netstat — closed valueless set; value-flags EXACTLY {-p} with enum EXACTLY the 8 protocols; no
	// forbidden; NO operand (refresh-interval loop closed).
	netstat := p["netstat"]
	if !eqStrings(sortedKeys(netstat.valuelessFlags), []string{"-a", "-b", "-e", "-f", "-n", "-o", "-q", "-r", "-s", "-y"}) {
		t.Errorf("netstat valueless flags drifted: %v", sortedKeys(netstat.valuelessFlags))
	}
	if !eqStrings(valueFlagKeys(netstat), []string{"-p"}) {
		t.Errorf("netstat value-flag keys drifted: %v", valueFlagKeys(netstat))
	}
	assertEnumExactly(t, netstat, "-p", "tcp", "udp", "tcpv6", "udpv6", "ip", "ipv6", "icmp", "icmpv6")
	if len(netstat.forbiddenFlags) != 0 {
		t.Errorf("netstat must have no forbidden flags: %v", sortedKeys(netstat.forbiddenFlags))
	}
	if netstat.operandRule != operandNone {
		t.Errorf("netstat must take no operand (refresh interval closed), got rule %v", netstat.operandRule)
	}

	// ping — forbidden EXACTLY {-t}; valueless {-a,-4,-6,-f}; value-flags EXACTLY {-n,-w,-l,-i}; one required host.
	ping := p["ping"]
	if !eqStrings(sortedKeys(ping.forbiddenFlags), []string{"-t"}) {
		t.Errorf("ping forbidden flags must be exactly {-t}: %v", sortedKeys(ping.forbiddenFlags))
	}
	if !eqStrings(sortedKeys(ping.valuelessFlags), []string{"-4", "-6", "-a", "-f"}) {
		t.Errorf("ping valueless flags drifted: %v", sortedKeys(ping.valuelessFlags))
	}
	if !eqStrings(valueFlagKeys(ping), []string{"-i", "-l", "-n", "-w"}) {
		t.Errorf("ping value-flag keys drifted: %v", valueFlagKeys(ping))
	}
	assertIntRange(t, ping, "-n", 1, 10)
	assertIntRange(t, ping, "-w", 1, 60000)
	assertIntRange(t, ping, "-l", 1, 8192)
	assertIntRange(t, ping, "-i", 1, 255)
	if ping.operandRule != operandRequiredHost || ping.maxOperands != 1 {
		t.Errorf("ping must require exactly one host operand, got rule=%v max=%d", ping.operandRule, ping.maxOperands)
	}

	// tracert — valueless {-d,-4,-6}; value-flags EXACTLY {-h,-w}; no forbidden; one required host.
	tracert := p["tracert"]
	if !eqStrings(sortedKeys(tracert.valuelessFlags), []string{"-4", "-6", "-d"}) {
		t.Errorf("tracert valueless flags drifted: %v", sortedKeys(tracert.valuelessFlags))
	}
	if !eqStrings(valueFlagKeys(tracert), []string{"-h", "-w"}) {
		t.Errorf("tracert value-flag keys drifted: %v", valueFlagKeys(tracert))
	}
	assertIntRange(t, tracert, "-h", 1, 255)
	assertIntRange(t, tracert, "-w", 1, 60000)
	if len(tracert.forbiddenFlags) != 0 {
		t.Errorf("tracert must have no forbidden flags: %v", sortedKeys(tracert.forbiddenFlags))
	}
	if tracert.operandRule != operandRequiredHost || tracert.maxOperands != 1 {
		t.Errorf("tracert must require exactly one host operand, got rule=%v max=%d", tracert.operandRule, tracert.maxOperands)
	}
}

// valueFlagKeys returns the sorted value-flag keys of a spec (for exact-set drift comparison).
func valueFlagKeys(s argCommandSpec) []string {
	out := make([]string, 0, len(s.valueFlags))
	for k := range s.valueFlags {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// assertEnumExactly checks an enum value-flag accepts EXACTLY the given members (size + each) and nothing
// else of a known-foreign token — catching an agent-side enum WIDENING.
func assertEnumExactly(t *testing.T, s argCommandSpec, flag string, members ...string) {
	t.Helper()
	vs, ok := s.valueFlags[flag]
	if !ok || vs.integer {
		t.Errorf("%s must be an enum value flag, got %+v (ok=%v)", flag, vs, ok)
		return
	}
	if len(vs.enum) != len(members) {
		t.Errorf("%s enum size = %d, want %d (%v)", flag, len(vs.enum), len(members), members)
	}
	for _, m := range members {
		if !vs.accepts(m) {
			t.Errorf("%s enum must accept %q", flag, m)
		}
	}
	if vs.accepts("__not_a_member__") {
		t.Errorf("%s enum must reject a foreign token", flag)
	}
}

func assertIntRange(t *testing.T, s argCommandSpec, flag string, lo, hi int64) {
	t.Helper()
	vs, ok := s.valueFlags[flag]
	if !ok || !vs.integer {
		t.Errorf("%s must be an integer-range value flag, got %+v (ok=%v)", flag, vs, ok)
		return
	}
	if vs.min != lo || vs.max != hi {
		t.Errorf("%s range drifted: [%d,%d], want [%d,%d]", flag, vs.min, vs.max, lo, hi)
	}
	if vs.accepts("0") || !vs.accepts(itoa(lo)) || !vs.accepts(itoa(hi)) || vs.accepts(itoa(hi+1)) {
		t.Errorf("%s range edges wrong for [%d,%d]", flag, lo, hi)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// TestDefaultAllowlistArgPolicyParity asserts every runnable command has a non-nil ArgPolicy AND the policy
// key set exactly equals the allowlist key set (no runnable command without a policy; no orphan policy).
func TestDefaultAllowlistArgPolicyParity(t *testing.T) {
	allow := DefaultAllowlist()
	policies := pilotArgPolicies()

	for id, rule := range allow {
		if rule.ArgPolicy == nil {
			t.Errorf("DefaultAllowlist[%q] has a nil ArgPolicy — every LIVE-runnable command MUST carry one (#1612)", id)
		}
		if _, ok := policies[id]; !ok {
			t.Errorf("DefaultAllowlist[%q] has no matching pilotArgPolicies entry (drift)", id)
		}
	}
	for id := range policies {
		if _, ok := allow[id]; !ok {
			t.Errorf("pilotArgPolicies[%q] has no matching DefaultAllowlist command (orphan policy)", id)
		}
	}
}

// TestArgPolicyThroughBuildExecPlan exercises the real wiring: ParseCommand → DefaultAllowlist → BuildExecPlan,
// asserting each broker-mirrored allow/deny outcome. Deny cases assert BOTH the generic ErrArgPolicy gate and
// the specific reason sentinel (proving the double-wrap surfaces the metered reason).
func TestArgPolicyThroughBuildExecPlan(t *testing.T) {
	allow := DefaultAllowlist()
	cases := []struct {
		name string
		line string
		// wantErr nil ⇒ must build; non-nil ⇒ must fail with errors.Is(err, wantErr) AND errors.Is(err, ErrArgPolicy).
		wantErr error
	}{
		// allowed
		{"hostname bare", "hostname", nil},
		{"whoami /all", "whoami /all", nil},
		{"whoami /fo csv", "whoami /fo csv", nil},
		{"netstat -a -n -o", "netstat -a -n -o", nil},
		{"netstat -p tcp", "netstat -p tcp", nil},
		{"ping host", "ping 8.8.8.8", nil},
		{"ping -n in range", "ping -n 4 8.8.8.8", nil},
		{"ping -l max", "ping -l 8192 8.8.8.8", nil},
		{"tracert host", "tracert example.com", nil},
		{"tracert -h in range", "tracert -h 30 1.1.1.1", nil},

		// forbidden flag (metered probe) — distinct sentinel
		{"ping -t infinite", "ping -t 8.8.8.8", ErrArgForbiddenFlag},

		// unknown flag (default-deny)
		{"ping unknown flag", "ping -z 8.8.8.8", ErrArgUnknownFlag},
		{"whoami unknown flag", "whoami /xyz", ErrArgUnknownFlag},
		{"netstat combined-flag not allowlisted", "netstat -an", ErrArgUnknownFlag},

		// disallowed value (out of range / not in enum / value is itself a flag)
		{"ping -n zero", "ping -n 0 8.8.8.8", ErrArgDisallowedValue},
		{"ping -n over", "ping -n 11 8.8.8.8", ErrArgDisallowedValue},
		{"ping -l jumbo", "ping -l 9000 8.8.8.8", ErrArgDisallowedValue},
		{"whoami /fo bad enum", "whoami /fo xml", ErrArgDisallowedValue},
		{"netstat -p bad enum", "netstat -p sctp", ErrArgDisallowedValue},
		{"ping -n value is a flag", "ping -n -4 8.8.8.8", ErrArgDisallowedValue},

		// disallowed operand (operand where none allowed / too many / bad host chars)
		{"whoami operand", "whoami somehost", ErrArgDisallowedOperand},
		{"netstat operand (refresh interval)", "netstat 5", ErrArgDisallowedOperand},
		{"ping missing host", "ping", ErrArgDisallowedOperand},
		{"ping two operands", "ping 8.8.8.8 9.9.9.9", ErrArgDisallowedOperand},
		{"ping bad host chars", "ping a;b|c", ErrArgDisallowedOperand},
		{"tracert missing host", "tracert -d", ErrArgDisallowedOperand},

		// malformed (value-flag missing its value)
		{"ping -n missing value", "ping -n", ErrArgMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := BuildExecPlan(operation.ParseCommand(c.line), allow)
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("%q: must build, got %v", c.line, err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Errorf("%q: err=%v, want errors.Is %v", c.line, err, c.wantErr)
			}
			if !errors.Is(err, ErrArgPolicy) {
				t.Errorf("%q: arg-policy failures must also wrap ErrArgPolicy, got %v", c.line, err)
			}
		})
	}
}

// TestArgPolicyCaseInsensitiveFlags — ParseCommand lowercases argv[0] but NOT the args; the policy must
// lowercase flags for matching (mirrors the broker). An uppercase forbidden flag is still forbidden.
func TestArgPolicyCaseInsensitiveFlags(t *testing.T) {
	allow := DefaultAllowlist()
	// "PING" → commandID "ping"; "-T" → forbidden -t.
	if _, err := BuildExecPlan(operation.ParseCommand("PING -T 8.8.8.8"), allow); !errors.Is(err, ErrArgForbiddenFlag) {
		t.Errorf("uppercase -T must be the forbidden -t: %v", err)
	}
	// "WHOAMI /ALL" → "/all" valueless flag → allowed.
	if _, err := BuildExecPlan(operation.ParseCommand("WHOAMI /ALL"), allow); err != nil {
		t.Errorf("uppercase /ALL must be the allowed /all: %v", err)
	}
	// enum value case-insensitive.
	if _, err := BuildExecPlan(operation.ParseCommand("whoami /fo CSV"), allow); err != nil {
		t.Errorf("uppercase enum CSV must be accepted: %v", err)
	}
}

// TestArgPolicyOperandOptionalHost covers the operandOptionalHost branch (the third broker OperandRule the
// pilot table happens not to use): 0 operands OK, 1 OK, 2 denied.
func TestArgPolicyOperandOptionalHost(t *testing.T) {
	spec := argCommandSpec{operandRule: operandOptionalHost, maxOperands: 1}
	if err := spec.evaluate(nil); err != nil {
		t.Errorf("optional host with 0 operands must pass: %v", err)
	}
	if err := spec.evaluate([]string{"example.com"}); err != nil {
		t.Errorf("optional host with 1 operand must pass: %v", err)
	}
	if err := spec.evaluate([]string{"a.com", "b.com"}); !errors.Is(err, ErrArgDisallowedOperand) {
		t.Errorf("optional host with 2 operands must be denied: %v", err)
	}
}

// TestArgPolicyTokenCap — a token over MAX_VALUE_LEN fails-closed as malformed, capped before the HOST
// pattern is even consulted (exactly the broker evaluate() top-of-loop order). The whole-LINE bound
// (broker MAX_LINE) is NOT evaluate()'s job — it is the gate's raw-line guard (operation.MaxCommandLine,
// covered in operation/gate_test.go); evaluate() mirrors broker evaluate(), which has no line-length check.
func TestArgPolicyTokenCap(t *testing.T) {
	ping := pilotArgPolicies()["ping"]

	longHost := make([]byte, argMaxValueLen+1)
	for i := range longHost {
		longHost[i] = 'a'
	}
	if err := ping.evaluate([]string{string(longHost)}); !errors.Is(err, ErrArgMalformed) {
		t.Errorf("a >MAX_VALUE_LEN token must be malformed (capped before the host pattern): %v", err)
	}

	// evaluate() itself does NOT bound the line length: many repeated valueless flags (each individually
	// valid) + a host are accepted HERE; the over-long-line refusal is the gate's (broker decide() vs
	// evaluate() split). This asserts the faithful decomposition — not a regression.
	many := make([]string, 0, 2100)
	for i := 0; i < 2100; i++ {
		many = append(many, "-a")
	}
	many = append(many, "8.8.8.8")
	if err := ping.evaluate(many); err != nil {
		t.Errorf("evaluate() must NOT enforce a line bound (that is the gate's MaxCommandLine job): %v", err)
	}
}

// TestArgValueSpecAccepts — direct unit on the value matcher: integer range edges, enum membership, length,
// emptiness, and non-numeric rejection.
func TestArgValueSpecAccepts(t *testing.T) {
	r := intRange(1, 10)
	for _, v := range []string{"1", "5", "10"} {
		if !r.accepts(v) {
			t.Errorf("intRange(1,10) must accept %q", v)
		}
	}
	for _, v := range []string{"0", "11", "-1", "", "abc", "1.5", "0x5"} {
		if r.accepts(v) {
			t.Errorf("intRange(1,10) must reject %q", v)
		}
	}
	e := oneOf("csv", "table", "list")
	if !e.accepts("CSV") || !e.accepts("table") || e.accepts("xml") || e.accepts("") {
		t.Error("oneOf enum membership wrong")
	}
	long := make([]byte, argMaxValueLen+1)
	for i := range long {
		long[i] = '1'
	}
	if r.accepts(string(long)) {
		t.Error("a value over MAX_VALUE_LEN must be rejected")
	}
}
