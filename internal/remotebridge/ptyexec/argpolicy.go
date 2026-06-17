// argpolicy.go — the agent-side mirror of the broker PtyArgumentPolicy (endpoint-admin-service, Faz 22.6
// D-3, ADR-0033 §7 / ADR-0034 D8). plan.go's DefaultAllowlist constrains WHICH command NAMES may run; this
// file constrains WHICH ARGUMENTS each may carry — the AllowRule.ArgPolicy the LIVE-wiring slice (board
// #1612) must supply BEFORE owner-gated execution (ADR-0034 §13/D10). Disabled-by-default; nothing here
// executes.
//
// WHY a second gate at the agent. The operation gate already proves the argv equals the broker-SIGNED argv
// (the permit commandHash binding). That binds argv to the signer — NOT to the broker's argument grammar.
// A broker COMPROMISE (or a signer bug) could mint a permit for a signed-but-out-of-policy argv: an
// infinite `ping -t`, a netstat refresh-interval operand (also infinite), an arbitrary ping/tracert
// operand, a network-recon/traffic-gen flag. The same broker-compromise threat that justifies the agent's
// command-NAME subset (plan.go DefaultAllowlist staying ⊆ the broker issuance set) justifies an agent
// ARGUMENT backstop: the agent's last-line execution must independently re-assert the broker's CLOSED
// flag/value/operand grammar. Defense-in-depth, fail-closed, total (never panics).
//
// FAITHFUL MIRROR. This re-implements broker PtyArgumentPolicy.evaluate(spec, args) byte-for-byte — same
// flag sets, same value ranges/enums, same forbidden flags, same operand rule, same default-deny on unknown
// flags, same per-token length cap, same two-tier refusal (a forbidden flag is a metered probe, distinct
// from a merely unknown flag). The agent receives the argv ALREADY tokenised identically to the broker
// (operation.ParseCommand mirrors broker CanonicalCommand.of: javaTrim + split-on-space-runs), so evaluate
// here sees the SAME `args` list (the tokens AFTER argv[0]) the broker's evaluate receives — no re-tokenise,
// no token drift. The agent table is the broker's PILOT_DEFAULT_POLICY MINUS the shell-only `ver` (which the
// no-shell executor cannot run; see plan.go). If the broker table changes, the drift-guard test
// (argpolicy_test.go) — which encodes the broker values explicitly — must change too: divergence is made
// visible, never silent.
package ptyexec

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Argument-policy refusal sentinels — mirror the broker PtyArgumentPolicy.Decision deny outcomes so the
// LIVE-wiring caller can meter them exactly as the broker does. Notably ErrArgForbiddenFlag (a
// known-dangerous probe — a `-t`/`/S`/`/X` attempt worth alerting on) is DISTINCT from ErrArgUnknownFlag (a
// merely-not-allowlisted flag, default-deny). Token-free by design: an operand can be an internal
// hostname/IP (KVKK m.12) — the reason is STRUCTURAL, the offending value is never embedded. BuildExecPlan
// double-wraps these under ErrArgPolicy, so errors.Is matches both the generic gate and the specific reason.
var (
	ErrArgForbiddenFlag     = errors.New("ptyexec: forbidden flag (known-dangerous probe)")
	ErrArgUnknownFlag       = errors.New("ptyexec: unknown flag (default-deny)")
	ErrArgDisallowedValue   = errors.New("ptyexec: disallowed flag value")
	ErrArgDisallowedOperand = errors.New("ptyexec: disallowed operand")
	ErrArgMalformed         = errors.New("ptyexec: malformed argument token")
)

// argMaxValueLen mirrors broker PtyArgumentPolicy.MAX_VALUE_LEN — caps EVERY token (flag, value, operand).
// (Broker MAX_LINE, the whole-RAW-line bound, is NOT here: it belongs to the agent's "decide" equivalent —
// operation.Authorizer, which holds the raw commandLine — exactly as the broker checks MAX_LINE in decide()
// and NOT in evaluate(). See operation.MaxCommandLine.)
const argMaxValueLen = 64

var (
	// broker HOST = ^[A-Za-z0-9._:-]{1,253}$ (IPv4 / IPv6 / DNS; tighter than the D-2 whole-line class). In
	// practice argMaxValueLen (64) caps a token before the 253 upper bound is ever reached — exactly as the
	// broker, whose per-token MAX_VALUE_LEN check runs first.
	argHostPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,253}$`)
	// broker UINT = \d{1,18} matched with Java .matches() (whole-string ⇒ anchored here).
	argUintPattern = regexp.MustCompile(`^\d{1,18}$`)
)

// argOperandRule mirrors broker OperandRule: whether a command accepts a positional host operand.
type argOperandRule int

const (
	operandNone         argOperandRule = iota // no positional operand permitted (zero value ⇒ fail-closed default)
	operandOptionalHost                       // a single host operand is optional
	operandRequiredHost                       // a single host operand is required
)

// argValueSpec mirrors broker ValueSpec: the accepted value of a value-flag — a bounded integer range OR a
// fixed, case-insensitive enum of tokens.
type argValueSpec struct {
	integer bool
	min     int64
	max     int64
	enum    map[string]struct{} // lowercased; nil/empty ⇒ not an enum spec
	// sensitive mirrors broker ValueSpec.sensitive. The pilot marks none sensitive, but carrying the bit in
	// the mirror lets the golden-vector test catch a future broker redaction-contract change instead of
	// silently dropping it.
	sensitive bool
}

// intRange mirrors broker ValueSpec.intRange.
func intRange(min, max int64) argValueSpec { return argValueSpec{integer: true, min: min, max: max} }

// oneOf mirrors broker ValueSpec.oneOf (enum, case-insensitive).
func oneOf(values ...string) argValueSpec {
	m := make(map[string]struct{}, len(values))
	for _, v := range values {
		m[asciiLower(v)] = struct{}{}
	}
	return argValueSpec{enum: m}
}

// accepts mirrors broker ValueSpec.accepts: non-empty, length-capped, an in-range unsigned integer OR an
// in-enum token (lowercased).
func (s argValueSpec) accepts(value string) bool {
	if value == "" || len(value) > argMaxValueLen {
		return false
	}
	if s.integer {
		if !argUintPattern.MatchString(value) {
			return false
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return false
		}
		return n >= s.min && n <= s.max
	}
	_, ok := s.enum[asciiLower(value)]
	return ok
}

// argCommandSpec mirrors broker CommandSpec: the per-command argument grammar. All flag keys are lowercase
// (matched case-insensitively).
type argCommandSpec struct {
	valuelessFlags map[string]struct{}
	valueFlags     map[string]argValueSpec
	forbiddenFlags map[string]struct{}
	operandRule    argOperandRule
	maxOperands    int
}

// evaluate mirrors broker PtyArgumentPolicy.evaluate(spec, args) exactly: one pass, flags then operands,
// default-deny. `args` is the argv AFTER the command (operation.CanonicalCommand.Argv) — the SAME list the
// broker's evaluate receives. Total; never panics; anything not provably in-policy is denied. Like the
// broker's evaluate(), it does NOT bound the whole-line length — that is the raw-line MAX_LINE guard the
// broker performs in decide() and the agent performs in operation.Authorizer (the layer holding the raw
// commandLine). evaluate only enforces the per-token cap + the flag/value/operand grammar.
func (s argCommandSpec) evaluate(args []string) error {
	operandCount := 0
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "" || len(tok) > argMaxValueLen {
			return ErrArgMalformed
		}
		if isArgFlag(tok) {
			flag := asciiLower(tok)
			if _, bad := s.forbiddenFlags[flag]; bad {
				return ErrArgForbiddenFlag // metered probe (distinct outcome)
			}
			if _, ok := s.valuelessFlags[flag]; ok {
				continue
			}
			vspec, ok := s.valueFlags[flag]
			if !ok {
				return ErrArgUnknownFlag // default-deny, never passed through
			}
			// a value-flag consumes the NEXT token as its value
			if i+1 >= len(args) {
				return ErrArgMalformed // missing value
			}
			value := args[i+1]
			if value == "" || isArgFlag(value) || !vspec.accepts(value) {
				return ErrArgDisallowedValue
			}
			i++ // skip the consumed value
		} else {
			operandCount++
			if s.operandRule == operandNone || operandCount > s.maxOperands {
				return ErrArgDisallowedOperand
			}
			if !argHostPattern.MatchString(tok) {
				return ErrArgDisallowedOperand
			}
		}
	}
	if s.operandRule == operandRequiredHost && operandCount == 0 {
		return ErrArgDisallowedOperand // required host absent
	}
	return nil
}

// policyFunc adapts a spec to the AllowRule.ArgPolicy signature (func(args []string) error).
func (s argCommandSpec) policyFunc() func(args []string) error {
	return func(args []string) error { return s.evaluate(args) }
}

// isArgFlag mirrors broker isFlag: a token beginning with '/' or '-'.
func isArgFlag(token string) bool {
	return strings.HasPrefix(token, "/") || strings.HasPrefix(token, "-")
}

// asciiLower lowercases ONLY ASCII A-Z (byte-wise), leaving every other byte unchanged. This is used for ALL
// flag/enum normalisation instead of Go's Unicode strings.ToLower, because Go's case-folding is NOT
// byte-equivalent to the broker's Java toLowerCase(Locale.ROOT) on non-ASCII input. Go folds some non-ASCII
// letters (e.g. U+0130 İ) to a plain ASCII letter, which would then match an ASCII policy key/enum that the
// broker's Locale.ROOT folding does NOT match (it yields a non-ASCII form) — making the agent MORE permissive
// than the broker (a signed-out-of-policy argv bypass under broker-compromise). ASCII-only folding leaves
// every non-ASCII byte unchanged, so it can never match an ASCII key/enum ⇒ the agent is byte-identical to
// the broker on the ASCII command surface (the D-2 safe class) and stricter-or-equal everywhere else, never a
// bypass. (Codex 019ed29c.)
func asciiLower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + ('a' - 'A')
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// pilotArgPolicies mirrors broker PtyArgumentPolicy.PILOT_DEFAULT_POLICY for the commands the agent can
// actually run — the broker pilot set MINUS the shell-only `ver` (no standalone .exe; the no-shell executor
// cannot run it). Each key MUST equal a DefaultAllowlist command and vice-versa (argpolicy_test.go enforces
// exact parity): a runnable command with no arg policy, or a policy with no runnable command, is a drift bug.
// The values here are the authoritative broker values; the drift-guard test re-states them so any change on
// either side must be made deliberately.
func pilotArgPolicies() map[string]argCommandSpec {
	return map[string]argCommandSpec{
		// hostname — no flags, no operand.
		"hostname": {operandRule: operandNone},
		// whoami — read-only identity flags; /fo {csv,table,list}; no operand.
		"whoami": {
			valuelessFlags: stringSet("/all", "/groups", "/priv", "/user", "/fqdn", "/upn", "/logonid", "/nh"),
			valueFlags:     map[string]argValueSpec{"/fo": oneOf("csv", "table", "list")},
			operandRule:    operandNone,
		},
		// netstat — closed flag set; -p {tcp,udp,...}; NO operand (the refresh-interval operand = infinite loop, closed).
		"netstat": {
			valuelessFlags: stringSet("-a", "-n", "-o", "-r", "-s", "-e", "-b", "-q", "-f", "-y"),
			valueFlags:     map[string]argValueSpec{"-p": oneOf("tcp", "udp", "tcpv6", "udpv6", "ip", "ipv6", "icmp", "icmpv6")},
			operandRule:    operandNone,
		},
		// ping — -t (infinite) FORBIDDEN; -n/-w/-l/-i range-bounded; exactly one required host.
		"ping": {
			valuelessFlags: stringSet("-a", "-4", "-6", "-f"),
			valueFlags: map[string]argValueSpec{
				"-n": intRange(1, 10),
				"-w": intRange(1, 60_000),
				"-l": intRange(1, 8_192), // bounded payload (avoid jumbo-ICMP resource abuse)
				"-i": intRange(1, 255),
			},
			forbiddenFlags: stringSet("-t"),
			operandRule:    operandRequiredHost,
			maxOperands:    1,
		},
		// tracert — -h/-w range-bounded; exactly one required host.
		"tracert": {
			valuelessFlags: stringSet("-d", "-4", "-6"),
			valueFlags: map[string]argValueSpec{
				"-h": intRange(1, 255),
				"-w": intRange(1, 60_000),
			},
			operandRule: operandRequiredHost,
			maxOperands: 1,
		},
	}
}

// stringSet builds a lowercased set (the broker lowercases all flag keys).
func stringSet(items ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		m[asciiLower(it)] = struct{}{}
	}
	return m
}
