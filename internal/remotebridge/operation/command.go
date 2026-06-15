// Package operation is the agent-side CONSTRAINED_PTY foundation (Faz 22.6, board #1588): it VERIFIES a
// broker-signed OperationPermit and canonicalises a constrained command, byte-exact with the broker
// (broker-private / agent-public model). It mints nothing and executes nothing — the ConPTY executor +
// output streaming + harness wiring are later, owner-gated slices (ADR-0034 §13/D10). Disabled-by-default.
package operation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const commandDomain = "RemoteBridgeCommand:v1"

// CanonicalCommand mirrors the broker's CanonicalCommand (Faz 22.6 T-1a): the no-shell commandId + argv form
// and its stable SHA-256 hash. The agent executes EXACTLY commandId+argv (the D-2 no-shell invariant) — it
// never re-parses a free string into a shell. An empty/blank line canonicalises to the empty command, which
// the broker denies a PTY op without.
type CanonicalCommand struct {
	CommandID string
	Argv      []string
}

// ParseCommand canonicalises a raw command line exactly like the broker's CanonicalCommand.of(String):
// Java-trim (strip chars <= ' '), split on runs of the SPACE char only (Java {@code trim().split(" +")}),
// commandId = first token trimmed + lowercased, argv = the rest in order.
func ParseCommand(commandLine string) CanonicalCommand {
	line := javaTrim(commandLine)
	if line == "" {
		return CanonicalCommand{CommandID: "", Argv: nil}
	}
	tokens := splitSpaceRuns(line)
	cc := CanonicalCommand{CommandID: strings.ToLower(javaTrim(tokens[0]))}
	if len(tokens) > 1 {
		cc.Argv = append([]string(nil), tokens[1:]...)
	}
	return cc
}

// IsEmpty reports the empty canonicalisation (no command).
func (c CanonicalCommand) IsEmpty() bool { return c.CommandID == "" }

// Hash is the lowercase-hex SHA-256 over the length-prefixed domain + commandId + each argv IN ORDER
// (order-sensitive, delimiter-safe) — byte-exact with the broker's CanonicalCommand.hash().
func (c CanonicalCommand) Hash() string {
	var b bytes.Buffer
	writeField(&b, commandDomain)
	writeField(&b, c.CommandID)
	for _, a := range c.Argv {
		writeField(&b, a)
	}
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}

// javaTrim strips leading/trailing chars <= ' ' (0x20), matching java.lang.String.trim() (NOT Unicode
// whitespace) so the tokenisation is byte-exact with the broker.
func javaTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return r <= ' ' })
}

// splitSpaceRuns splits on runs of the SPACE char only (mirrors Java split(" +")); s is already java-trimmed,
// so there are no leading/trailing empties. Tabs/other chars stay inside tokens, exactly as the broker.
func splitSpaceRuns(s string) []string {
	parts := strings.Split(s, " ")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
