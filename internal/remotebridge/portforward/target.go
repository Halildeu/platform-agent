// Package portforward is the agent-side Faz 22.6 PORT_FORWARD data-plane CORE: the
// SSRF-safe broker-signed target allowlist + dialer (this file) and, in a follow-up,
// the TCP-connection multiplexer. It is deliberately PROTO-INDEPENDENT and INERT —
// it does NOT import the wire protocol, the harness, or any capability enum, and
// nothing dials until a future (owner/contract-gated) PORT_FORWARD dispatcher drives
// it with a broker-signed allowlist. This lets the highest-risk control — target
// restriction (SSRF/pivot defense) — be built + exhaustively tested ahead of the
// backend wire-contract (3-AI design Codex 019f119a, staged-plan step 4).
//
// PORT_FORWARD grants bidirectional network adjacency to domain controllers, so the
// #1 control is: the agent dials ONLY exact broker-signed {IP,port} tuples, resolved
// by an opaque target id (the wire Open frame carries a target id, NEVER a host/port),
// never via DNS, and never to an SSRF-classic address even if mis-signed.
package portforward

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

var (
	// ErrTargetUnknown: the requested target id is not in the broker-signed allowlist.
	ErrTargetUnknown = errors.New("portforward: target id not in the signed allowlist")
	// ErrTargetUnsafe: the (even signed) target address is never a legitimate forward
	// destination (loopback / link-local / multicast / unspecified — SSRF classics).
	ErrTargetUnsafe = errors.New("portforward: target address is not a safe forward destination")
	// ErrPortNotAllowed: the target port is outside the configured allowed set.
	ErrPortNotAllowed = errors.New("portforward: target port is not in the allowed set")
	// ErrInvalidTarget: a target failed allowlist construction validation.
	ErrInvalidTarget = errors.New("portforward: invalid target")
)

// Target is one broker-approved forward destination: an opaque id mapped to an EXACT
// IP + port. The id is what the wire carries; the IP+port are what the broker signed.
type Target struct {
	ID   string     // stable broker-assigned id (opaque; the only thing the wire Open frame carries)
	Addr netip.Addr // exact destination IP — never DNS-resolved at dial time
	Port uint16
}

// Allowlist is an immutable set of broker-signed forward targets keyed by id. Dial
// resolves ONLY by id, so the agent can never be steered to an arbitrary host:port.
type Allowlist struct {
	byID         map[string]Target
	allowedPorts map[uint16]struct{} // empty = accept any signed port (the broker is then the sole port authority)
	// guard validates a resolved address is a safe forward destination. Overridable
	// in tests ONLY (to exercise the happy dial against a loopback listener); the
	// default is the fail-closed SSRF guard.
	guard func(netip.Addr) error
}

// NewAllowlist builds an immutable allowlist from broker-signed targets. allowedPorts
// (defense in depth) restricts the dialable ports; nil/empty defers entirely to the
// signed targets. Every target is validated: non-empty unique id, valid+safe addr.
func NewAllowlist(targets []Target, allowedPorts []uint16) (*Allowlist, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: empty target set", ErrInvalidTarget)
	}
	byID := make(map[string]Target, len(targets))
	for _, t := range targets {
		if t.ID == "" {
			return nil, fmt.Errorf("%w: empty target id", ErrInvalidTarget)
		}
		if _, dup := byID[t.ID]; dup {
			return nil, fmt.Errorf("%w: duplicate target id %q", ErrInvalidTarget, t.ID)
		}
		if !t.Addr.IsValid() {
			return nil, fmt.Errorf("%w: target %q has an invalid address", ErrInvalidTarget, t.ID)
		}
		if t.Port == 0 {
			return nil, fmt.Errorf("%w: target %q has port 0", ErrInvalidTarget, t.ID)
		}
		// fail-closed at construction too: an SSRF-classic signed address is a defect.
		if err := safeForwardAddr(t.Addr); err != nil {
			return nil, fmt.Errorf("%w: target %q: %v", ErrInvalidTarget, t.ID, err)
		}
		byID[t.ID] = t
	}
	ports := make(map[uint16]struct{}, len(allowedPorts))
	for _, p := range allowedPorts {
		ports[p] = struct{}{}
	}
	return &Allowlist{byID: byID, allowedPorts: ports, guard: safeForwardAddr}, nil
}

// Resolve returns the signed target for an id (no dial). ok=false for an unknown id.
func (a *Allowlist) Resolve(targetID string) (Target, bool) {
	t, ok := a.byID[targetID]
	return t, ok
}

// Dial connects to the signed target for targetID, fail-closed. It NEVER resolves DNS
// and NEVER accepts a caller-supplied host — the address is the exact signed IP. It
// refuses an unknown id, an SSRF-classic address (even if signed), and a port outside
// the allowed set.
func (a *Allowlist) Dial(ctx context.Context, targetID string, timeout time.Duration) (net.Conn, error) {
	t, ok := a.byID[targetID]
	if !ok {
		return nil, ErrTargetUnknown
	}
	guard := a.guard
	if guard == nil {
		guard = safeForwardAddr
	}
	if err := guard(t.Addr); err != nil {
		return nil, err
	}
	if len(a.allowedPorts) > 0 {
		if _, ok := a.allowedPorts[t.Port]; !ok {
			return nil, ErrPortNotAllowed
		}
	}
	d := net.Dialer{Timeout: timeout}
	// AddrPort is a fixed IP:port literal — net.Dialer does NOT DNS-resolve it.
	return d.DialContext(ctx, "tcp", netip.AddrPortFrom(t.Addr, t.Port).String())
}

// safeForwardAddr refuses addresses that are NEVER a legitimate remote forward
// destination, even if the broker signed them (a signed loopback/link-local/metadata
// is a mis-signed permit or an attack). A real DC is private or global unicast — none
// of these classes. Note IsLinkLocalUnicast covers 169.254.0.0/16 (incl. the cloud
// metadata 169.254.169.254) and fe80::/10.
func safeForwardAddr(a netip.Addr) error {
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsInterfaceLocalMulticast() {
		return ErrTargetUnsafe
	}
	return nil
}
