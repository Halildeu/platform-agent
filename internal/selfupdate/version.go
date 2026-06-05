package selfupdate

import (
	"errors"
	"strconv"
	"strings"
)

// Self-contained SemVer 2.0.0 parse + precedence (Codex 019e94fd checklist
// #4). We deliberately do NOT pull a semver dependency into the agent: this
// comparator is a SECURITY boundary (downgrade/replay refusal), so it is
// implemented faithfully to https://semver.org/#spec-item-11 and pinned by
// exhaustive tests (including the spec's canonical precedence chain). A bug
// in prerelease ordering could let a downgrade through, so correctness here
// is verified locally, not delegated.

// errInvalidVersion is the sentinel for an unparseable version string.
var errInvalidVersion = errors.New("invalid semantic version")

// Version is a parsed SemVer 2.0.0 value. Build metadata is retained for
// echo but is IGNORED in precedence (spec item 10).
type Version struct {
	Major      uint64
	Minor      uint64
	Patch      uint64
	Prerelease []string // dot-separated identifiers; nil/empty => release
	Build      string   // ignored in precedence
	Raw        string   // original input (for audit echo only)
}

// IsRelease reports whether v carries no prerelease identifiers (a "clean"
// release). Production self-update policy MAY require the CURRENT version to
// be a clean release before advertising the capability; PR0's
// EvaluateVersionPolicy itself accepts any parseable current version and
// leaves that stricter gate to the capability layer (PR2).
func (v Version) IsRelease() bool { return len(v.Prerelease) == 0 }

// ParseVersion parses a SemVer 2.0.0 string with an OPTIONAL leading "v".
// It is strict: leading zeros in numeric fields, empty identifiers, and
// non-3-component cores are rejected (so "dev", "1.2", "01.0.0" all fail
// closed). Returns errInvalidVersion on any violation.
func ParseVersion(s string) (Version, error) {
	raw := s
	s = strings.TrimSpace(s)
	if s == "" {
		return Version{}, errInvalidVersion
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}

	// Split off build metadata (after the FIRST '+').
	var build string
	if i := strings.IndexByte(s, '+'); i >= 0 {
		build = s[i+1:]
		s = s[:i]
		if !validDotSeparated(build, true) {
			return Version{}, errInvalidVersion
		}
	}

	// Split off prerelease (after the FIRST '-').
	var pre []string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		preStr := s[i+1:]
		s = s[:i]
		if !validDotSeparated(preStr, false) {
			return Version{}, errInvalidVersion
		}
		pre = strings.Split(preStr, ".")
	}

	// Core major.minor.patch.
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, errInvalidVersion
	}
	var nums [3]uint64
	for k, p := range parts {
		if !validNumericCore(p) {
			return Version{}, errInvalidVersion
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return Version{}, errInvalidVersion
		}
		nums[k] = n
	}

	return Version{
		Major:      nums[0],
		Minor:      nums[1],
		Patch:      nums[2],
		Prerelease: pre,
		Build:      build,
		Raw:        raw,
	}, nil
}

// validNumericCore: digits only, no leading zero unless the value is "0".
func validNumericCore(p string) bool {
	if p == "" {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
	}
	return len(p) == 1 || p[0] != '0'
}

// validDotSeparated validates a prerelease (build=false) or build (build=true)
// string. Each dot-separated identifier must be non-empty and ASCII
// alphanumeric-or-hyphen. For prerelease, a purely-numeric identifier must
// not carry a leading zero (spec item 9); build metadata has no such rule.
func validDotSeparated(s string, build bool) bool {
	if s == "" {
		return false
	}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		numeric := true
		for i := 0; i < len(id); i++ {
			c := id[i]
			isDigit := c >= '0' && c <= '9'
			isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-'
			if !isDigit && !isAlpha {
				return false
			}
			if !isDigit {
				numeric = false
			}
		}
		if !build && numeric && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

// Compare returns -1 if a < b, 0 if equal, +1 if a > b, per SemVer precedence
// (build metadata ignored).
func Compare(a, b Version) int {
	if c := cmpUint(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpUint(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmpUint(a.Patch, b.Patch); c != 0 {
		return c
	}
	return comparePrerelease(a.Prerelease, b.Prerelease)
}

// comparePrerelease implements spec item 11: a version WITH prerelease has
// LOWER precedence than the same version without; otherwise compare
// identifiers left-to-right, with "more fields wins" when all shared
// identifiers are equal.
func comparePrerelease(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0: // a is a release, b is a prerelease => a > b
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareIdent(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

// compareIdent: numeric identifiers compare numerically; numeric always has
// lower precedence than alphanumeric; two alphanumerics compare in ASCII
// order.
//
// Codex 019e9912 #1 (security boundary): numeric identifiers are compared at
// ARBITRARY PRECISION (length-then-lexical, valid because the parser forbids
// leading zeros), NOT via uint64. A prerelease identifier that overflows
// uint64 must still sort as a NUMBER — otherwise it would fall through to an
// alphanumeric string compare and a downgrade/replay could slip past the
// version policy.
func compareIdent(a, b string) int {
	aNum := isNumericIdent(a)
	bNum := isNumericIdent(b)
	switch {
	case aNum && bNum:
		return compareNumericIdent(a, b)
	case aNum:
		return -1
	case bNum:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

// isNumericIdent reports whether id is a non-empty all-ASCII-digit identifier.
func isNumericIdent(id string) bool {
	if id == "" {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	return true
}

// compareNumericIdent compares two all-digit identifiers as arbitrary-precision
// non-negative integers. The parser guarantees no leading zeros, so the longer
// string is the larger number; equal lengths compare lexically (ASCII digit
// order matches numeric order at equal length).
func compareNumericIdent(a, b string) int {
	if len(a) != len(b) {
		return cmpInt(len(a), len(b))
	}
	return strings.Compare(a, b)
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// VersionDecision is the outcome of EvaluateVersionPolicy.
//
//   - Allowed=true: target is a strict, non-replay upgrade of current.
//   - Noop=true: target == current (already current) — NOT an error, maps to
//     stageStatus NOOP_ALREADY_CURRENT.
//   - otherwise Code is a bounded refusal (downgrade / replay / unparseable).
type VersionDecision struct {
	Allowed bool
	Noop    bool
	Code    ErrorCode
	Reason  string
}

// EvaluateVersionPolicy enforces, LOCALLY and fail-closed (Codex 019e94fd):
//   - current/target/maxSeen must parse as SemVer, else POLICY_VERSION_UNPARSEABLE
//     (an unparseable version is never treated as 0);
//   - target must be strictly greater than maxSeen (anti-replay of old signed
//     releases) when maxSeen is non-empty, else POLICY_VERSION_REPLAY;
//   - target == current => Noop (already current);
//   - target < current => POLICY_VERSION_DOWNGRADE (rollback is a separate,
//     narrower command, out of AG-029 scope).
//
// maxSeen is the persisted monotonic high-water mark of versions this device
// has activated; pass "" when none is recorded yet.
func EvaluateVersionPolicy(current, target, maxSeen string) VersionDecision {
	cur, err := ParseVersion(current)
	if err != nil {
		return VersionDecision{Code: ErrVersionUnparseable, Reason: "current version is not parseable semver"}
	}
	tgt, err := ParseVersion(target)
	if err != nil {
		return VersionDecision{Code: ErrVersionUnparseable, Reason: "target version is not parseable semver"}
	}
	if strings.TrimSpace(maxSeen) != "" {
		ms, err := ParseVersion(maxSeen)
		if err != nil {
			return VersionDecision{Code: ErrVersionUnparseable, Reason: "maxSeen version is not parseable semver"}
		}
		if Compare(tgt, ms) <= 0 {
			return VersionDecision{Code: ErrVersionReplay, Reason: "target <= maxSeenVersion (anti-replay)"}
		}
	}
	switch Compare(tgt, cur) {
	case 0:
		return VersionDecision{Noop: true, Reason: "target == current (already current)"}
	case -1:
		return VersionDecision{Code: ErrVersionDowngrade, Reason: "target < current (downgrade refused)"}
	default:
		return VersionDecision{Allowed: true, Reason: "target > current"}
	}
}
