package users

import (
	"fmt"
	"regexp"
	"strings"
)

// Defense-in-depth guard for destructive local-user mutations
// (LOCK_USER_LOGIN / UNLOCK_USER_LOGIN / CHANGE_LOCAL_PASSWORD).
//
// The backend maker-checker (dual-control) gate is the PRIMARY authorization
// for these commands. This guard is an independent agent-side refusal: even if
// the backend gate is bypassed or misconfigured, the agent must never act on a
// well-known built-in / service identity, because locking (or changing the
// password of) e.g. the built-in Administrator can strand the endpoint without
// any administrative access.
//
// ENFORCED HERE: name-based denylist + SID-literal rejection
// (GuardReservedUsername) AND the RID-based guard ({500..504},
// GuardProtectedRID, called from the Windows MutateLocal once the account SID is
// resolved) — together they refuse the well-known built-ins both by name and by
// stable identifier, so a renamed/localized built-in is still caught.
//
// REMAINING FOLLOW-UP: the last-enabled-administrator lockout guard (needs
// Administrators-group enumeration via NetLocalGroupGetMembers + per-member
// enabled-state cross-reference) is a separate slice, not stubbed here, so
// nothing pretends to enforce a check it does not actually run (Codex 019ea1a2).

// reservedLocalUsernames are well-known Windows local / service account names
// that destructive remote commands must never target. Compared case-insensitively
// against the trimmed, lower-cased username.
var reservedLocalUsernames = map[string]struct{}{
	"administrator":      {},
	"guest":              {},
	"defaultaccount":     {},
	"wdagutilityaccount": {},
	"defaultuser0":       {},
	"krbtgt":             {},
	"system":             {},
	"localsystem":        {},
	"networkservice":     {},
	"localservice":       {},
}

// sidLiteralPattern matches a security-identifier string (e.g. S-1-5-21-...),
// which is never a valid local SAM account name for these commands.
var sidLiteralPattern = regexp.MustCompile(`(?i)^s-\d+-\d+(-\d+)*$`)

// GuardReservedUsername returns a non-nil error when the username is a reserved
// built-in / service account or a SID literal. Callers MUST treat a non-nil
// result as a hard refusal (fail-closed) and report the command as FAILED.
//
// It does not re-validate syntax already enforced upstream (trim, length,
// control / domain characters); it adds only the reserved-identity refusal.
func GuardReservedUsername(username string) error {
	candidate := strings.ToLower(strings.TrimSpace(username))
	if candidate == "" {
		return fmt.Errorf("username is required")
	}
	if sidLiteralPattern.MatchString(candidate) {
		return fmt.Errorf("username %q is a SID literal and cannot be targeted", username)
	}
	if _, reserved := reservedLocalUsernames[candidate]; reserved {
		return fmt.Errorf("username %q is a reserved built-in account and cannot be targeted by a remote command", username)
	}
	return nil
}

// reservedAccountRIDs are the relative identifiers of well-known Windows local
// accounts: built-in Administrator (500), Guest (501), krbtgt (502),
// DefaultAccount (503), WDAGUtilityAccount (504). The RID is stable across a
// rename and across locale, so this guard catches a *renamed* or localized
// built-in that the name denylist (GuardReservedUsername) cannot.
var reservedAccountRIDs = map[uint32]struct{}{
	500: {},
	501: {},
	502: {},
	503: {},
	504: {},
}

// GuardProtectedRID returns a non-nil error when the resolved account RID is a
// reserved well-known identifier. The RID is the last sub-authority of the
// account's SID. Callers MUST treat a non-nil result as a hard refusal
// (fail-closed) and report the command as FAILED.
func GuardProtectedRID(rid uint32) error {
	if _, reserved := reservedAccountRIDs[rid]; reserved {
		return fmt.Errorf("account RID %d is a reserved built-in identifier and cannot be targeted by a remote command", rid)
	}
	return nil
}
