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
// THREE GUARDS, all enforced:
//   1. name denylist + SID-literal rejection (GuardReservedUsername, here);
//   2. the RID guard ({500..504}, GuardProtectedRID here, fed by the Windows
//      MutateLocal once the account SID is resolved) — catches a renamed/localized
//      built-in the name list would miss;
//   3. the last-enabled-administrator lockout guard — its decision is the pure
//      evaluateLockoutGuard below, fed by the Windows-only gathering in
//      lockout_windows.go (Administrators membership + enabled cross-reference).
//
// Live Windows acceptance (prlctl) is the remaining verification for the Windows
// gathering; an indirect-membership / current-interactive-user refinement is a
// possible future hardening (Codex 019ea1a2).

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

// LockoutFacts is the minimal local-SAM state the last-administrator lockout
// guard needs. It is gathered by the Windows adapter (the security-sensitive
// enumeration) and consumed by the pure decision function evaluateLockoutGuard,
// which keeps the *decision* fully testable on every platform.
type LockoutFacts struct {
	// TargetIsLocalAdmin: the target account is a DIRECT member of the built-in
	// Administrators alias (v1 scope — the Windows gathering enumerates the alias
	// membership directly; nested-group / indirect membership is a possible
	// future refinement via NetUserGetLocalGroups(LG_INCLUDE_INDIRECT)).
	TargetIsLocalAdmin bool
	// TargetEnabled: the target account is currently enabled (not disabled).
	TargetEnabled bool
	// OtherEnabledLocalAdmins: count of OTHER enabled local-user members of the
	// Administrators alias (the target itself is excluded).
	OtherEnabledLocalAdmins int
}

// evaluateLockoutGuard refuses a LOCK_USER_LOGIN that would disable the last
// enabled local administrator — which would strand the endpoint with no
// administrative access. It is a no-op for:
//   - any action other than LOCK_USER_LOGIN (unlock / change-password),
//   - a target that is not a local administrator,
//   - a target that is already disabled,
//   - any case where at least one other enabled local admin remains.
//
// Callers MUST gather LockoutFacts fail-closed (treat a gather error as a hard
// refusal) — this function only encodes the decision, not the gathering.
func evaluateLockoutGuard(action LocalUserMutationAction, f LockoutFacts) error {
	if action != ActionLockUserLogin {
		return nil
	}
	if !f.TargetEnabled || !f.TargetIsLocalAdmin {
		return nil
	}
	if f.OtherEnabledLocalAdmins <= 0 {
		return fmt.Errorf("refusing to disable the last enabled local administrator (no other enabled local admin would remain)")
	}
	return nil
}
