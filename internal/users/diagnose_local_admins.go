package users

// LocalAdminDiagnostic is the READ-ONLY Gate-0 view (Codex 019ea719) of the
// last-enabled-local-administrator lockout guard's inputs on THIS host: the
// machine account-domain SID and, per direct member of the built-in
// Administrators alias, whether localUnderMachineDomain classifies it as a LOCAL
// principal (counted by the guard) or a domain principal (skipped).
//
// It MUTATES NOTHING. Its purpose is to let an operator verify the local-vs-domain
// discriminator on a real domain-joined host BEFORE any destructive
// LOCK_USER_LOGIN test: on a correctly-behaving member workstation every
// Domain Admins / domain member must show LocalUnderMachineDomain=false and a
// "*-skipped" classification. A domain member showing LocalUnderMachineDomain=true
// (or a "*-counted"/"*-recursed" classification) would prove a
// resolveMachineDomainSid / discriminator gap — caught here with zero SAM-write
// risk, gating the destructive tests.
//
// LOCAL-ONLY: this is emitted to CLI stdout for an operator running `diagnose
// local-admins` on the box. It carries full member SIDs + domain account names and
// is more sensitive than `diagnose local-users`; it is NOT collected into the
// backend inventory/result payloads and must never be uploaded.
type LocalAdminDiagnostic struct {
	MachineDomainSID             string             `json:"machineDomainSid"`
	AdministratorsAliasName      string             `json:"administratorsAliasName"`
	DirectMembers                []LocalAdminMember `json:"directMembers"`
	EffectiveLocalAdminUserSIDs  []string           `json:"effectiveLocalAdminUserSids"`
	EffectiveLocalAdminUserCount int                `json:"effectiveLocalAdminUserCount"`
	Errors                       []string           `json:"errors,omitempty"`
}

// LocalAdminMember is one DIRECT member of the Administrators alias with its
// guard classification. Classification mirrors adminLocalUserSIDStrings() so the
// diagnostic shows exactly what the lockout guard would count:
//   - "local-user-counted"   SidTypeUser under the machine domain (counted)
//   - "domain-user-skipped"  SidTypeUser NOT under the machine domain (skipped)
//   - "local-group-recursed" built-in alias / machine-local group (guard recurses)
//   - "domain-group-skipped" S-1-5-21-* group NOT local to this machine (skipped)
//   - "well-known-or-nonlocal-group-skipped" other non-local group/alias
//     (Everyone, Authenticated Users, …) — also skipped by the guard
//   - "orphaned-skipped"     SID does not resolve (ERROR_NONE_MAPPED) — cannot be
//     an enabled admin, so the guard skips it
//   - "unresolved"           a non-orphan lookup error (surfaced for diagnosis;
//     the guard fail-closes on this for local/built-in SIDs)
//   - "other-skipped"        computer account / label SID / etc.
type LocalAdminMember struct {
	SID                     string `json:"sid"`
	Name                    string `json:"name,omitempty"`
	AccountType             string `json:"accountType,omitempty"`
	LocalUnderMachineDomain bool   `json:"localUnderMachineDomain"`
	Classification          string `json:"classification"`
}
