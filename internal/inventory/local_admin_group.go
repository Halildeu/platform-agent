package inventory

import "time"

// AG-032 — Local Administrators alias direct membership posture.
//
// HARD SCOPE: enumerates ONLY direct members of the local Built-in
// Administrators alias (S-1-5-32-544). Does NOT expand transitive
// domain group / Entra group membership. Does NOT evaluate
// user-rights assignment, service ACLs, scheduled tasks, or other
// admin-equivalent privilege paths.
//
// Wire-safe by construction:
//   - Zero raw SID material on the wire: no SID bytes, no SID
//     family/authority, no SID relative-ID (RID), no domain-SID
//     prefix.
//   - Zero name material on the wire: no account name, no display
//     name, no description, no domain path. Localized alias name
//     resolved from S-1-5-32-544 is process-local only.
//   - Only derived bucket booleans + typed Kind enum + count
//     totals + scope booleans reach the wire.
//   - Member array is bounded (maxLocalAdminMembers=256); counts
//     cover the full enumeration even when the slice is truncated.
//
// Codex 019e74d7 cross-AI peer-review chain (5 iters → AGREE):
//
//   - iter-0 REVISE (12 must_fix): SID/RID leak, name targeting,
//     source enumeration breadth, classifier expansion, contract
//     scope honesty, member cap, fail-closed semantics, machine
//     SID resolution
//   - iter-1 REVISE (5 implementation must_fix): NetAPI API
//     signature, machine SID source via LSA, fallback success
//     semantics, classifier precedence, unresolved SID behavior
//   - iter-2 REVISE (5 contract must_fix): NetAPI pagination,
//     CreateWellKnownSid buffer pattern, generic builtin alias
//     coverage, capability SID family expansion (S-1-15-2 + -3),
//     MACHINE_SID error source value
//   - iter-3 REVISE (3 critical bugs): SID pointer lifetime
//     after-free, invalid buffer guard, static error summary
//     phrasing
//   - iter-4 REVISE (3 result-builder corners): generic builtin
//     alias requires S-1-5-32 prefix only (drop SidTypeAlias
//     fallback), Members never nil (always `[]`), cap explicit
//     in result-builder
//   - iter-5 **AGREE** / ready_for_impl=true / must_fix:[]

const LocalAdminGroupSchemaVersion = 1

// maxLocalAdminMembers caps the Members[] wire slice. Counts cover
// the full enumeration; only the array is bounded.
const maxLocalAdminMembers = 256

// LocalAdminMemberKind enumerates the principal class of each
// member of the local Administrators alias. Each enumerated SID
// matches exactly one Kind value via the classifier precedence
// table documented in COMMAND-CONTRACT.md §14.
type LocalAdminMemberKind string

const (
	LocalAdminKindLocalUser           LocalAdminMemberKind = "localUser"
	LocalAdminKindLocalGroup          LocalAdminMemberKind = "localGroup"
	LocalAdminKindDomainUser          LocalAdminMemberKind = "domainUser"
	LocalAdminKindDomainGroup         LocalAdminMemberKind = "domainGroup"
	LocalAdminKindDomainComputer      LocalAdminMemberKind = "domainComputer"
	LocalAdminKindBuiltinAlias        LocalAdminMemberKind = "builtinAlias"
	LocalAdminKindServiceSID          LocalAdminMemberKind = "serviceSid"
	LocalAdminKindWellKnownPrivileged LocalAdminMemberKind = "wellKnownPrivileged"
	LocalAdminKindBroadWellKnown      LocalAdminMemberKind = "broadWellKnown"
	LocalAdminKindCloudPrincipal      LocalAdminMemberKind = "cloudPrincipal"
	LocalAdminKindCapability          LocalAdminMemberKind = "capability"
	LocalAdminKindUnknown             LocalAdminMemberKind = "unknown"
)

// LocalAdminProbeSource enumerates the contributing enumeration
// sources. Values are typed enum allowlist (Codex iter-0 MF-10
// absorb).
type LocalAdminProbeSource string

const (
	LocalAdminSourceNetAPI                  LocalAdminProbeSource = "netapi"
	LocalAdminSourcePowerShellLocalAccounts LocalAdminProbeSource = "powershellLocalAccounts"
	LocalAdminSourceWMIGroupUser            LocalAdminProbeSource = "wmiGroupUser"
	// LocalAdminSourceNone is the "no source attribution" value.
	// Used for SourceUsed when no enumeration source succeeded,
	// and for probeErrors[].source on errors that are not
	// attributable to a specific enumeration source
	// (e.g. MACHINE_SID_RESOLUTION_FAILED).
	LocalAdminSourceNone LocalAdminProbeSource = "none"
)

// LocalAdminProbeError code constants. Stable enum; expansion
// additive.
const (
	LocalAdminErrUnsupportedPlatform        = "UNSUPPORTED_PLATFORM"
	LocalAdminErrNetAPIFailed               = "NETAPI_FAILED"
	LocalAdminErrNetAPIAccessDenied         = "NETAPI_ACCESS_DENIED"
	LocalAdminErrNetAPIGroupNotFound        = "NETAPI_GROUP_NOT_FOUND"
	LocalAdminErrPowerShellTimeout          = "POWERSHELL_TIMEOUT"
	LocalAdminErrPowerShellFailed           = "POWERSHELL_FAILED"
	LocalAdminErrPowerShellEmptyOutput      = "POWERSHELL_EMPTY_OUTPUT"
	LocalAdminErrPowerShellParseError       = "POWERSHELL_PARSE_ERROR"
	LocalAdminErrCmdletUnavailable          = "CMDLET_UNAVAILABLE"
	LocalAdminErrAccessDenied               = "ACCESS_DENIED"
	LocalAdminErrWMIFailed                  = "WMI_FAILED"
	LocalAdminErrWellKnownSIDFailed         = "WELL_KNOWN_SID_FAILED"
	LocalAdminErrMachineSIDResolutionFailed = "MACHINE_SID_RESOLUTION_FAILED"
	LocalAdminErrNoEvidence                 = "NO_EVIDENCE"
)

// LocalAdminProbeError is the per-source structured failure
// carrier. Summary is bounded operator-facing text — capped at 200
// chars, control-char normalized (\t \r \n / NUL / BEL / ESC / DEL
// → space), and static-phrasing only. NEVER carries a raw Win32
// status code, account name, SID, or domain path (Codex iter-3
// MF-3 absorb).
type LocalAdminProbeError struct {
	Source  LocalAdminProbeSource `json:"source,omitempty"`
	Code    string                `json:"code"`
	Summary string                `json:"summary,omitempty"`
}

// LocalAdminMember is one row of the direct-member enumeration.
//
// Fields explicitly NOT included on the wire (HARD BOUNDARY):
//   - account name / display name / description
//   - principal path / DN / UPN
//   - full SID bytes
//   - SID family / authority / sub-authority breakdown
//   - SID relative-ID (RID)
//   - domain SID prefix
//   - last logon timestamp / behavioral signal
//   - resolved domain name / forest topology
//
// Only the derived Kind enum + the bucket booleans appear on the
// wire. The booleans encode operator-actionable signals
// (privileged builtin, broad reach, cloud principal, scope) without
// re-introducing stable principal identity.
type LocalAdminMember struct {
	Kind                     LocalAdminMemberKind `json:"kind"`
	IsLocalScoped            bool                 `json:"isLocalScoped"`
	IsDomainScoped           bool                 `json:"isDomainScoped"`
	IsPrivilegedBuiltinAlias bool                 `json:"isPrivilegedBuiltinAlias"`
	IsBroadWellKnown         bool                 `json:"isBroadWellKnown"`
	IsCloudPrincipal         bool                 `json:"isCloudPrincipal"`
}

// LocalAdminGroupResult is the wire-safe outcome. Snapshot
// includes it via *LocalAdminGroupResult json:"localAdminGroup,omitempty";
// pointer is nil when the caller did not opt in.
//
// Members MUST serialize as `[]` for successful empty
// enumeration AND for every failure path (Codex iter-4 MF-2
// absorb). Counts cover the full enumeration even when Members is
// truncated to maxLocalAdminMembers.
type LocalAdminGroupResult struct {
	SchemaVersion int  `json:"schemaVersion"`
	Supported     bool `json:"supported"`
	ProbeComplete bool `json:"probeComplete"`

	// Direct member counts (Codex iter-2 NTH-1 absorb: explicitly
	// "direct" to forbid effective-admin misread). Each member is
	// counted in exactly one Kind bucket per the precedence table.
	DirectMemberCount        int `json:"directMemberCount"`
	LocalUserCount           int `json:"localUserCount"`
	LocalGroupCount          int `json:"localGroupCount"`
	DomainUserCount          int `json:"domainUserCount"`
	DomainGroupCount         int `json:"domainGroupCount"`
	DomainComputerCount      int `json:"domainComputerCount"`
	BuiltinAliasCount        int `json:"builtinAliasCount"`
	ServiceSIDCount          int `json:"serviceSidCount"`
	WellKnownPrivilegedCount int `json:"wellKnownPrivilegedCount"`
	BroadWellKnownCount      int `json:"broadWellKnownCount"`
	CloudPrincipalCount      int `json:"cloudPrincipalCount"`
	CapabilityCount          int `json:"capabilityCount"`
	UnknownCount             int `json:"unknownCount"`

	// Operator-actionable risk flags.
	HasDomainScopedPrincipal   bool `json:"hasDomainScopedPrincipal"`
	HasBroadWellKnownPrincipal bool `json:"hasBroadWellKnownPrincipal"`
	HasCloudPrincipal          bool `json:"hasCloudPrincipal"`
	HasNonBuiltinLocalUser     bool `json:"hasNonBuiltinLocalUser"`

	// Members slice — bounded by maxLocalAdminMembers; counts above
	// reflect the full pre-truncation totals. NO omitempty — must
	// always serialize as `[]` on empty / failure.
	Members          []LocalAdminMember `json:"members"`
	MembersTruncated bool               `json:"membersTruncated"`
	MaxMembers       int                `json:"maxMembers"`

	// Source telemetry — which enumeration source produced the
	// final readout. "none" means no enumeration source succeeded.
	SourceUsed LocalAdminProbeSource `json:"sourceUsed"`

	ProbeErrors     []LocalAdminProbeError `json:"probeErrors,omitempty"`
	ProbeDurationMs int                    `json:"probeDurationMs"`
}

// deriveLocalAdminGroupSummary fills ProbeComplete and the
// risk-flag rollups from the Members[] slice and counts. Members
// is normalized to non-nil to honor the `members:[]` JSON contract.
func deriveLocalAdminGroupSummary(result *LocalAdminGroupResult) {
	// Codex iter-4 MF-2 absorb: never nil; serialize as `[]`.
	if result.Members == nil {
		result.Members = make([]LocalAdminMember, 0)
	}
	if result.MaxMembers == 0 {
		result.MaxMembers = maxLocalAdminMembers
	}
	result.ProbeComplete = len(result.ProbeErrors) == 0

	// Risk flag derivation from counts. These are bool projections
	// of the bucket counts; tests verify the projection is
	// deterministic.
	result.HasDomainScopedPrincipal = result.DomainUserCount+result.DomainGroupCount+result.DomainComputerCount > 0
	result.HasBroadWellKnownPrincipal = result.BroadWellKnownCount > 0
	result.HasCloudPrincipal = result.CloudPrincipalCount > 0
	// HasNonBuiltinLocalUser is set by the Windows live runner's
	// classifier (Codex 019e74d7 iter-1 post-impl MF-2 absorb) —
	// the runner inspects the SID RID process-locally so the
	// built-in Administrator (RID 500) does not flip the flag. On
	// non-Windows platforms there are no enumerated members, so
	// this stays at its zero value (false). DO NOT override the
	// runner-set flag here.
}

// localAdminGroupElapsedMs is the monotonic-duration helper.
func localAdminGroupElapsedMs(start time.Time, now func() time.Time) int {
	if now == nil {
		now = time.Now
	}
	return int(now().Sub(start) / time.Millisecond)
}
