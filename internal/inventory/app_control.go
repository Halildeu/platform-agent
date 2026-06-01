package inventory

import (
	"context"
	"time"
)

// AG-041 — Application Control / WDAC + AppLocker policy state probe
// (Faz 22.5 P1 ops visibility, Sprint C).
//
// Read-only Windows Application-Control posture probe. Reports two
// orthogonal facets:
//   - **WDAC** (Windows Defender Application Control / kernel-mode)
//     — operational mode + bounded capability evidence + active CIP
//     policy count + legacy SIPolicy presence + multi-policy mode bit.
//   - **AppLocker** (user-mode SrpV2 policy enforcement) — per-rule-
//     collection enforcement mode (Exe / Dll / Script / Msi / Appx) +
//     AppIDSvc state + startup mode + presence.
//
// HARD BOUNDARY — read-only registry + bounded filesystem metadata only.
// Codex 019e83ce iter-1 P0 #1 + #2 + #3 absorb + iter-2 finalisation:
//   - NO PowerShell, NO `Get-CimInstance`, NO WMI/CIM, NO event log,
//     NO process enumeration, NO `gpresult`, NO `Get-AppLockerPolicy`,
//     NO arbitrary filesystem scan.
//   - WDAC mode `UNKNOWN` is the dominant return — `AUDIT`/`ENFORCE`
//     emitted ONLY when an implementation-verified, version-defensible
//     explicit scalar reads true. Capability/presence evidence bits
//     (boot enforcement, multi-policy mode) NEVER drive the mode
//     derivation directly.
//   - CIPolicies\Active\*.cip = COUNT ONLY, never file names / GUIDs /
//     hashes.
//   - SIPolicy.p7b = presence boolean only.
//   - AppLocker = registry DWORD per collection, NO rule subkeys, NO
//     rule lists, NO publisher / signer thumbprints.
//
// REDACTION CONTRACT — the wire `AppControlResult` carries ONLY:
//   - SchemaVersion (pinned 1)
//   - Supported (bool — false on non-Windows; key always present)
//   - ProbeComplete (bool — derived from per-facet success; key always present)
//   - WdacQueryable / AppLockerQueryable (bool — facet queryability;
//     stable wire keys per Codex iter-1 P0 #3)
//   - WDAC scalars: WdacMode (4-state enum) + 4 bounded *bool / *int
//     evidence pointers with STABLE keys (explicit JSON null when nil,
//     no `omitempty` per Codex iter-2 #2)
//   - AppLocker scalars: 5 per-collection enforcement enums + AppIDSvc
//     {State, StartupMode, Present} reusing AG-039 ServiceState +
//     StartupMode enums verbatim (Codex iter-1 P1 #5)
//   - ProbeErrors[] each {Code (bounded enum), Source? (3-value enum
//     wdac|appLocker|filesystem per Codex iter-1 P1 #4), Summary?
//     (bounded static phrasing ≤200 chars CRLF-stripped)}; empty slice
//     when no errors, NEVER null (Codex iter-2 #2 absorb)
//   - ProbeDurationMs (int)
//
// FAIL-CLOSED EVIDENCE: supported=false (non-Windows) and
// probeComplete=false (any facet decision-critical read failure) MUST be
// persisted AS evidence — consumers (web UI, alerting rules) MUST NOT
// render an incomplete probe as "no application control" or as
// "enforcement enabled".

const AppControlSchemaVersion = 1

// MaxAppControlProbeErrors caps the wire-payload size. Codex 019e83ce
// iter-2 recommendation: 16 with aggregation + a final truncation marker
// (PROBE_ERRORS_TRUNCATED) so consumers KNOW data was dropped rather
// than silently inferring "no errors" from a capped slice.
const MaxAppControlProbeErrors = 16

// AppControlProbeTimeout bounds the registry + filesystem reads. A slow
// read returns ProbeComplete=false + typed error rather than blocking
// the inventory collection.
const AppControlProbeTimeout = 10 * time.Second

// WdacMode is the wire enum for Windows Defender Application Control
// operational mode.
//
// `UNKNOWN` is the dominant return per Codex 019e83ce iter-1 P0 #2:
// without a confirmed, version-defensible explicit canonical scalar
// (`AUDIT`/`ENFORCE`) the probe MUST NOT guess from capability evidence
// (driver blocklist, deployment bit, DeviceGuard availability) — those
// go into bounded evidence fields, NEVER into mode derivation.
//
// `OFF` requires ALL reads to succeed AND NO explicit policy evidence
// found (CIPolicies\Active count==0 AND SIPolicy.p7b absent AND no
// explicit audit/enforce scalar).
type WdacMode string

const (
	WdacModeOff     WdacMode = "OFF"
	WdacModeAudit   WdacMode = "AUDIT"
	WdacModeEnforce WdacMode = "ENFORCE"
	WdacModeUnknown WdacMode = "UNKNOWN"
)

// AppLockerEnforcementMode is the wire enum for per-rule-collection
// AppLocker enforcement, mapped strictly from registry DWORD values per
// Codex 019e83ce iter-1 P1 #5:
//
//	missing key/value OR DWORD 0 → NOT_CONFIGURED
//	DWORD 1                      → AUDIT_ONLY
//	DWORD 2                      → ENFORCE
//	other type / value / failure → UNKNOWN (+ typed probe error)
type AppLockerEnforcementMode string

const (
	AppLockerNotConfigured AppLockerEnforcementMode = "NOT_CONFIGURED"
	AppLockerAuditOnly     AppLockerEnforcementMode = "AUDIT_ONLY"
	AppLockerEnforce       AppLockerEnforcementMode = "ENFORCE"
	AppLockerUnknown       AppLockerEnforcementMode = "UNKNOWN"
)

// AppControlProbeErrorSource disambiguates which sub-probe surfaced the
// error. Codex 019e83ce iter-1 P1 #4 absorb: 3-value enum, NOT
// freeform — `wdac` (registry/scalar reads under HKLM\SYSTEM CI),
// `appLocker` (registry SrpV2 collections + AppIDSvc SCM query),
// `filesystem` (CIPolicies\Active dir + SIPolicy.p7b stat).
type AppControlProbeErrorSource string

const (
	AppControlProbeErrSourceWdac       AppControlProbeErrorSource = "wdac"
	AppControlProbeErrSourceAppLocker  AppControlProbeErrorSource = "appLocker"
	AppControlProbeErrSourceFilesystem AppControlProbeErrorSource = "filesystem"
)

// Bounded probe-error code allowlist. New codes require a contract
// bump; the policy layer (backend) rejects unknown codes by
// rowOrdinal-fallthrough.
const (
	AppControlErrNoEvidence              = "NO_EVIDENCE"
	AppControlErrRegistryDenied          = "REGISTRY_DENIED"
	AppControlErrFilesystemDenied        = "FILESYSTEM_DENIED"
	AppControlErrCipPoliciesDirUnreadable = "CIP_POLICIES_DIR_UNREADABLE"
	AppControlErrAppLockerKeyUnreadable  = "APPLOCKER_KEY_UNREADABLE"
	AppControlErrAppIdSvcQueryFailed     = "APP_ID_SVC_QUERY_FAILED"
	AppControlErrWdacScalarUnreadable    = "WDAC_SCALAR_UNREADABLE"
	AppControlErrProbeErrorsTruncated    = "PROBE_ERRORS_TRUNCATED"
)

// AppControlProbeError mirrors the wire shape. Codex iter-1 P1 #4 +
// iter-2 #2:
//   - Code: bounded enum (see AppControlErr* constants).
//   - Source: optional 3-value enum (wdac/appLocker/filesystem).
//   - Summary: optional bounded operator text (≤200 chars,
//     CRLF-stripped; sanitisation happens at the policy layer).
type AppControlProbeError struct {
	Code    string                      `json:"code"`
	Source  *AppControlProbeErrorSource `json:"source,omitempty"`
	Summary *string                     `json:"summary,omitempty"`
}

// AppControlResult is the v1 wire payload. Codex 019e83ce iter-1 +
// iter-2 absorb: STABLE keys throughout — pointer evidence fields drop
// `omitempty` so consumers (backend ingest, web view) can rely on the
// key being present, even when the runtime evidence is `null` /
// "unknown" / "untrustworthy".
type AppControlResult struct {
	SchemaVersion int  `json:"schemaVersion"`
	Supported     bool `json:"supported"`
	ProbeComplete bool `json:"probeComplete"`

	// Codex iter-1 P0 #3: facet queryability is its own wire field,
	// not inferred from sub-scalar nullability. UI can render a "WDAC
	// facet not queryable" message distinctly from "WDAC mode UNKNOWN".
	WdacQueryable      bool `json:"wdacQueryable"`
	AppLockerQueryable bool `json:"appLockerQueryable"`

	// WDAC facet. WdacMode is the operational decision; the *bool/*int
	// pointers are bounded capability + presence evidence (Codex iter-1
	// P0 #2 + P1 #4 — evidence NEVER drives the mode derivation).
	WdacMode                   WdacMode `json:"wdacMode"`
	WdacBootEnforcementPresent *bool    `json:"wdacBootEnforcementPresent"`
	WdacActiveCipPolicyCount   *int     `json:"wdacActiveCipPolicyCount"`
	WdacLegacySipolicyPresent  *bool    `json:"wdacLegacySipolicyPresent"`
	WdacMultiPolicyMode        *bool    `json:"wdacMultiPolicyMode"`

	// AppLocker facet. Per-collection enforcement enum + AppIDSvc state
	// reusing the AG-039 ServiceState + StartupMode enums verbatim
	// (Codex iter-1 P1 #5: AG-039 6-service allowlist excludes AppIDSvc;
	// AG-041 reports it redundantly here).
	AppLockerExeRule         AppLockerEnforcementMode `json:"appLockerExeRule"`
	AppLockerDllRule         AppLockerEnforcementMode `json:"appLockerDllRule"`
	AppLockerScriptRule      AppLockerEnforcementMode `json:"appLockerScriptRule"`
	AppLockerMsiRule         AppLockerEnforcementMode `json:"appLockerMsiRule"`
	AppLockerAppxRule        AppLockerEnforcementMode `json:"appLockerAppxRule"`
	AppLockerAppIdSvcState   ServiceState             `json:"appLockerAppIdSvcState"`
	AppLockerAppIdSvcStartup StartupMode              `json:"appLockerAppIdSvcStartup"`
	AppLockerAppIdSvcPresent *bool                    `json:"appLockerAppIdSvcPresent"`

	ProbeDurationMs int                    `json:"probeDurationMs"`
	ProbeErrors     []AppControlProbeError `json:"probeErrors"`
}

// WdacEvidence is the implementation-internal struct the Windows reader
// fills before WdacResult derivation. Decouples the "what we read" from
// the "what we wire" so the conservative mode derivation can stay
// implementation-agnostic and table-testable.
type WdacEvidence struct {
	// Queryable indicates whether the WDAC sub-probe was able to attempt
	// any reads (true even if individual reads failed). Set false only
	// when the very first decision-critical read raises
	// "unsupported" semantics (e.g. non-Windows runtime).
	Queryable bool

	// ExplicitAudit / ExplicitEnforce are the implementation-confirmed,
	// version-defensible explicit scalar reads — set TRUE only when a
	// canonical registry value actually says "audit" / "enforce" with
	// high confidence (Codex iter-1 P0 #2). Initial v1 implementation
	// MAY leave both at nil and emit `UNKNOWN` dominant.
	ExplicitAudit   *bool
	ExplicitEnforce *bool

	// Evidence fields (independent of mode derivation).
	BootEnforcementPresent *bool
	ActiveCipPolicyCount   *int
	LegacySipolicyPresent  *bool
	MultiPolicyMode        *bool

	// DecisionCriticalReadFailed flips probeComplete to false. Set true
	// when CI\Policy / CI\Config primary key reads fail outright (vs.
	// "value not present" which is a legitimate OFF signal).
	DecisionCriticalReadFailed bool
}

// DeriveWdacMode applies the conservative Codex 019e83ce iter-1 P0 #2 +
// iter-2 finalisation derivation rule. Pure function over the evidence
// struct — table-tested in app_control_test.go.
//
//	OFF      ← Queryable=true AND no DecisionCriticalReadFailed AND
//	            ExplicitAudit!=true AND ExplicitEnforce!=true AND
//	            ActiveCipPolicyCount=0 AND LegacySipolicyPresent=false
//	AUDIT    ← Queryable=true AND ExplicitAudit=true (highest-priority
//	            explicit truth)
//	ENFORCE  ← Queryable=true AND ExplicitEnforce=true (or AUDIT iff
//	            both explicit, but in v1 ExplicitEnforce wins for safety)
//	UNKNOWN  ← all other cases (the dominant return)
func DeriveWdacMode(e WdacEvidence) WdacMode {
	if !e.Queryable {
		return WdacModeUnknown
	}
	if e.DecisionCriticalReadFailed {
		return WdacModeUnknown
	}
	// ExplicitEnforce > ExplicitAudit (safety-prioritised: a confirmed
	// enforce signal beats a confirmed audit signal if both somehow
	// read true; v1 implementation should not allow that combo, but
	// the derivation function is defensive).
	if e.ExplicitEnforce != nil && *e.ExplicitEnforce {
		return WdacModeEnforce
	}
	if e.ExplicitAudit != nil && *e.ExplicitAudit {
		return WdacModeAudit
	}
	// OFF requires all evidence to point to "no policy" actively.
	cipCountZero := e.ActiveCipPolicyCount != nil && *e.ActiveCipPolicyCount == 0
	legacyAbsent := e.LegacySipolicyPresent != nil && !*e.LegacySipolicyPresent
	if cipCountZero && legacyAbsent {
		return WdacModeOff
	}
	return WdacModeUnknown
}

// AppendProbeError appends an error to the slice with bounded
// aggregation per Codex iter-2 #4. When the cap is hit, emits a final
// `PROBE_ERRORS_TRUNCATED` sentinel so consumers know data was dropped.
// Returns the (possibly modified) slice.
func AppendProbeError(errs []AppControlProbeError, e AppControlProbeError) []AppControlProbeError {
	if len(errs) >= MaxAppControlProbeErrors {
		// Already at cap. If the last entry isn't the truncation marker,
		// replace the last entry with it (preserve the earliest cap-1
		// errors which are likely the most diagnostic).
		if len(errs) > 0 && errs[len(errs)-1].Code != AppControlErrProbeErrorsTruncated {
			errs[len(errs)-1] = AppControlProbeError{Code: AppControlErrProbeErrorsTruncated}
		}
		return errs
	}
	return append(errs, e)
}

// ProbeAppControl is the cross-platform entry point. The non-Windows
// stub (app_control_other.go) returns the stable wire shape with
// supported=false + queryable flags false + UNKNOWN enums + null
// evidence + a single NO_EVIDENCE probe error. The Windows
// implementation (app_control_windows.go) performs the bounded reads.
//
// The `now` parameter is required (injectable clock for test-time
// determinism). Caller passes `time.Now` in production.
func ProbeAppControl(ctx context.Context, now func() time.Time) AppControlResult {
	if now == nil {
		now = time.Now
	}
	startedAt := now()
	result := probeAppControlImpl(ctx, now)
	if result.ProbeErrors == nil {
		// Stable wire contract: empty slice, never null.
		result.ProbeErrors = []AppControlProbeError{}
	}
	result.SchemaVersion = AppControlSchemaVersion
	result.ProbeDurationMs = int(now().Sub(startedAt).Milliseconds())
	return result
}

// errSourcePtr is a syntactic-noise reducer for the bounded enum
// pointer (Go won't let you `&AppControlProbeErrSourceWdac` against an
// untyped constant directly).
func errSourcePtr(s AppControlProbeErrorSource) *AppControlProbeErrorSource {
	return &s
}

// AppLockerDwordValueType is the platform-independent representation of
// the Windows registry value type for AppLocker EnforcementMode reads.
// Extracted as a separate type so the mapping function below stays
// cross-platform testable. On Windows, callers pass
// `uint32(registry.DWORD)` (=4); test harnesses pass any non-`DwordType`
// value to exercise the "wrong type" branch.
type AppLockerDwordValueType uint32

const AppLockerDwordType AppLockerDwordValueType = 4 // matches registry.DWORD constant

// AppLockerReadResult is the platform-independent outcome of a single
// AppLocker collection EnforcementMode read. Extracted from the
// Windows-only readAppLockerCollectionMode so the strict mapping rule
// (Codex 019e83ce iter-1 P1 #5 + iter-3 P1 #4 absorb) lives in a pure
// function table-testable on Linux CI.
type AppLockerReadResult struct {
	Mode AppLockerEnforcementMode
	// ErrorCode is non-empty when the read should emit a probe error
	// (`REGISTRY_DENIED` for permission-denied, `APPLOCKER_KEY_UNREADABLE`
	// for wrong type / unexpected DWORD).
	ErrorCode string
}

// AppLockerReadOutcome enumerates the discrete cases the Windows reader
// passes to MapAppLockerDword. Codex iter-3 P1 #4 absorb: each outcome
// maps to a SPECIFIC probe-error code (or none).
type AppLockerReadOutcome int

const (
	// KeyAbsent: registry key/value not present. Maps to NOT_CONFIGURED
	// + no probe error (legitimate "no policy" observation).
	AppLockerReadKeyAbsent AppLockerReadOutcome = iota
	// PermissionDenied: registry access denied (ERROR_ACCESS_DENIED).
	// Maps to UNKNOWN + REGISTRY_DENIED probe error.
	AppLockerReadPermissionDenied
	// DwordValue: DWORD value read successfully — interpret per strict
	// table (0=NOT_CONFIGURED, 1=AUDIT_ONLY, 2=ENFORCE, other=UNKNOWN
	// + APPLOCKER_KEY_UNREADABLE).
	AppLockerReadDwordValue
	// WrongType: value present but non-DWORD type. Maps to UNKNOWN +
	// APPLOCKER_KEY_UNREADABLE probe error.
	AppLockerReadWrongType
	// OtherReadFailure: any other read error (corrupt registry, etc.).
	// Maps to UNKNOWN + APPLOCKER_KEY_UNREADABLE probe error.
	AppLockerReadOtherFailure
)

// MapAppLockerDword applies the strict Codex 019e83ce iter-1 P1 #5 +
// iter-3 P1 #4 absorbed mapping. Pure function over (outcome, dword
// value) — testable on Linux CI without registry access.
func MapAppLockerDword(outcome AppLockerReadOutcome, dwordValue uint64) AppLockerReadResult {
	switch outcome {
	case AppLockerReadKeyAbsent:
		return AppLockerReadResult{Mode: AppLockerNotConfigured}
	case AppLockerReadPermissionDenied:
		return AppLockerReadResult{Mode: AppLockerUnknown, ErrorCode: AppControlErrRegistryDenied}
	case AppLockerReadWrongType, AppLockerReadOtherFailure:
		return AppLockerReadResult{Mode: AppLockerUnknown, ErrorCode: AppControlErrAppLockerKeyUnreadable}
	case AppLockerReadDwordValue:
		switch dwordValue {
		case 0:
			return AppLockerReadResult{Mode: AppLockerNotConfigured}
		case 1:
			return AppLockerReadResult{Mode: AppLockerAuditOnly}
		case 2:
			return AppLockerReadResult{Mode: AppLockerEnforce}
		default:
			// Unexpected DWORD value (3+) — same UNKNOWN + APPLOCKER_KEY
			// _UNREADABLE as wrong-type, distinct from REGISTRY_DENIED.
			return AppLockerReadResult{Mode: AppLockerUnknown, ErrorCode: AppControlErrAppLockerKeyUnreadable}
		}
	}
	return AppLockerReadResult{Mode: AppLockerUnknown, ErrorCode: AppControlErrAppLockerKeyUnreadable}
}

// stringPtr returns a bounded summary pointer — used by the platform
// implementations when a probe-error needs a non-empty summary field.
func appControlSummaryPtr(s string) *string {
	return &s
}
