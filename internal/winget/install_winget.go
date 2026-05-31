package winget

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"platform-agent/internal/security"
)

// AG-027 — WinGet Install Execution Adapter (Faz 22.5).
//
// Codex 019e6bfa plan-time AGREE / ready_for_impl=true (iter-2 absorb).
// AG-027 handles the agent-side execution of an `INSTALL_SOFTWARE`
// command issued by the future BE-022 install-issuer endpoint.
//
// HARD BOUNDARIES (locked in the plan-time consensus):
//
//   - **Fail-closed pre-mutation on invalid/unsupported detection rules.**
//     Supported types: `WINGET_PACKAGE` (CONFIRM_ONLY) and
//     `REGISTRY_UNINSTALL` (AUTHORITATIVE — Session-0-reliable; a miss is
//     a real denial). An invalid or unimplemented rule returns
//     FinalStatusFailedUnsupportedDetectionRule BEFORE running winget —
//     the agent never mutates a system it cannot subsequently verify. For
//     an AUTHORITATIVE detector that cannot run, even the pre-detect fails
//     closed before mutation (see §11.3c).
//
//   - **Args policy is an enum preset, never a free-text string.**
//     The catalog publishes `argsPolicyPreset ∈ {DEFAULT,
//     VENDOR_RECOMMENDED_WINGET_NO_UPGRADE}`. The agent maps each
//     to a hard-coded `[]string` argv slice; no payload field is
//     interpolated into the command line. Shell invocation is
//     impossible (exec.Cmd argument vector).
//
//   - **Pre-detect before install.** If the catalog's detection
//     rule already matches the device's current state AND the
//     version predicate is satisfied, the adapter returns
//     SUCCEEDED_NOOP without invoking `winget install`. If the
//     package is present but the version predicate FAILS, the
//     adapter returns FAILED_PREEXISTING_VERSION_CONFLICT — silent
//     upgrade is forbidden.
//
//   - **Post-install verification.** After `winget install` exits,
//     the detection rule re-runs. A SUCCEEDED final status requires
//     positive verification; verification failure flips the result
//     to FAILED_VERIFICATION even when winget reported exit 0.
//
//   - **30-minute hard cap with process-tree kill.** v1 ships a
//     `taskkill /F /T /PID` fallback after Start+Wait control of
//     the spawned `winget.exe`. The kill is dispatched from the
//     same goroutine that listens for `ctx.Done()`, so the parent
//     process is still alive when taskkill walks the tree (Codex
//     019e6c0d iter-1 P1#3 absorb). A Windows Job Object impl
//     that pre-binds the spawned tree is RT-AG-027-F1 (post-v1
//     hardening, documented in docs/COMMAND-CONTRACT.md §11.5).
//
// What this file deliberately does NOT do:
//
//   - Does not reboot automatically (SUCCEEDED_REBOOT_REQUIRED is
//     surfaced; reboot decision lives upstream).
//   - Does not run `winget upgrade` (DEFAULT preset injects
//     `--no-upgrade`).
//   - Does not parse / display localised winget progress bars
//     to the user — stdout/stderr are captured for forensic tail
//     only.
//   - Does not query the backend at any point — every input the
//     pipeline consumes arrives on the command payload (the BE-022
//     issuer is responsible for catalog snapshot pinning).

// ────────────────────────────────────────────────────────────────
// Public constants

// DefaultInstallTimeout is the hard upper bound on a single
// `INSTALL_SOFTWARE` command. WinGet installs typically complete
// in well under a minute, but large vendor MSI bundles + slow
// network can occasionally exceed 10 minutes. 30 min is a
// pragmatic ceiling chosen so a stuck install does not hold the
// command channel hostage indefinitely.
const DefaultInstallTimeout = 30 * time.Minute

// InstallSchemaVersion is bumped on non-additive schema changes
// to InstallRequest / InstallResult. v1 ships as 1.
const InstallSchemaVersion = 1

// PreVerifyEgressTimeout is the wall-clock budget allotted to the
// re-verified AG-026A source/egress preflight that AG-027 runs
// before pulling the install trigger. 10s keeps the install
// command responsive — longer egress probes already failed elsewhere.
const PreVerifyEgressTimeout = 10 * time.Second

// DetectionProbeTimeout is the wall-clock budget for a single
// `winget list --id <pkg> --exact --source winget` invocation
// (pre-detect + post-verify). The probe may run TWO attempts
// (source-scoped, then no-source fallback) inside this budget.
const DetectionProbeTimeout = 30 * time.Second

// Detection-probe method tags recorded in
// PreDetectResult/PostVerificationResult.DetectionMethod for audit/debug.
// The source-scoped probe is preferred (it proves the installed package
// correlates to the trusted winget catalog source); the no-source
// fallback proves installed-state PRESENCE/identity only, NOT source
// provenance (see COMMAND-CONTRACT.md §11.3b).
const (
	DetectionMethodSource            = "winget_list_source"
	DetectionMethodNoSourceFallback  = "winget_list_no_source_fallback"
	DetectionMethodRegistryUninstall = "registry_uninstall"
)

// wingetExitUpdateNotApplicable (0x8A150061,
// APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE) is winget's "package
// already installed / no newer version available" signal. It is NOT an
// install failure: the desired installed-state may already be met, so
// the pipeline treats it as verify-gated (fall through to post-verify)
// rather than a terminal FAILED_INSTALL.
const wingetExitUpdateNotApplicable uint32 = 0x8A150061

// isWingetAlreadyInstalledExit normalizes the signed/unsigned HRESULT
// representations of the winget exit code (2316632161 as uint32 ==
// -1978335135 as int32) before comparing against UPDATE_NOT_APPLICABLE.
func isWingetAlreadyInstalledExit(code int) bool {
	return uint32(code) == wingetExitUpdateNotApplicable
}

// Post-verification verdict (PostVerificationResult.Status). The
// winget INSTALL exit code is the AUTHORITY for installed-state; the
// `winget list` post-verify is CONFIRM-ONLY. A positive probe is
// SATISFIED (and a positive version mismatch still fails); a miss /
// error / timeout is INCONCLUSIVE and never downgrades a clean install
// exit (LIVE evidence: `winget list` enumeration is unreliable under the
// SYSTEM Session-0 service context). See COMMAND-CONTRACT.md §11.3b.
const (
	PostVerifyStatusSatisfied    = "SATISFIED"
	PostVerifyStatusInconclusive = "INCONCLUSIVE"
	// PostVerifyStatusNotSatisfied is an AUTHORITATIVE denial: a reliable
	// detector (REGISTRY_UNINSTALL) ran and the package is NOT present →
	// FAILED_VERIFICATION. Distinct from INCONCLUSIVE (CONFIRM_ONLY miss).
	PostVerifyStatusNotSatisfied = "NOT_SATISFIED"
)

// postVerifyInconclusiveSession0 is the ReasonCode carried on an
// INCONCLUSIVE post-verify: `winget list` could neither confirm nor deny
// installed-state under SYSTEM Session-0. It is a verification caveat on
// a SUCCEEDED result, NOT a FailedReasonCode.
const postVerifyInconclusiveSession0 = "winget_list_session0_enumeration_unreliable"

// versionPredicateRequiresVersionProof reports whether the predicate can
// only be verified against a concrete installed version
// (EXACT / MINIMUM / RANGE). LATEST and the zero value need no version
// proof, so an INCONCLUSIVE post-verify is acceptable for them.
func versionPredicateRequiresVersionProof(p VersionPredicate) bool {
	switch p.Type {
	case VersionPredicateExact, VersionPredicateMinimum, VersionPredicateRange:
		return true
	default:
		return false
	}
}

// CaptureLimitBytes caps each of stdout / stderr tail capture
// in the wire-safe result. The remainder is dropped silently
// and *Truncated/*TotalBytes carry the loss signal.
const CaptureLimitBytes = 4 * 1024

// ────────────────────────────────────────────────────────────────
// Final status enum (machine-readable, locked in plan-time AGREE)

const (
	FinalStatusSucceeded                        = "SUCCEEDED"
	FinalStatusSucceededNoop                    = "SUCCEEDED_NOOP"
	FinalStatusSucceededRebootRequired          = "SUCCEEDED_REBOOT_REQUIRED"
	FinalStatusFailedPreexistingVersionConflict = "FAILED_PREEXISTING_VERSION_CONFLICT"
	FinalStatusFailedUnsupportedDetectionRule   = "FAILED_UNSUPPORTED_DETECTION_RULE"
	FinalStatusFailedUnsupportedArgsPolicy      = "FAILED_UNSUPPORTED_ARGS_POLICY"
	FinalStatusFailedUnsupportedPlatform        = "FAILED_UNSUPPORTED_PLATFORM"
	FinalStatusFailedEgress                     = "FAILED_EGRESS"
	FinalStatusFailedInstall                    = "FAILED_INSTALL"
	FinalStatusFailedVerification               = "FAILED_VERIFICATION"
	FinalStatusFailedTimeout                    = "FAILED_TIMEOUT"
	FinalStatusFailedInternal                   = "FAILED_INTERNAL"
)

// ────────────────────────────────────────────────────────────────
// Args presets

// ArgsPresetDefault is the canonical preset used for every winget
// install issued by the safe-default path. The `--no-upgrade` flag
// prevents an accidental version bump on a device that already has
// a different version installed (pre-detect rejects that case
// explicitly, but defence-in-depth at the args layer is cheap).
const ArgsPresetDefault = "DEFAULT"

// ArgsPresetVendorRecommendedWingetNoUpgrade is reserved for
// catalog entries flagged `silentArgsPolicy=VENDOR_RECOMMENDED`.
// v1 ships the same arg slice as DEFAULT — the distinct name lets
// the audit trail show operator intent. A v2 widening may grow
// the preset registry.
const ArgsPresetVendorRecommendedWingetNoUpgrade = "VENDOR_RECOMMENDED_WINGET_NO_UPGRADE"

// argsPresets is the hard-coded args allowlist. No public mutator.
// Test code reads it via ArgsForPreset; production reads it via
// the same function. There is NO path for a payload to override
// or extend this registry — that is the security boundary.
var argsPresets = map[string][]string{
	ArgsPresetDefault: {
		"install",
		"--id", "%PKG%",
		"--exact",
		"--source", "winget",
		"--silent",
		"--accept-package-agreements",
		"--accept-source-agreements",
		"--disable-interactivity",
		"--no-upgrade",
	},
	ArgsPresetVendorRecommendedWingetNoUpgrade: {
		"install",
		"--id", "%PKG%",
		"--exact",
		"--source", "winget",
		"--silent",
		"--accept-package-agreements",
		"--accept-source-agreements",
		"--disable-interactivity",
		"--no-upgrade",
	},
}

// IsKnownArgsPreset reports whether the supplied preset name is
// recognised by AG-027 v1. The agent MUST refuse to execute an
// install whose preset is unknown (FAILED_UNSUPPORTED_ARGS_POLICY).
func IsKnownArgsPreset(name string) bool {
	_, ok := argsPresets[name]
	return ok
}

// ArgsForPreset returns a freshly-allocated args slice for the
// preset with `%PKG%` substituted by packageID. The function
// returns an error if the preset is unknown so callers cannot
// fall back to a partially-constructed argv accidentally.
func ArgsForPreset(name, packageID string) ([]string, error) {
	tmpl, ok := argsPresets[name]
	if !ok {
		return nil, fmt.Errorf("AG-027 unknown args preset %q", name)
	}
	if packageID == "" {
		return nil, errors.New("AG-027 packageID is empty")
	}
	out := make([]string, len(tmpl))
	for i, v := range tmpl {
		if v == "%PKG%" {
			out[i] = packageID
		} else {
			out[i] = v
		}
	}
	return out, nil
}

// ────────────────────────────────────────────────────────────────
// Wire-safe request + result shapes (canonical BE-022 contract)

// VersionPredicateType enumerates the version policy shapes that
// AG-027 understands post-install. Mirrors the BE-020 catalog
// `versionPolicyType` enum exactly.
type VersionPredicateType string

const (
	VersionPredicateLatest  VersionPredicateType = "LATEST"
	VersionPredicateExact   VersionPredicateType = "EXACT"
	VersionPredicateMinimum VersionPredicateType = "MINIMUM"
	VersionPredicateRange   VersionPredicateType = "RANGE"
)

// VersionPredicate bundles the predicate type with the catalog
// authoring shape (`spec`). The agent does NOT resolve LATEST →
// concrete version; that resolution is BE-022's job and arrives
// via InstallRequest.ResolvedVersion (may be nil for LATEST).
type VersionPredicate struct {
	Type VersionPredicateType `json:"type"`
	Spec string               `json:"spec,omitempty"`
}

// DetectionRuleType enumerates the rule types AG-027 can verify.
//   - WINGET_PACKAGE   — `winget list` (CONFIRM_ONLY under Session-0;
//     see §11.3b). A miss is INCONCLUSIVE, never a denial.
//   - REGISTRY_UNINSTALL — ARP (Add/Remove Programs) registry match.
//     Reliable under SYSTEM Session-0, so AUTHORITATIVE: a post-verify
//     miss IS a denial. (FILE_EXISTS / FILE_VERSION / FILE_SHA256 are a
//     planned follow-up; rejected fail-closed until implemented.)
//
// Any unrecognized / unimplemented type is rejected fail-closed BEFORE
// invoking winget install.
type DetectionRuleType string

const (
	DetectionRuleTypeWingetPackage     DetectionRuleType = "WINGET_PACKAGE"
	DetectionRuleTypeRegistryUninstall DetectionRuleType = "REGISTRY_UNINSTALL"
)

// String-match modes for REGISTRY_UNINSTALL displayName/publisher
// matching. v1 uses bounded literal/glob matching — NO regex (Codex
// 019e7d82: regex adds authoring risk + debug difficulty). All matches
// are case-insensitive. GLOB honours only `*` and `?`.
const (
	MatchModeExact    = "EXACT"
	MatchModePrefix   = "PREFIX"
	MatchModeContains = "CONTAINS"
	MatchModeGlob     = "GLOB"
)

// DetectionReliability records whether a rule type's detector can
// authoritatively DENY installed-state under SYSTEM Session-0:
//   - AUTHORITATIVE (REGISTRY_UNINSTALL): a post-verify miss → FAILED_VERIFICATION.
//   - CONFIRM_ONLY  (WINGET_PACKAGE): a post-verify miss → INCONCLUSIVE,
//     never downgrades a clean install exit (§11.3b).
//
// Surfaced on the result so audit/backend reads it explicitly rather
// than inferring from ruleType (Codex 019e7d82).
const (
	DetectionReliabilityAuthoritative = "AUTHORITATIVE"
	DetectionReliabilityConfirmOnly   = "CONFIRM_ONLY"
)

// detectionReliability maps a rule type to its post-verify authority.
func detectionReliability(t DetectionRuleType) string {
	switch t {
	case DetectionRuleTypeRegistryUninstall:
		return DetectionReliabilityAuthoritative
	default:
		return DetectionReliabilityConfirmOnly
	}
}

// DetectionRule is the wire-safe detection contract. WINGET_PACKAGE uses
// PackageID; REGISTRY_UNINSTALL uses ProductCode (MSI `{GUID}`, primary)
// OR a DisplayName (+ Publisher) fallback. Fields are additive/omitempty
// so the wire stays backward-compatible. The agent re-validates the rule
// fail-closed before any mutation (matching the backend validator).
type DetectionRule struct {
	Type      DetectionRuleType `json:"type"`
	PackageID string            `json:"packageId,omitempty"`

	// REGISTRY_UNINSTALL — primary precise match.
	ProductCode string `json:"productCode,omitempty"` // MSI `{GUID}`

	// REGISTRY_UNINSTALL — DisplayName(+Publisher) fallback (used when
	// ProductCode is absent). Publisher is REQUIRED for the fallback
	// unless AllowPublisherMissing is set with an EXACT DisplayName
	// (Codex 019e7d82: avoids "7-Zip"/"Zoom" false positives).
	DisplayName           string `json:"displayName,omitempty"`
	DisplayNameMatch      string `json:"displayNameMatch,omitempty"` // EXACT|PREFIX|CONTAINS|GLOB
	Publisher             string `json:"publisher,omitempty"`
	PublisherMatch        string `json:"publisherMatch,omitempty"` // EXACT|CONTAINS
	AllowPublisherMissing bool   `json:"allowPublisherMissing,omitempty"`
}

// InstallRequest is the wire-safe payload AG-027 consumes.
// BE-022 issues this verbatim; AG-027 does not transform the
// payload before consumption beyond field validation.
type InstallRequest struct {
	CommandResultID   string           `json:"commandResultId"`
	IdempotencyKey    string           `json:"idempotencyKey"`
	CatalogItemID     string           `json:"catalogItemId"`
	CatalogItemKey    string           `json:"catalogItemKey"`
	CatalogRowVersion int64            `json:"catalogRowVersion"`
	Provider          string           `json:"provider"`
	PackageID         string           `json:"packageId"`
	ArgsPolicyPreset  string           `json:"argsPolicyPreset"`
	VersionPredicate  VersionPredicate `json:"versionPredicate"`
	ResolvedVersion   string           `json:"resolvedVersion,omitempty"`
	DetectionRule     DetectionRule    `json:"detectionRule"`
}

// PreDetectResult captures the pre-install detection-rule probe.
// `Satisfied` is true when the package is present and the version
// predicate succeeds; `Satisfied=false, MatchedPackageID!=nil`
// means present-with-version-conflict (drives
// FAILED_PREEXISTING_VERSION_CONFLICT).
type PreDetectResult struct {
	Satisfied        bool   `json:"satisfied"`
	MatchedPackageID string `json:"matchedPackageId,omitempty"`
	MatchedVersion   string `json:"matchedVersion,omitempty"`
	// DetectionMethod records which winget-list probe variant produced
	// this result: DetectionMethodSource (preferred, `--source winget`)
	// or DetectionMethodNoSourceFallback (ARP-based, used when the
	// source-scoped probe could not correlate an installed package — a
	// known failure mode under the SYSTEM Session-0 service context).
	// Empty when no probe ran (validation error) or in injected stubs.
	// This is PRESENCE/identity evidence, not source-provenance evidence
	// (see COMMAND-CONTRACT.md §11.3b).
	DetectionMethod string `json:"detectionMethod,omitempty"`
}

// PostVerificationResult is the CONFIRM-ONLY post-install detection
// probe. A positive probe sets `Satisfied=true` + `Status=SATISFIED` and
// populates the matched fields. A miss/error/timeout sets
// `Satisfied=false` + `Status=INCONCLUSIVE` (it does NOT deny installed
// state — `winget list` is unreliable under Session-0) and carries a
// `ReasonCode`. The winget install exit code, not this probe, is the
// install-state authority (see COMMAND-CONTRACT.md §11.3b).
type PostVerificationResult struct {
	Satisfied bool `json:"satisfied"`
	// Status is the verification verdict: PostVerifyStatusSatisfied (the
	// probe positively confirmed installed-state) or
	// PostVerifyStatusInconclusive (the probe could neither confirm nor
	// deny — `winget list` is unreliable under the SYSTEM Session-0
	// service context, so a miss is NOT a denial). Empty in legacy/stub
	// paths. A clean install exit is NEVER downgraded by an INCONCLUSIVE
	// post-verify (see §11.3b).
	Status string `json:"status,omitempty"`
	// ReasonCode explains an INCONCLUSIVE / NOT_SATISFIED verdict. Empty
	// when SATISFIED.
	ReasonCode string `json:"reasonCode,omitempty"`
	// Authority records whether this rule type's detector can
	// authoritatively DENY installed-state under Session-0:
	// DetectionReliabilityAuthoritative (REGISTRY_UNINSTALL — a miss is a
	// real denial → FAILED_VERIFICATION) or DetectionReliabilityConfirmOnly
	// (WINGET_PACKAGE — a miss is INCONCLUSIVE). Surfaced so audit/backend
	// reads it explicitly rather than inferring from ruleType.
	Authority        string            `json:"authority,omitempty"`
	MatchedPackageID string            `json:"matchedPackageId,omitempty"`
	MatchedVersion   string            `json:"matchedVersion,omitempty"`
	RuleType         DetectionRuleType `json:"ruleType,omitempty"`
	// DetectionMethod mirrors PreDetectResult.DetectionMethod for the
	// post-install probe (winget_list_source vs
	// winget_list_no_source_fallback) — audit/debug for which variant
	// ran.
	DetectionMethod string `json:"detectionMethod,omitempty"`
}

// InstallResult is the wire-safe outcome the agent reports back
// via the command-result channel. Every field is machine-readable;
// no human-formatted text is required for the backend to drive UI
// or audit downstream.
type InstallResult struct {
	FinalStatus      string                 `json:"finalStatus"`
	SchemaVersion    int                    `json:"schemaVersion"`
	Supported        bool                   `json:"supported"`
	FailedReasonCode string                 `json:"failedReasonCode,omitempty"`
	ExitCode         int                    `json:"exitCode"`
	DurationMs       int                    `json:"durationMs"`
	RebootRequired   bool                   `json:"rebootRequired"`
	KillStrategy     string                 `json:"killStrategy,omitempty"`
	PreDetect        PreDetectResult        `json:"preDetect"`
	PostVerification PostVerificationResult `json:"postVerification"`
	Egress           SourceEgressReadiness  `json:"egress"`
	StdoutTail       string                 `json:"stdoutTail,omitempty"`
	StdoutTruncated  bool                   `json:"stdoutTruncated"`
	StdoutTotalBytes int                    `json:"stdoutTotalBytes"`
	StderrTail       string                 `json:"stderrTail,omitempty"`
	StderrTruncated  bool                   `json:"stderrTruncated"`
	StderrTotalBytes int                    `json:"stderrTotalBytes"`
}

// ────────────────────────────────────────────────────────────────
// Test seam interface — InstallOptions

// EgressVerifier re-runs an AG-026A-style preflight against the
// hard-coded default targets. Production wires DetectSourceEgress
// (Windows) or a non-Windows stub; tests inject a deterministic
// stub.
type EgressVerifier func(ctx context.Context) SourceEgressReadiness

// DetectionProbeFn runs `winget list --id <pkg> --exact --source winget`
// (or the rule-type-specific probe) and returns whether the
// package is present + its observed version. Tests inject a
// deterministic stub; production wires a thin wrapper around
// Executor + parseDetectionListOutput.
type DetectionProbeFn func(ctx context.Context, rule DetectionRule, wingetPath string) (PreDetectResult, error)

// InstallRunnerFn launches the winget install process and reports
// the structured outcome. The runner is responsible for:
//
//   - Building the os/exec.Cmd with the supplied argv (no shell);
//   - Capturing stdout / stderr up to CaptureLimitBytes per stream;
//   - Reporting exit code + reboot-required signal;
//   - On context cancellation OR timeout, terminating the process
//     tree atomically (Windows: Job Object; fallback: taskkill).
//
// The function returns the wall-clock duration the install
// occupied even on error — the caller stitches that into the final
// InstallResult.
type InstallRunnerFn func(ctx context.Context, wingetPath string, args []string) RunnerOutcome

// RunnerOutcome is what an InstallRunnerFn returns.
type RunnerOutcome struct {
	ExitCode         int
	DurationMs       int
	RebootRequired   bool
	KillStrategy     string
	TimedOut         bool
	StartFailureCode string
	StdoutTail       string
	StdoutTruncated  bool
	StdoutTotalBytes int
	StderrTail       string
	StderrTruncated  bool
	StderrTotalBytes int
}

// InstallOptions controls every I/O boundary the install pipeline
// reaches across. Zero value yields production defaults on
// Windows; tests override every seam to exercise the pipeline
// hermetically.
type InstallOptions struct {
	Locator        Locator
	EgressVerify   EgressVerifier
	DetectionProbe DetectionProbeFn
	InstallRunner  InstallRunnerFn
	Timeout        time.Duration
	Now            func() time.Time
}

// ────────────────────────────────────────────────────────────────
// Decision pipeline

// RunInstall executes the AG-027 decision pipeline. The function is
// pure with respect to the supplied seams — no global state, no
// network, no process spawn happens here. Every I/O boundary is
// pluggable for testing.
//
// Codex 019e6c0d iter-1 P0#2 absorb: the function accepts a parent
// context so the executor / agent shutdown signals propagate to the
// install runner. The internal deadline (`opts.Timeout`, default
// 30 min) is derived from the parent context, not a fresh
// background context.
func RunInstall(parentCtx context.Context, req InstallRequest, opts InstallOptions) InstallResult {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultInstallTimeout
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	result := InstallResult{
		SchemaVersion: InstallSchemaVersion,
		Supported:     true,
	}

	// 1. Detection rule valid? Fail-closed BEFORE mutation (mirrors the
	// backend DetectionRuleValidator). Covers WINGET_PACKAGE (packageId
	// required) and REGISTRY_UNINSTALL (productCode or displayName+publisher).
	if err := validateDetectionRule(req.DetectionRule); err != nil {
		result.FinalStatus = FinalStatusFailedUnsupportedDetectionRule
		result.FailedReasonCode = "detection_rule_invalid"
		return result
	}

	// 1.5 Payload integrity — Codex 019e6c0d iter-1 P1#4 absorb.
	// `provider` must be WINGET. For a WINGET_PACKAGE detection rule,
	// `detectionRule.packageId` must equal the install `packageId`
	// (else a malformed payload could install package A and verify
	// package B — false success). This identity check applies ONLY to
	// WINGET_PACKAGE; REGISTRY_UNINSTALL carries its own match criteria
	// and intentionally does not reference packageId (Codex 019e7d82).
	if !strings.EqualFold(strings.TrimSpace(req.Provider), "WINGET") {
		result.FinalStatus = FinalStatusFailedUnsupportedArgsPolicy
		result.FailedReasonCode = "provider_unsupported"
		return result
	}
	if req.DetectionRule.Type == DetectionRuleTypeWingetPackage &&
		!strings.EqualFold(strings.TrimSpace(req.PackageID), strings.TrimSpace(req.DetectionRule.PackageID)) {
		result.FinalStatus = FinalStatusFailedUnsupportedDetectionRule
		result.FailedReasonCode = "detection_rule_package_id_mismatch"
		return result
	}

	// 2. Args policy preset known? Fail-closed BEFORE mutation.
	if !IsKnownArgsPreset(req.ArgsPolicyPreset) {
		result.FinalStatus = FinalStatusFailedUnsupportedArgsPolicy
		result.FailedReasonCode = "args_policy_preset_unknown"
		return result
	}

	// 3. Package id present?
	if strings.TrimSpace(req.PackageID) == "" {
		result.FinalStatus = FinalStatusFailedInternal
		result.FailedReasonCode = "package_id_missing"
		return result
	}

	// 4. Locate winget binary. A missing winget is treated as a
	// platform-level failure (the caller surfaces this distinctly
	// from a runtime error so the audit log is precise).
	if opts.Locator == nil {
		result.FinalStatus = FinalStatusFailedUnsupportedPlatform
		result.FailedReasonCode = "locator_unavailable"
		return result
	}
	wingetPath, err := opts.Locator()
	if err != nil || wingetPath == "" {
		result.FinalStatus = FinalStatusFailedUnsupportedPlatform
		result.FailedReasonCode = "winget_not_installed"
		return result
	}

	// 5. Re-verify AG-026A egress readiness before pulling the
	// trigger. Hours can pass between command issue and execute.
	startedAt := opts.Now()
	ctx, cancel := context.WithTimeout(parentCtx, opts.Timeout)
	defer cancel()
	if opts.EgressVerify != nil {
		egressCtx, egressCancel := context.WithTimeout(ctx, PreVerifyEgressTimeout)
		result.Egress = opts.EgressVerify(egressCtx)
		egressCancel()
		if !egressReady(result.Egress) {
			result.FinalStatus = FinalStatusFailedEgress
			result.FailedReasonCode = "egress_not_ready"
			result.DurationMs = elapsedMs(startedAt, opts.Now)
			return result
		}
	}

	// 6. Pre-detect: is the package already present?
	if opts.DetectionProbe == nil {
		result.FinalStatus = FinalStatusFailedInternal
		result.FailedReasonCode = "detection_probe_unwired"
		result.DurationMs = elapsedMs(startedAt, opts.Now)
		return result
	}
	reliability := detectionReliability(req.DetectionRule.Type)

	preCtx, preCancel := context.WithTimeout(ctx, DetectionProbeTimeout)
	pre, preErr := opts.DetectionProbe(preCtx, req.DetectionRule, wingetPath)
	preCancel()
	result.PreDetect = pre
	// Pre-detect is the NOOP short-circuit. A POSITIVE pre-detect
	// short-circuits (NOOP, or FAILED_PREEXISTING_VERSION_CONFLICT on a
	// version mismatch); a clean MISS proceeds to the idempotent install.
	//
	// A pre-detect ERROR is keyed by detector reliability: for an
	// AUTHORITATIVE detector (registry/file) the SAME detector drives the
	// authoritative post-verify, so if it cannot run now (probe error /
	// ambiguous rule) we fail-closed BEFORE mutating — installing a package
	// we then could not verify is worse than not installing (Codex
	// 019e7d82). For a CONFIRM_ONLY detector (`winget list`, unreliable
	// under Session-0) a probe error is non-fatal — proceed to install.
	if preErr != nil {
		if reliability == DetectionReliabilityAuthoritative {
			reason := "pre_detect_probe_error"
			if errors.Is(preErr, ErrRegistryAmbiguous) {
				reason = "detection_rule_ambiguous_match"
			}
			result.FinalStatus = FinalStatusFailedVerification
			result.FailedReasonCode = reason
			result.PostVerification = PostVerificationResult{
				Satisfied: false, Status: PostVerifyStatusNotSatisfied,
				ReasonCode: reason, Authority: reliability,
				RuleType: req.DetectionRule.Type, DetectionMethod: pre.DetectionMethod,
			}
			result.DurationMs = elapsedMs(startedAt, opts.Now)
			return result
		}
		// CONFIRM_ONLY: best-effort — proceed to the idempotent install.
	} else if pre.Satisfied {
		if versionPredicateSatisfied(req.VersionPredicate, req.ResolvedVersion, pre.MatchedVersion) {
			result.FinalStatus = FinalStatusSucceededNoop
			result.PostVerification = PostVerificationResult{
				Satisfied:        true,
				Status:           PostVerifyStatusSatisfied,
				Authority:        reliability,
				MatchedPackageID: pre.MatchedPackageID,
				MatchedVersion:   pre.MatchedVersion,
				RuleType:         req.DetectionRule.Type,
				DetectionMethod:  pre.DetectionMethod,
			}
			result.DurationMs = elapsedMs(startedAt, opts.Now)
			return result
		}
		// Package present but version predicate fails — refuse to silently
		// upgrade. Operator action required.
		result.FinalStatus = FinalStatusFailedPreexistingVersionConflict
		result.FailedReasonCode = "preexisting_version_conflict"
		result.DurationMs = elapsedMs(startedAt, opts.Now)
		return result
	}

	// 7. Run install.
	if opts.InstallRunner == nil {
		result.FinalStatus = FinalStatusFailedInternal
		result.FailedReasonCode = "install_runner_unwired"
		result.DurationMs = elapsedMs(startedAt, opts.Now)
		return result
	}
	args, err := ArgsForPreset(req.ArgsPolicyPreset, req.PackageID)
	if err != nil {
		result.FinalStatus = FinalStatusFailedUnsupportedArgsPolicy
		result.FailedReasonCode = "args_preset_render_failed"
		result.DurationMs = elapsedMs(startedAt, opts.Now)
		return result
	}
	runnerOutcome := opts.InstallRunner(ctx, wingetPath, args)
	result.ExitCode = runnerOutcome.ExitCode
	result.RebootRequired = runnerOutcome.RebootRequired
	result.KillStrategy = runnerOutcome.KillStrategy
	result.StdoutTail = sanitizeForWire(runnerOutcome.StdoutTail)
	result.StdoutTruncated = runnerOutcome.StdoutTruncated
	result.StdoutTotalBytes = runnerOutcome.StdoutTotalBytes
	result.StderrTail = sanitizeForWire(runnerOutcome.StderrTail)
	result.StderrTruncated = runnerOutcome.StderrTruncated
	result.StderrTotalBytes = runnerOutcome.StderrTotalBytes

	if runnerOutcome.TimedOut {
		result.FinalStatus = FinalStatusFailedTimeout
		result.FailedReasonCode = "install_timeout"
		result.DurationMs = runnerOutcome.DurationMs
		return result
	}

	// 8. Base install-state from the winget INSTALL exit code. winget is
	// the AUTHORITY for installed-state: LIVE evidence proved `winget list`
	// enumeration is unreliable under the SYSTEM Session-0 service context,
	// so it cannot be the verification authority, whereas `winget install`
	// reports installed-state reliably.
	//   0          → SUCCEEDED (reboot flag → SUCCEEDED_REBOOT_REQUIRED)
	//   3010       → SUCCEEDED_REBOOT_REQUIRED
	//   0x8A150061 → SUCCEEDED_NOOP (already installed / no applicable upgrade)
	//   other      → FAILED_INSTALL (winget_exit_<n>)
	// result.ExitCode retains the winget code for audit.
	var baseStatus string
	switch {
	case runnerOutcome.ExitCode == 0:
		if runnerOutcome.RebootRequired {
			result.RebootRequired = true
			baseStatus = FinalStatusSucceededRebootRequired
		} else {
			baseStatus = FinalStatusSucceeded
		}
	case runnerOutcome.ExitCode == 3010:
		result.RebootRequired = true
		baseStatus = FinalStatusSucceededRebootRequired
	case isWingetAlreadyInstalledExit(runnerOutcome.ExitCode):
		baseStatus = FinalStatusSucceededNoop
	default:
		result.FinalStatus = FinalStatusFailedInstall
		result.FailedReasonCode = "winget_exit_" + strconv.Itoa(runnerOutcome.ExitCode)
		result.DurationMs = runnerOutcome.DurationMs
		return result
	}
	result.DurationMs = runnerOutcome.DurationMs

	// 9. Post-install verification — reliability-keyed (Codex 019e7d82).
	// A POSITIVE probe (either reliability) confirms installed-state and a
	// positive version mismatch downgrades. A non-positive result is then
	// keyed by detector reliability:
	//   AUTHORITATIVE (registry/file): the detector is reliable under
	//     Session-0, so a miss/error IS a denial → FAILED_VERIFICATION.
	//   CONFIRM_ONLY (`winget list`): a miss/error is INCONCLUSIVE — never
	//     downgrades a clean install exit (§11.3b).
	postCtx, postCancel := context.WithTimeout(ctx, DetectionProbeTimeout)
	post, postErr := opts.DetectionProbe(postCtx, req.DetectionRule, wingetPath)
	postCancel()

	if postErr == nil && post.Satisfied {
		result.PostVerification = PostVerificationResult{
			Satisfied:        true,
			Status:           PostVerifyStatusSatisfied,
			Authority:        reliability,
			MatchedPackageID: post.MatchedPackageID,
			MatchedVersion:   post.MatchedVersion,
			RuleType:         req.DetectionRule.Type,
			DetectionMethod:  post.DetectionMethod,
		}
		// A positive probe reporting a CONFLICTING version is an
		// authoritative contradiction — downgrade (both reliabilities).
		if !versionPredicateSatisfied(req.VersionPredicate, req.ResolvedVersion, post.MatchedVersion) {
			result.FinalStatus = FinalStatusFailedVerification
			result.FailedReasonCode = "post_verify_version_predicate_failed"
			return result
		}
		result.FinalStatus = baseStatus
		return result
	}

	if reliability == DetectionReliabilityAuthoritative {
		// A reliable detector's miss/error is an authoritative denial: the
		// install reported success but the package is not present (or the
		// detector could not run). Downgrade. (A bounded retry to absorb
		// installers that write ARP slightly after exit is a follow-up.)
		reason := "post_verify_not_satisfied"
		if postErr != nil {
			reason = "post_verify_probe_error"
			if errors.Is(postErr, ErrRegistryAmbiguous) {
				reason = "detection_rule_ambiguous_match"
			}
		}
		result.PostVerification = PostVerificationResult{
			Satisfied: false, Status: PostVerifyStatusNotSatisfied,
			ReasonCode: reason, Authority: reliability,
			MatchedPackageID: post.MatchedPackageID, MatchedVersion: post.MatchedVersion,
			RuleType: req.DetectionRule.Type, DetectionMethod: post.DetectionMethod,
		}
		result.FinalStatus = FinalStatusFailedVerification
		result.FailedReasonCode = reason
		return result
	}

	// CONFIRM_ONLY inconclusive: `winget list` could neither confirm nor
	// deny under Session-0. Carry the caveat on PostVerification — do NOT
	// pollute a SUCCEEDED result with a FailedReasonCode.
	result.PostVerification = PostVerificationResult{
		Satisfied:       false,
		Status:          PostVerifyStatusInconclusive,
		ReasonCode:      postVerifyInconclusiveSession0,
		Authority:       reliability,
		RuleType:        req.DetectionRule.Type,
		DetectionMethod: post.DetectionMethod,
	}
	// A versioned predicate REQUIRES a concrete installed version to verify;
	// with no version evidence we cannot assert it. Fail closed (strict v1).
	if versionPredicateRequiresVersionProof(req.VersionPredicate) {
		result.FinalStatus = FinalStatusFailedVerification
		result.FailedReasonCode = "post_verify_inconclusive_version_required"
		return result
	}
	// LATEST / no version predicate: the winget install exit code is a
	// sufficient authority; keep the base success status with the
	// verification caveat carried in PostVerification.
	result.FinalStatus = baseStatus
	return result
}

// ────────────────────────────────────────────────────────────────
// Helpers

func egressReady(r SourceEgressReadiness) bool {
	if !r.Supported {
		return false
	}
	if r.Timeout {
		return false
	}
	if r.ProbeError != "" {
		return false
	}
	if !r.PackageQuery.Found {
		// AG-026A's pilot probe (7zip.7zip) is a smoke test for
		// the source pipeline. A pre-install run that cannot find
		// the pilot package indicates the source list is mis-
		// configured or the egress is broken.
		return false
	}
	return true
}

// versionPredicateSatisfied returns true when the observed installed
// version satisfies the catalog's predicate. LATEST is always
// satisfied (no constraint). For EXACT / MINIMUM / RANGE the
// comparison delegates to compareVersions.
func versionPredicateSatisfied(predicate VersionPredicate, resolvedVersion, installedVersion string) bool {
	if predicate.Type == "" || predicate.Type == VersionPredicateLatest {
		return true
	}
	target := strings.TrimSpace(resolvedVersion)
	if target == "" {
		target = strings.TrimSpace(predicate.Spec)
	}
	installed := strings.TrimSpace(installedVersion)
	if installed == "" {
		// No version observed — predicate cannot be evaluated.
		// Treat as not-satisfied so the caller emits a precise
		// FAILED_VERIFICATION rather than silently passing.
		return false
	}
	switch predicate.Type {
	case VersionPredicateExact:
		return compareVersions(installed, target) == 0
	case VersionPredicateMinimum:
		return compareVersions(installed, target) >= 0
	case VersionPredicateRange:
		return rangeSatisfied(installed, predicate.Spec)
	default:
		return false
	}
}

// compareVersions performs a best-effort dotted-number comparison.
// Returns -1 / 0 / 1. Non-numeric tokens compare lexicographically
// to preserve a stable ordering on the "24.07" style WinGet versions
// without dragging in maven-artifact. v1 stays in-tree; if catalog
// versions grow more exotic this helper becomes a candidate for a
// dedicated `internal/semver` package.
func compareVersions(a, b string) int {
	if a == b {
		return 0
	}
	tokensA := strings.Split(a, ".")
	tokensB := strings.Split(b, ".")
	maxLen := len(tokensA)
	if len(tokensB) > maxLen {
		maxLen = len(tokensB)
	}
	for i := 0; i < maxLen; i++ {
		ta := ""
		tb := ""
		if i < len(tokensA) {
			ta = tokensA[i]
		}
		if i < len(tokensB) {
			tb = tokensB[i]
		}
		numA, errA := strconv.Atoi(ta)
		numB, errB := strconv.Atoi(tb)
		if errA == nil && errB == nil {
			if numA == numB {
				continue
			}
			if numA < numB {
				return -1
			}
			return 1
		}
		// At least one non-numeric — fall back to lexical compare.
		if ta == tb {
			continue
		}
		if ta < tb {
			return -1
		}
		return 1
	}
	return 0
}

// rangeSatisfied evaluates "[a,b]" / "[a,b)" / "(a,b]" / "(a,b)" /
// "[a,)" / "(,b]" forms. Mirrors the maven-artifact range syntax
// the backend uses on the BE-023 service-side (`VersionComparator`).
func rangeSatisfied(version, spec string) bool {
	if len(spec) < 3 {
		return false
	}
	openBracket := spec[0]
	closeBracket := spec[len(spec)-1]
	if (openBracket != '[' && openBracket != '(') ||
		(closeBracket != ']' && closeBracket != ')') {
		return false
	}
	inner := spec[1 : len(spec)-1]
	commaIdx := strings.Index(inner, ",")
	if commaIdx < 0 {
		return false
	}
	lower := strings.TrimSpace(inner[:commaIdx])
	upper := strings.TrimSpace(inner[commaIdx+1:])
	lowerInclusive := openBracket == '['
	upperInclusive := closeBracket == ']'

	if lower != "" {
		cmp := compareVersions(version, lower)
		if cmp < 0 || (cmp == 0 && !lowerInclusive) {
			return false
		}
	}
	if upper != "" {
		cmp := compareVersions(version, upper)
		if cmp > 0 || (cmp == 0 && !upperInclusive) {
			return false
		}
	}
	return true
}

func elapsedMs(start time.Time, now func() time.Time) int {
	return int(now().Sub(start) / time.Millisecond)
}

// sanitizeForWire strips terminal escape sequences / progress bars
// from raw winget output before it lands on the wire. The capture
// is already capped at CaptureLimitBytes per stream upstream; this
// helper is best-effort cleanup.
//
// AG-027L (Faz 22.5.4): free-form text is routed through
// security.RedactInstallerString — the AG-025/AG-026 baseline
// (JWT / password=… / email / SID / user path / product key) PLUS
// installer-specific shapes (URL userinfo, MSI/installer property
// assignments with credential keys, token-bearing query parameters).
// The combined redaction policy is documented in
// docs/COMMAND-CONTRACT.md §11.3a.
func sanitizeForWire(s string) string {
	if s == "" {
		return ""
	}
	cleaned := strings.ReplaceAll(s, "\r", "\n")
	cleaned = strings.TrimSpace(cleaned)
	return security.RedactInstallerString(cleaned)
}

// CaptureTail captures the trailing N bytes of a stream output into
// a tail buffer + truncation flags. Used by InstallRunner
// implementations to bound the on-wire payload.
func CaptureTail(raw []byte, limit int) (tail string, truncated bool, totalBytes int) {
	totalBytes = len(raw)
	if totalBytes == 0 {
		return "", false, 0
	}
	if totalBytes <= limit {
		return string(raw), false, totalBytes
	}
	return string(raw[totalBytes-limit:]), true, totalBytes
}

// ────────────────────────────────────────────────────────────────
// Detection-rule probe (winget list parser)

// ProbeViaWingetList answers "is <pkg> installed?" via `winget list`,
// using a two-attempt strategy. Exposed for production wire-up; tests
// inject their own DetectionProbeFn that bypasses this entirely.
//
// Attempt 1 (preferred) is source-scoped: `winget list --id <pkg>
// --exact --source winget`. It proves the installed package correlates
// to the trusted winget catalog source.
//
// Attempt 2 (fallback, unconditional on a MISS) drops `--source winget`:
// `winget list --id <pkg> --exact`. LIVE evidence (AG-027 7-Zip smoke)
// showed that under the SYSTEM Session-0 service context the source-
// scoped probe cannot always correlate an installed MSI (ARP) entry to
// the catalog source, returning a clean no-match even though the package
// IS installed. The no-source probe queries installed packages (ARP)
// directly and helps non-Session-0 contexts where only the source
// correlation fails. NOTE: under the genuine Session-0 service context
// BOTH attempts can still miss (`winget list` enumeration is unreliable
// there); that case is handled by the install-exit authority model (the
// probe is best-effort/confirm-only), NOT by this fallback. It still
// requires an EXACT package-id match — no fuzzy display-name fallback —
// so it is PRESENCE/identity evidence, not source-provenance evidence
// (COMMAND-CONTRACT.md §11.3b). The INSTALL path keeps `--source winget`;
// only DETECTION degrades gracefully.
//
// "Miss" = a source-scoped attempt that returned cleanly (no error) but
// not-satisfied, OR a non-zero winget exit ("no matching package"). A
// HARD failure — winget launch failure, ctx timeout, etc. — is NOT a
// miss: it bubbles up as a Go error (no fallback) so the pipeline maps a
// precise FAILED_INTERNAL and a genuine not-installed result is never
// masked by a probe that could not run.
func ProbeViaWingetList(ctx context.Context, runner Executor, rule DetectionRule, wingetPath string) (PreDetectResult, error) {
	if runner == nil {
		return PreDetectResult{}, errors.New("AG-027 detection probe executor is nil")
	}
	if rule.Type != DetectionRuleTypeWingetPackage {
		return PreDetectResult{}, fmt.Errorf("AG-027 unsupported detection rule type %q", rule.Type)
	}
	if strings.TrimSpace(rule.PackageID) == "" {
		return PreDetectResult{}, errors.New("AG-027 detection rule package id is empty")
	}

	src, hardErr := wingetListAttempt(ctx, runner, rule.PackageID, wingetPath, true, DetectionMethodSource)
	if hardErr != nil {
		return PreDetectResult{}, hardErr
	}
	if src.Satisfied {
		return src, nil
	}

	// Source-scoped miss → no-source ARP fallback.
	nos, hardErr := wingetListAttempt(ctx, runner, rule.PackageID, wingetPath, false, DetectionMethodNoSourceFallback)
	if hardErr != nil {
		return PreDetectResult{}, hardErr
	}
	return nos, nil
}

// wingetListAttempt runs a single `winget list --id <pkg> --exact
// [--source winget] --accept-source-agreements --disable-interactivity`
// probe. A non-zero winget exit ("no matching package") is a soft miss
// → {Satisfied:false, DetectionMethod:method}, nil. A process-launch
// failure or context deadline is a HARD error → ({}, err) so the caller
// can distinguish a genuine not-installed result from an undetermined
// probe.
func wingetListAttempt(ctx context.Context, runner Executor, packageID, wingetPath string, useSource bool, method string) (PreDetectResult, error) {
	args := []string{"list", "--id", packageID, "--exact"}
	if useSource {
		args = append(args, "--source", "winget")
	}
	args = append(args, "--accept-source-agreements", "--disable-interactivity")

	stdout, err := runner(ctx, wingetPath, args...)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return PreDetectResult{}, fmt.Errorf("AG-027 detection probe timed out (%s): %w", method, ctx.Err())
	}
	if err != nil {
		var exitErr interface{ ExitCode() int }
		if errors.As(err, &exitErr) {
			// Non-zero exit on `winget list` is the documented
			// "no matching package" signal; treat as a soft miss
			// (not-satisfied) without an error so the caller can try
			// the next probe variant.
			return PreDetectResult{Satisfied: false, DetectionMethod: method}, nil
		}
		return PreDetectResult{}, err
	}
	pkg, ver, found := parseDetectionListOutput(string(stdout), packageID)
	return PreDetectResult{
		Satisfied:        found,
		MatchedPackageID: pkg,
		MatchedVersion:   ver,
		DetectionMethod:  method,
	}, nil
}

// parseDetectionListOutput parses the tabular `winget list` output
// to extract the row matching `packageID`. The parser reuses the
// AG-026A column-detection logic (header dash separator + fixed-
// column splits) so the agent treats the same format consistently
// across read and write subcommands.
func parseDetectionListOutput(raw, packageID string) (matchedPackageID, matchedVersion string, found bool) {
	if raw == "" || packageID == "" {
		return "", "", false
	}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	var headerCols []int
	headerRead := false
	idColIdx, versionColIdx := -1, -1
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !headerRead {
			if isDashSeparator(trimmed) {
				// Previous non-blank line was the header.
				continue
			}
			// Detect the actual header row when its next line is the dash separator.
			lower := strings.ToLower(trimmed)
			if strings.Contains(lower, "id") && strings.Contains(lower, "version") {
				headerCols = splitFixedColumns(line)
				if len(headerCols) >= 3 {
					// Header columns: Name | Id | Version (| Available | Source).
					idColIdx = 1
					versionColIdx = 2
				}
				headerRead = true
			}
			continue
		}
		if len(headerCols) < 3 {
			continue
		}
		parts := splitByColumns(line, headerCols)
		if len(parts) <= versionColIdx {
			continue
		}
		idCell := strings.TrimSpace(parts[idColIdx])
		if strings.EqualFold(idCell, packageID) {
			versionCell := strings.TrimSpace(parts[versionColIdx])
			return idCell, versionCell, true
		}
	}
	return "", "", false
}
