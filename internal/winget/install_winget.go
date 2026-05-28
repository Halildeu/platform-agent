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
//   - **Fail-closed pre-mutation on unsupported detection rules.**
//     v1 only supports `WINGET_PACKAGE` detection rules. Any other
//     rule type returns FinalStatusFailedUnsupportedDetectionRule
//     BEFORE running winget — the agent never mutates a system it
//     cannot subsequently verify.
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
// (pre-detect + post-verify).
const DetectionProbeTimeout = 30 * time.Second

// CaptureLimitBytes caps each of stdout / stderr tail capture
// in the wire-safe result. The remainder is dropped silently
// and *Truncated/*TotalBytes carry the loss signal.
const CaptureLimitBytes = 4 * 1024

// ────────────────────────────────────────────────────────────────
// Final status enum (machine-readable, locked in plan-time AGREE)

const (
	FinalStatusSucceeded                       = "SUCCEEDED"
	FinalStatusSucceededNoop                   = "SUCCEEDED_NOOP"
	FinalStatusSucceededRebootRequired         = "SUCCEEDED_REBOOT_REQUIRED"
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
// v1 ONLY supports WINGET_PACKAGE. Any other type is rejected
// fail-closed BEFORE invoking winget install.
type DetectionRuleType string

const DetectionRuleTypeWingetPackage DetectionRuleType = "WINGET_PACKAGE"

// DetectionRule v1 carries the package id to look for via
// `winget list`. Future rule types (REGISTRY_UNINSTALL,
// FILE_EXISTS, FILE_SHA256) gain their own fields without breaking
// the wire.
type DetectionRule struct {
	Type      DetectionRuleType `json:"type"`
	PackageID string            `json:"packageId,omitempty"`
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
}

// PostVerificationResult is the post-install detection-rule probe.
// On SUCCEEDED both `Satisfied=true` and the matched fields are
// populated; on FAILED_VERIFICATION `Satisfied=false`.
type PostVerificationResult struct {
	Satisfied        bool              `json:"satisfied"`
	MatchedPackageID string            `json:"matchedPackageId,omitempty"`
	MatchedVersion   string            `json:"matchedVersion,omitempty"`
	RuleType         DetectionRuleType `json:"ruleType,omitempty"`
}

// InstallResult is the wire-safe outcome the agent reports back
// via the command-result channel. Every field is machine-readable;
// no human-formatted text is required for the backend to drive UI
// or audit downstream.
type InstallResult struct {
	FinalStatus       string                  `json:"finalStatus"`
	SchemaVersion     int                     `json:"schemaVersion"`
	Supported         bool                    `json:"supported"`
	FailedReasonCode  string                  `json:"failedReasonCode,omitempty"`
	ExitCode          int                     `json:"exitCode"`
	DurationMs        int                     `json:"durationMs"`
	RebootRequired    bool                    `json:"rebootRequired"`
	KillStrategy      string                  `json:"killStrategy,omitempty"`
	PreDetect         PreDetectResult         `json:"preDetect"`
	PostVerification  PostVerificationResult  `json:"postVerification"`
	Egress            SourceEgressReadiness   `json:"egress"`
	StdoutTail        string                  `json:"stdoutTail,omitempty"`
	StdoutTruncated   bool                    `json:"stdoutTruncated"`
	StdoutTotalBytes  int                     `json:"stdoutTotalBytes"`
	StderrTail        string                  `json:"stderrTail,omitempty"`
	StderrTruncated   bool                    `json:"stderrTruncated"`
	StderrTotalBytes  int                     `json:"stderrTotalBytes"`
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
	Locator          Locator
	EgressVerify     EgressVerifier
	DetectionProbe   DetectionProbeFn
	InstallRunner    InstallRunnerFn
	Timeout          time.Duration
	Now              func() time.Time
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

	// 1. Detection rule supported? Fail-closed BEFORE mutation.
	if req.DetectionRule.Type != DetectionRuleTypeWingetPackage {
		result.FinalStatus = FinalStatusFailedUnsupportedDetectionRule
		result.FailedReasonCode = "detection_rule_type_unsupported"
		return result
	}
	if strings.TrimSpace(req.DetectionRule.PackageID) == "" {
		result.FinalStatus = FinalStatusFailedUnsupportedDetectionRule
		result.FailedReasonCode = "detection_rule_package_id_missing"
		return result
	}

	// 1.5 Payload integrity — Codex 019e6c0d iter-1 P1#4 absorb.
	// `provider`, `packageId`, and `detectionRule.packageId` must
	// reference the same target; otherwise a malformed payload could
	// install package A and verify package B (false success). All
	// three checks are case-insensitive and fail-closed BEFORE any
	// mutation runs.
	if !strings.EqualFold(strings.TrimSpace(req.Provider), "WINGET") {
		result.FinalStatus = FinalStatusFailedUnsupportedArgsPolicy
		result.FailedReasonCode = "provider_unsupported"
		return result
	}
	if !strings.EqualFold(
		strings.TrimSpace(req.PackageID),
		strings.TrimSpace(req.DetectionRule.PackageID),
	) {
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
	preCtx, preCancel := context.WithTimeout(ctx, DetectionProbeTimeout)
	pre, preErr := opts.DetectionProbe(preCtx, req.DetectionRule, wingetPath)
	preCancel()
	if preErr != nil {
		result.FinalStatus = FinalStatusFailedInternal
		result.FailedReasonCode = "pre_detect_error"
		result.PreDetect = pre
		result.DurationMs = elapsedMs(startedAt, opts.Now)
		return result
	}
	result.PreDetect = pre
	if pre.Satisfied {
		// Pre-detect already proves the catalog package present.
		// Check that the version predicate is also satisfied to
		// decide NOOP vs FAILED_PREEXISTING_VERSION_CONFLICT.
		if versionPredicateSatisfied(req.VersionPredicate, req.ResolvedVersion, pre.MatchedVersion) {
			result.FinalStatus = FinalStatusSucceededNoop
			result.PostVerification = PostVerificationResult{
				Satisfied:        true,
				MatchedPackageID: pre.MatchedPackageID,
				MatchedVersion:   pre.MatchedVersion,
				RuleType:         req.DetectionRule.Type,
			}
			result.DurationMs = elapsedMs(startedAt, opts.Now)
			return result
		}
		// Package present but version predicate fails — refuse to
		// silently upgrade. Operator action required (remove + reinstall,
		// or adjust catalog policy).
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

	// Exit-code interpretation: 0 = clean success, 3010 = success
	// with reboot required, anything else = install failure.
	switch runnerOutcome.ExitCode {
	case 0, 3010:
		// fall through to post-verify
	default:
		result.FinalStatus = FinalStatusFailedInstall
		result.FailedReasonCode = "winget_exit_" + strconv.Itoa(runnerOutcome.ExitCode)
		result.DurationMs = runnerOutcome.DurationMs
		return result
	}

	// 8. Post-install verification — re-run detection rule.
	postCtx, postCancel := context.WithTimeout(ctx, DetectionProbeTimeout)
	post, postErr := opts.DetectionProbe(postCtx, req.DetectionRule, wingetPath)
	postCancel()
	verification := PostVerificationResult{
		Satisfied:        post.Satisfied,
		MatchedPackageID: post.MatchedPackageID,
		MatchedVersion:   post.MatchedVersion,
		RuleType:         req.DetectionRule.Type,
	}
	result.PostVerification = verification
	result.DurationMs = runnerOutcome.DurationMs
	if postErr != nil || !post.Satisfied {
		result.FinalStatus = FinalStatusFailedVerification
		if postErr != nil {
			result.FailedReasonCode = "post_verify_error"
		} else {
			result.FailedReasonCode = "post_verify_not_satisfied"
		}
		return result
	}
	// Re-check version predicate post-install (handles MINIMUM /
	// RANGE / EXACT where catalog supplied a concrete spec).
	if !versionPredicateSatisfied(req.VersionPredicate, req.ResolvedVersion, post.MatchedVersion) {
		result.FinalStatus = FinalStatusFailedVerification
		result.FailedReasonCode = "post_verify_version_predicate_failed"
		return result
	}

	if runnerOutcome.RebootRequired || runnerOutcome.ExitCode == 3010 {
		// Exit code 3010 is the documented MSI / WinGet reboot signal.
		// Even when the runner did not flip RebootRequired explicitly
		// (older runner implementations) we surface it here so the
		// result.RebootRequired flag matches FinalStatus consistently.
		result.RebootRequired = true
		result.FinalStatus = FinalStatusSucceededRebootRequired
		return result
	}
	result.FinalStatus = FinalStatusSucceeded
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
// helper is best-effort cleanup. Free-form text is then routed
// through security.RedactSoftwareString so any incidental token /
// hostname is masked.
func sanitizeForWire(s string) string {
	if s == "" {
		return ""
	}
	cleaned := strings.ReplaceAll(s, "\r", "\n")
	cleaned = strings.TrimSpace(cleaned)
	return security.RedactSoftwareString(cleaned)
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

// ProbeViaWingetList runs `winget list --id <pkg> --exact
// --source winget` via the supplied Executor and returns a
// PreDetectResult. Exposed for production wire-up; tests
// inject their own DetectionProbeFn that bypasses this entirely.
//
// Exit-code semantics: `winget list` returns a non-zero exit when
// no matching package is found. This helper treats that as a
// not-satisfied result (no error to the caller). Any other error
// surface — locator failure, ctx timeout, parse failure — bubbles
// up as a Go error so the pipeline can map it to a precise
// FAILED_INTERNAL.
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
	stdout, err := runner(ctx, wingetPath,
		"list",
		"--id", rule.PackageID,
		"--exact",
		"--source", "winget",
		"--accept-source-agreements",
		"--disable-interactivity",
	)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return PreDetectResult{}, fmt.Errorf("AG-027 detection probe timed out: %w", ctx.Err())
	}
	if err != nil {
		var exitErr interface{ ExitCode() int }
		if errors.As(err, &exitErr) {
			// Non-zero exit on `winget list` is the documented
			// "no matching package" signal; treat as not-satisfied
			// without returning an error to the caller.
			return PreDetectResult{Satisfied: false}, nil
		}
		return PreDetectResult{}, err
	}
	pkg, ver, found := parseDetectionListOutput(string(stdout), rule.PackageID)
	return PreDetectResult{
		Satisfied:        found,
		MatchedPackageID: pkg,
		MatchedVersion:   ver,
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
