package winget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AG-028 — Managed Uninstall Execution Adapter (Faz 22.5.6).
//
// Codex plan-time AGREE thread `019e8de2-cf3c-7d80-8a31-823fafcbc3ed`
// iter-2 (3-PR chain locked). Destructive-side counterpart to AG-027
// INSTALL_SOFTWARE. Backend Phase 1b
// (`EndpointUninstallService.propose/approve`) dispatches an
// UNINSTALL_SOFTWARE command after the propose/approve maker-checker +
// provenance + capability + heartbeat freshness + authoritative
// detection-rule gates pass.
//
// HARD BOUNDARIES (locked in plan-time consensus):
//
//   - **Authoritative-only detector tier (v1).** REGISTRY_UNINSTALL /
//     FILE_EXISTS / FILE_SHA256 / FILE_VERSION are accepted (post-uninstall
//     ABSENCE is reliably observable under SYSTEM Session-0). WINGET_PACKAGE
//     v1 fail-closes at the top of RunUninstall with
//     `FAILED_UNSUPPORTED_VERIFICATION`, BEFORE any mutation. The backend
//     Phase 1b follow-up gate (#419) already rejects WINGET_PACKAGE at the
//     propose/approve layer; this is defense-in-depth (Codex 019e8de2
//     iter-1 absorb).
//
//   - **Absence-aware probe wrapper.** `UninstallProbeResult.State` carries
//     a closed enum of device-target states (MATCHED / ABSENT /
//     PRESENT_MISMATCH / AMBIGUOUS / ERROR / UNSUPPORTED). The wrapper
//     ALWAYS distinguishes "file/package present but identity-mismatch"
//     from "file/package absent" — `PreDetectResult.Satisfied=false` is
//     NEVER conflated with ABSENT (Codex 019e8de2 iter-1).
//
//   - **Pre-uninstall probe drives the decision tree.**
//     `MATCHED`/`PRESENT_MISMATCH` proceed to mutation; `ABSENT` short-
//     circuits to `SKIP_ALREADY_ABSENT`+`SUCCEEDED` (no mutation);
//     `AMBIGUOUS`/`ERROR` fail-close `FAILED_PRECHECK_INCONCLUSIVE`
//     (no mutation); `UNSUPPORTED` fail-closes
//     `FAILED_UNSUPPORTED_VERIFICATION` (no mutation).
//
//   - **`winget uninstall` args preset is a separate registry.** v1 ships
//     ONLY `UNINSTALL_DEFAULT`. The install preset registry is NOT shared
//     — install argv begins with `install`, uninstall argv begins with
//     `uninstall`. Re-using DEFAULT would either crash winget or, worse,
//     compose a benign-looking install command (Codex 019e8de2 iter-1).
//
//   - **Post-uninstall probe is the truth, exit code is forensic.**
//     `exit != 0 + post-probe ABSENT` → `SUCCEEDED_VERIFIED + exitCode!=0`
//     (Codex 019e8de2 iter-2 absorb). The destructive operation's success
//     criterion is hedef-state ABSENCE — the strongest authority post-
//     mutation is the AUTHORITATIVE detector, not winget's exit code. The
//     exit-code anomaly is preserved in `safeEvidence` for forensic audit
//     and does not flip the verdict.
//     `FAILED_EXIT` remains for the case where exit non-zero AND
//     post-probe could NOT confirm absence.
//
//   - **30-minute hard cap with process-tree kill.** Mirrors AG-027 install
//     timeout; MSI uninstall paths run repair / custom-action / network
//     wait that can push past the 5-min median (Codex 019e8de2 iter-1: 30
//     min stays, no optimisation without LIVE evidence). Job Object +
//     `taskkill /F /T /PID` fallback parity with install.
//
//   - **HKLM + WOW6432Node ARP only.** Per AG-027 detect_registry HKCU is
//     deliberately out of scope (SYSTEM agent cannot trust per-user uninstall
//     state; per-user uninstall requires a separate capability + policy).

// ────────────────────────────────────────────────────────────────
// Schema + timeout constants

// UninstallSchemaVersion locks the wire envelope. Backend
// UninstallEvidencePayloadPolicy parses verdict only from `probeState`
// + `finalStatus`; schema version is informational/forensic.
const UninstallSchemaVersion = 1

// DefaultUninstallTimeout is the hard upper bound on a single
// UNINSTALL_SOFTWARE command. Parity with DefaultInstallTimeout.
const DefaultUninstallTimeout = 30 * time.Minute

// UninstallProbeTimeout bounds a single pre-uninstall or post-uninstall
// probe invocation across all authoritative detector types
// (REGISTRY_UNINSTALL / FILE_*). 30 s mirrors install's
// DetectionProbeTimeout — registry walks + bounded file hashes complete
// well inside this budget.
const UninstallProbeTimeout = 30 * time.Second

// ────────────────────────────────────────────────────────────────
// ProbeState — closed enum of device-target observations

// ProbeState is the absence-aware state observed by the detector probe.
// Distinct from `finalStatus` (the operation outcome). The backend
// UninstallEvidencePayloadPolicy.deriveVerification maps probeState to
// UninstallVerification audit column.
type ProbeState string

const (
	// ProbeStateMatched — target detected; identity + version satisfy the
	// detection rule. Pre-probe: package is currently present, proceed to
	// mutation. Post-probe: uninstall did NOT remove the target →
	// FAILED_VERIFY_GHOST.
	ProbeStateMatched ProbeState = "MATCHED"
	// ProbeStateAbsent — target NOT detected. AUTHORITATIVE for the v1
	// detector tier (REGISTRY_UNINSTALL / FILE_*). Pre-probe: nothing to
	// remove → SKIP_ALREADY_ABSENT. Post-probe: uninstall successful →
	// SUCCEEDED_VERIFIED (even if exit non-zero — Codex 019e8de2 iter-2).
	ProbeStateAbsent ProbeState = "ABSENT"
	// ProbeStatePresentMismatch — target present but identity drift
	// (e.g. FILE_SHA256 hash mismatch, FILE_VERSION predicate fails,
	// REGISTRY_UNINSTALL displayName matches but Publisher differs).
	// Pre-probe: still proceed (operator-approved uninstall covers this
	// surface). Post-probe: residue remains → PARTIAL_RESIDUE.
	ProbeStatePresentMismatch ProbeState = "PRESENT_MISMATCH"
	// ProbeStateAmbiguous — multiple matches; cannot pick canonical
	// target (e.g. REGISTRY_UNINSTALL `displayName="7-Zip"` matches
	// 7-Zip 22.01 AND 7-Zip 23.01 AND a third-party "7-Zip Helper").
	// Fail-close BEFORE mutation; operator must re-author detection
	// rule with stricter match (Publisher / ProductCode).
	ProbeStateAmbiguous ProbeState = "AMBIGUOUS"
	// ProbeStateError — probe ran but the result is uninterpretable
	// (registry access denied, file I/O error). Fail-close BEFORE
	// mutation — destroying state we cannot subsequently verify is
	// worse than not destroying it (parity with AG-027 authoritative-
	// detector fail-closed on pre-detect error).
	ProbeStateError ProbeState = "ERROR"
	// ProbeStateUnsupported — detection rule type not implementable on
	// this OS / agent build (e.g. WINGET_PACKAGE in v1, FILE_VERSION on
	// non-Windows). Fail-close BEFORE mutation.
	ProbeStateUnsupported ProbeState = "UNSUPPORTED"
)

// IsKnownProbeState reports whether s is one of the closed-allowlist
// states. Drift to an unknown literal is mapped to ERROR by the
// pipeline so it never accidentally fires SUCCEEDED_VERIFIED.
func IsKnownProbeState(s ProbeState) bool {
	switch s {
	case ProbeStateMatched, ProbeStateAbsent, ProbeStatePresentMismatch,
		ProbeStateAmbiguous, ProbeStateError, ProbeStateUnsupported:
		return true
	default:
		return false
	}
}

// ────────────────────────────────────────────────────────────────
// Final status enum (machine-readable, locked in plan-time AGREE)

const (
	// UninstallFinalStatusSucceededVerified — post-probe ABSENT confirmed
	// authoritatively. Issued for clean exit 0 paths AND for exit != 0
	// paths where post-probe still confirms ABSENCE (Codex 019e8de2
	// iter-2 exit-code decision — destructive op product target is
	// hedef-state ABSENCE; post-probe AUTHORITATIVE detector is the
	// strongest truth post-mutation, NOT the exit code).
	UninstallFinalStatusSucceededVerified = "SUCCEEDED_VERIFIED"
	// UninstallFinalStatusSkipAlreadyAbsent — pre-probe returned ABSENT
	// so no mutation was attempted. Backend
	// EndpointUninstallAuditService.recordUninstallResult maps this to
	// `verification=ABSENT_VERIFIED` (Codex 019e8de2 iter-1 absorb).
	UninstallFinalStatusSkipAlreadyAbsent = "SKIP_ALREADY_ABSENT"
	// UninstallFinalStatusFailedVerifyGhost — winget reported clean exit
	// but post-probe still MATCHED. Distinct from PARTIAL_RESIDUE (which
	// is a partial removal with detectable identity drift).
	UninstallFinalStatusFailedVerifyGhost = "FAILED_VERIFY_GHOST"
	// UninstallFinalStatusPartialResidue — post-probe returned
	// PRESENT_MISMATCH (binaries gone but registry entries lingering, or
	// vice versa). Operator action: review residue + decide whether to
	// retry with `--purge` (future preset).
	UninstallFinalStatusPartialResidue = "PARTIAL_RESIDUE"
	// UninstallFinalStatusPartialInconclusive — post-probe returned
	// AMBIGUOUS / ERROR / UNSUPPORTED OR the runner timed out / was
	// cancelled. Backend audit verification → VERIFY_INCONCLUSIVE.
	UninstallFinalStatusPartialInconclusive = "PARTIAL_INCONCLUSIVE"
	// UninstallFinalStatusFailedPrecheckInconclusive — pre-probe
	// returned AMBIGUOUS / ERROR. No mutation attempted.
	UninstallFinalStatusFailedPrecheckInconclusive = "FAILED_PRECHECK_INCONCLUSIVE"
	// UninstallFinalStatusFailedExit — winget exit != 0 AND post-probe
	// could NOT confirm absence (Codex 019e8de2 iter-2: this case is the
	// genuine non-zero failure; the contradiction with absent post-probe
	// is resolved in favour of SUCCEEDED_VERIFIED for that branch).
	UninstallFinalStatusFailedExit = "FAILED_EXIT"
	// UninstallFinalStatusFailedUnsupportedPlatform — non-Windows agent.
	UninstallFinalStatusFailedUnsupportedPlatform = "FAILED_UNSUPPORTED_PLATFORM"
	// UninstallFinalStatusFailedUnsupportedVerification — WINGET_PACKAGE
	// detection rule in v1 OR top-level UNSUPPORTED probe state.
	// CONFIRM_ONLY tier cannot certify ABSENT_VERIFIED — fail-closed
	// BEFORE mutation (Codex 019e8de2 iter-1 absorb; defense in depth
	// with backend Phase 1b follow-up gate #419).
	UninstallFinalStatusFailedUnsupportedVerification = "FAILED_UNSUPPORTED_VERIFICATION"
	// UninstallFinalStatusFailedInternal — programmatic error
	// (locator unwired, probe function nil, etc.). Forensic.
	UninstallFinalStatusFailedInternal = "FAILED_INTERNAL"
	// UninstallFinalStatusFailedTimeout — wall-clock budget exhausted
	// before the post-probe could complete. Process tree killed.
	UninstallFinalStatusFailedTimeout = "FAILED_TIMEOUT"
)

// FailedReason codes (machine-readable forensic detail; bounded
// scalar values for the audit row).
const (
	UninstallReasonProbeError                 = "uninstall_probe_error"
	UninstallReasonDetectionRuleInvalid       = "uninstall_detection_rule_invalid"
	UninstallReasonDetectionRuleUnsupportedV1 = "uninstall_detection_rule_unsupported_v1_confirm_only"
	UninstallReasonProviderUnsupported        = "uninstall_provider_unsupported"
	UninstallReasonPackageIDMissing           = "uninstall_package_id_missing"
	UninstallReasonArgsPresetUnknown          = "uninstall_args_policy_preset_unknown"
	UninstallReasonRequestIDMissing           = "uninstall_request_id_missing"
	UninstallReasonLocatorUnavailable         = "uninstall_locator_unavailable"
	UninstallReasonWingetNotInstalled         = "uninstall_winget_not_installed"
	UninstallReasonProbeUnwired               = "uninstall_probe_unwired"
	UninstallReasonRunnerUnwired              = "uninstall_runner_unwired"
	UninstallReasonTimeout                    = "uninstall_timeout"
	UninstallReasonCancelled                  = "uninstall_cancelled"
	UninstallReasonPreProbeAmbiguous          = "uninstall_pre_probe_ambiguous"
	UninstallReasonPreProbeError              = "uninstall_pre_probe_error"
	UninstallReasonPreProbeUnsupported        = "uninstall_pre_probe_unsupported"
	UninstallReasonPostProbeAmbiguous         = "uninstall_post_probe_ambiguous"
	UninstallReasonPostProbeError             = "uninstall_post_probe_error"
	UninstallReasonPostProbeUnsupported       = "uninstall_post_probe_unsupported"
	UninstallReasonExitNonzeroAbsenceUnverified = "uninstall_exit_nonzero_absence_unverified"
	UninstallReasonAuthorityNotAdvertised     = "uninstall_authority_not_advertised"
)

// ────────────────────────────────────────────────────────────────
// Args preset registry (SEPARATE from install presets — Codex iter-1)

// UninstallArgsPresetDefault — only preset shipped in v1. Single-package
// silent uninstall under the trusted winget catalog source. Hard-coded
// argv; NO payload field is interpolated into the command line (shell
// invocation impossible — exec.Cmd argv vector).
const UninstallArgsPresetDefault = "UNINSTALL_DEFAULT"

// uninstallArgsPresets is the closed allow-list for uninstall args.
// Production reads via UninstallArgsForPreset; no public mutator.
// `%PKG%` is substituted by `packageID` at dispatch time. v1 ships only
// one preset; `UNINSTALL_PURGE` and friends are deliberately deferred —
// `--purge`, `--force`, `--preserve` widening risks catalog policy +
// audit semantic drift (Codex 019e8de2 iter-1: v1 conservative).
var uninstallArgsPresets = map[string][]string{
	UninstallArgsPresetDefault: {
		"uninstall",
		"--id", "%PKG%",
		"--exact",
		"--source", "winget",
		"--silent",
		"--accept-source-agreements",
		"--disable-interactivity",
	},
}

// IsKnownUninstallArgsPreset reports whether the supplied preset name
// is recognised by AG-028 v1. The agent MUST refuse to execute an
// uninstall whose preset is unknown.
func IsKnownUninstallArgsPreset(name string) bool {
	_, ok := uninstallArgsPresets[name]
	return ok
}

// UninstallArgsForPreset returns a freshly-allocated args slice for the
// preset with `%PKG%` substituted by packageID. Error if preset unknown
// so callers cannot fall back to a partially-constructed argv.
func UninstallArgsForPreset(name, packageID string) ([]string, error) {
	tmpl, ok := uninstallArgsPresets[name]
	if !ok {
		return nil, fmt.Errorf("AG-028 unknown uninstall args preset %q", name)
	}
	if packageID == "" {
		return nil, errors.New("AG-028 uninstall packageID is empty")
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
// Wire-safe request + result shapes

// UninstallRequest is the wire-safe payload AG-028 consumes. Backend
// Phase 1b `EndpointUninstallService.buildUninstallPayload` constructs
// this verbatim from the catalog row + approved request. AG-028 does
// not transform the payload before consumption beyond field validation.
type UninstallRequest struct {
	Intent            string        `json:"intent"`            // "UNINSTALL"
	RequestID         string        `json:"requestId"`
	CatalogItemID     string        `json:"catalogItemId"`     // slug
	CatalogItemUUID   string        `json:"catalogItemUuid"`
	CatalogPackageID  string        `json:"catalogPackageId"`
	CatalogRowVersion int64         `json:"catalogRowVersion"`
	PackageProvider   string        `json:"packageProvider"`   // "WINGET"
	SourceType        string        `json:"sourceType,omitempty"`
	InstallerType     string        `json:"installerType,omitempty"`
	// PackageID is the agent-consumed identifier (= CatalogPackageID).
	// Mirrors AG-027 InstallRequest.PackageID; the backend
	// `buildUninstallPayload` sends catalogPackageId so this is normally
	// populated from there at the executor layer.
	PackageID         string        `json:"packageId,omitempty"`
	ArgsPolicyPreset  string        `json:"argsPolicyPreset"`  // "UNINSTALL_DEFAULT"
	DetectionRule     DetectionRule `json:"detectionRule"`
	UninstallSupported bool         `json:"uninstallSupported"`
	UninstallProtected bool         `json:"uninstallProtected"`
	CreatedBy         string        `json:"createdBy,omitempty"`
	ApprovedBy        string        `json:"approvedBy,omitempty"`
	ProposeReason     string        `json:"proposeReason,omitempty"`
	ApproveReason     string        `json:"approveReason,omitempty"`
}

// UninstallProbeResult is the absence-aware wrapper around the
// authoritative detector probe (Codex 019e8de2 iter-1 absorb). `State`
// distinguishes ABSENT from PRESENT_MISMATCH from AMBIGUOUS/ERROR — the
// install path's `PreDetectResult.Satisfied=false` blob is too coarse
// to drive a destructive decision tree.
type UninstallProbeResult struct {
	State           ProbeState        `json:"state"`
	Authority       string            `json:"authority,omitempty"` // DetectionReliabilityAuthoritative
	RuleType        DetectionRuleType `json:"ruleType,omitempty"`
	DetectionMethod string            `json:"detectionMethod,omitempty"`
	ReasonCode      string            `json:"reasonCode,omitempty"`
	// SafeEvidence is a bounded scalar map projected by the backend
	// `UninstallEvidencePayloadPolicy` against
	// `ALLOWED_SAFE_EVIDENCE_KEYS`. The agent populates known scalars
	// (matchedPackageId, matchedVersion, matchedProductCode,
	// matchedDisplayName, matchedPublisher, candidateCount,
	// absentReason). Unknown keys are dropped backend-side.
	SafeEvidence map[string]interface{} `json:"safeEvidence,omitempty"`
}

// UninstallResult is the wire-safe outcome the agent reports back via
// the command-result channel. Every field is machine-readable; backend
// `UninstallEvidencePayloadPolicy.redact()` strips raw tails (NOT in
// allow-list) — `StdoutTail`/`StderrTail` therefore land in
// `endpoint_command_results` but NOT in the audit row.
type UninstallResult struct {
	FinalStatus      string               `json:"finalStatus"`
	SchemaVersion    int                  `json:"schemaVersion"`
	Supported        bool                 `json:"supported"`
	FailedReasonCode string               `json:"failedReasonCode,omitempty"`
	ExitCode         int                  `json:"exitCode"`
	DurationMs       int                  `json:"durationMs"`
	RebootRequired   bool                 `json:"rebootRequired"`
	KillStrategy     string               `json:"killStrategy,omitempty"`
	// ProbeState is the post-probe state IF the runner attempted
	// mutation, else the pre-probe state. Drives the backend
	// `deriveVerification(probeState)` mapping
	// (MATCHED→PRESENT_VERIFIED, ABSENT→ABSENT_VERIFIED,
	// PRESENT_MISMATCH→RESIDUE_PRESENT, others→VERIFY_INCONCLUSIVE).
	ProbeState   ProbeState        `json:"probeState,omitempty"`
	Authority    string            `json:"authority,omitempty"`
	RuleType     DetectionRuleType `json:"ruleType,omitempty"`
	SafeEvidence map[string]interface{} `json:"safeEvidence,omitempty"`
	// PreProbe + PostProbe are the structured probe results for forensic
	// audit. The backend sanitiser does NOT surface these in the audit
	// row; they live in `endpoint_command_results.result_payload.details`
	// only. Operators inspect via the per-device drawer "İşlemler"
	// surface.
	PreProbe  UninstallProbeResult `json:"preProbe,omitempty"`
	PostProbe UninstallProbeResult `json:"postProbe,omitempty"`
	// StdoutTail/StderrTail captured for forensic depth; dropped by the
	// backend sanitiser (Codex 019e8d81 iter-6 absorb — backend redactor
	// weaker than agent AG-027L PII redactor, raw tails not surfaced).
	StdoutTail       string `json:"stdoutTail,omitempty"`
	StdoutTruncated  bool   `json:"stdoutTruncated"`
	StdoutTotalBytes int    `json:"stdoutTotalBytes"`
	StderrTail       string `json:"stderrTail,omitempty"`
	StderrTruncated  bool   `json:"stderrTruncated"`
	StderrTotalBytes int    `json:"stderrTotalBytes"`
}

// ────────────────────────────────────────────────────────────────
// Test seam — UninstallOptions

// UninstallProbeFn runs the rule-type-specific absence-aware probe.
// Production wires a thin wrapper around the existing AG-027 detectors
// (probeViaRegistry, probeFileExists, probeFileSha256, probeFileVersion)
// + the ProbeState absence-aware mapping. Tests inject deterministic
// stubs.
type UninstallProbeFn func(ctx context.Context, rule DetectionRule, wingetPath string) UninstallProbeResult

// UninstallRunnerFn launches `winget uninstall` and reports the
// structured outcome. The runner is responsible for:
//
//   - Building os/exec.Cmd with the supplied argv (no shell);
//   - Capturing stdout / stderr up to CaptureLimitBytes;
//   - Reporting exit code + reboot-required signal;
//   - On context cancellation OR timeout, terminating the process tree
//     atomically (Windows: Job Object; fallback: taskkill).
//
// Returns wall-clock duration the uninstall occupied even on error.
type UninstallRunnerFn func(ctx context.Context, wingetPath string, args []string) RunnerOutcome

// UninstallOptions controls every I/O boundary the uninstall pipeline
// reaches across. Zero value yields production defaults on Windows;
// tests override every seam to exercise the pipeline hermetically.
type UninstallOptions struct {
	Locator         Locator
	Probe           UninstallProbeFn
	UninstallRunner UninstallRunnerFn
	Timeout         time.Duration
	Now             func() time.Time
}

// ────────────────────────────────────────────────────────────────
// Decision pipeline

// RunUninstall executes the AG-028 decision pipeline. The function is
// pure with respect to the supplied seams — no global state, no network,
// no process spawn happens here. Every I/O boundary is pluggable for
// testing.
//
// Codex plan-time iter-2 AGREE flow:
//
//	1. Validate detection rule + provider + args preset + package id +
//	   request id (fail-close BEFORE locator).
//	2. v1 WINGET_PACKAGE rejected → FAILED_UNSUPPORTED_VERIFICATION
//	   (defense in depth with backend Phase 1b follow-up gate #419).
//	3. Locate winget (fail-close on locator unavailable).
//	4. Pre-probe (authoritative detector).
//	     • ABSENT  → SKIP_ALREADY_ABSENT + SUCCEEDED.
//	     • MATCHED / PRESENT_MISMATCH → proceed to (5).
//	     • AMBIGUOUS / ERROR → FAILED_PRECHECK_INCONCLUSIVE.
//	     • UNSUPPORTED → FAILED_UNSUPPORTED_VERIFICATION.
//	5. Run `winget uninstall` with hard-coded argv (no shell). Capture
//	   exit + bounded stdout/stderr tails. Honour ctx cancellation /
//	   wall-clock budget via process-tree kill.
//	6. Post-probe (same detector).
//	     • ABSENT  → SUCCEEDED_VERIFIED (even on exit != 0; Codex
//	       iter-2 absorb — post-probe AUTHORITATIVE is the truth, not
//	       exit code).
//	     • MATCHED → FAILED_VERIFY_GHOST (exit 0 case; otherwise
//	       FAILED_EXIT).
//	     • PRESENT_MISMATCH → PARTIAL_RESIDUE.
//	     • AMBIGUOUS / ERROR / UNSUPPORTED → PARTIAL_INCONCLUSIVE.
//	7. Timeout / cancel during runner → process-tree kill, return
//	   FAILED_TIMEOUT (or PARTIAL_INCONCLUSIVE if a bounded post-probe
//	   could still execute under the parent context).
func RunUninstall(parentCtx context.Context, req UninstallRequest, opts UninstallOptions) UninstallResult {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultUninstallTimeout
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	result := UninstallResult{
		SchemaVersion: UninstallSchemaVersion,
		Supported:     true,
		RuleType:      req.DetectionRule.Type,
	}

	// 1. Detection rule basic shape validation. Reuses AG-027 validator
	// for parity with backend `DetectionRuleValidator`.
	if err := validateDetectionRule(req.DetectionRule); err != nil {
		result.FinalStatus = UninstallFinalStatusFailedUnsupportedVerification
		result.FailedReasonCode = UninstallReasonDetectionRuleInvalid
		return result
	}

	// 2. v1 authoritative-tier gate. WINGET_PACKAGE post-uninstall verify
	// is CONFIRM_ONLY (Session-0 winget list cache lag) → fail-closed
	// BEFORE mutation. Backend Phase 1b follow-up gate (#419) already
	// rejects this at propose/approve; this is defense in depth.
	if !isAuthoritativeUninstallRule(req.DetectionRule.Type) {
		result.FinalStatus = UninstallFinalStatusFailedUnsupportedVerification
		result.FailedReasonCode = UninstallReasonDetectionRuleUnsupportedV1
		result.Authority = DetectionReliabilityConfirmOnly
		result.ProbeState = ProbeStateUnsupported
		return result
	}

	// 3. Provider + payload integrity.
	if !strings.EqualFold(strings.TrimSpace(req.PackageProvider), "WINGET") {
		result.FinalStatus = UninstallFinalStatusFailedUnsupportedVerification
		result.FailedReasonCode = UninstallReasonProviderUnsupported
		return result
	}
	pkg := strings.TrimSpace(req.PackageID)
	if pkg == "" {
		pkg = strings.TrimSpace(req.CatalogPackageID)
	}
	if pkg == "" {
		result.FinalStatus = UninstallFinalStatusFailedInternal
		result.FailedReasonCode = UninstallReasonPackageIDMissing
		return result
	}
	if strings.TrimSpace(req.RequestID) == "" {
		result.FinalStatus = UninstallFinalStatusFailedInternal
		result.FailedReasonCode = UninstallReasonRequestIDMissing
		return result
	}
	if !IsKnownUninstallArgsPreset(req.ArgsPolicyPreset) {
		result.FinalStatus = UninstallFinalStatusFailedUnsupportedVerification
		result.FailedReasonCode = UninstallReasonArgsPresetUnknown
		return result
	}

	// 4. Locate winget binary.
	if opts.Locator == nil {
		result.FinalStatus = UninstallFinalStatusFailedUnsupportedPlatform
		result.FailedReasonCode = UninstallReasonLocatorUnavailable
		return result
	}
	wingetPath, err := opts.Locator()
	if err != nil || wingetPath == "" {
		result.FinalStatus = UninstallFinalStatusFailedUnsupportedPlatform
		result.FailedReasonCode = UninstallReasonWingetNotInstalled
		return result
	}
	if opts.Probe == nil {
		result.FinalStatus = UninstallFinalStatusFailedInternal
		result.FailedReasonCode = UninstallReasonProbeUnwired
		return result
	}

	startedAt := opts.Now()
	ctx, cancel := context.WithTimeout(parentCtx, opts.Timeout)
	defer cancel()

	// 5. Pre-uninstall probe.
	preCtx, preCancel := context.WithTimeout(ctx, UninstallProbeTimeout)
	pre := opts.Probe(preCtx, req.DetectionRule, wingetPath)
	preCancel()
	if !IsKnownProbeState(pre.State) {
		pre.State = ProbeStateError
		if pre.ReasonCode == "" {
			pre.ReasonCode = "unknown_probe_state"
		}
	}
	result.PreProbe = pre
	result.ProbeState = pre.State
	result.Authority = pre.Authority
	result.SafeEvidence = pre.SafeEvidence

	switch pre.State {
	case ProbeStateAbsent:
		// Pre-uninstall short-circuit: target already absent. No
		// mutation; backend audit row will record
		// `verification=ABSENT_VERIFIED` (Codex 019e8de2 iter-1).
		result.FinalStatus = UninstallFinalStatusSkipAlreadyAbsent
		result.DurationMs = elapsedMs(startedAt, opts.Now)
		return result
	case ProbeStateAmbiguous:
		result.FinalStatus = UninstallFinalStatusFailedPrecheckInconclusive
		result.FailedReasonCode = UninstallReasonPreProbeAmbiguous
		result.DurationMs = elapsedMs(startedAt, opts.Now)
		return result
	case ProbeStateError:
		result.FinalStatus = UninstallFinalStatusFailedPrecheckInconclusive
		result.FailedReasonCode = UninstallReasonPreProbeError
		result.DurationMs = elapsedMs(startedAt, opts.Now)
		return result
	case ProbeStateUnsupported:
		result.FinalStatus = UninstallFinalStatusFailedUnsupportedVerification
		result.FailedReasonCode = UninstallReasonPreProbeUnsupported
		result.DurationMs = elapsedMs(startedAt, opts.Now)
		return result
	}

	// 6. Build hard-coded argv + run.
	args, argsErr := UninstallArgsForPreset(req.ArgsPolicyPreset, pkg)
	if argsErr != nil {
		result.FinalStatus = UninstallFinalStatusFailedUnsupportedVerification
		result.FailedReasonCode = UninstallReasonArgsPresetUnknown
		result.DurationMs = elapsedMs(startedAt, opts.Now)
		return result
	}
	if opts.UninstallRunner == nil {
		result.FinalStatus = UninstallFinalStatusFailedInternal
		result.FailedReasonCode = UninstallReasonRunnerUnwired
		result.DurationMs = elapsedMs(startedAt, opts.Now)
		return result
	}
	outcome := opts.UninstallRunner(ctx, wingetPath, args)
	result.ExitCode = outcome.ExitCode
	result.DurationMs = elapsedMs(startedAt, opts.Now)
	if outcome.DurationMs > 0 {
		result.DurationMs = outcome.DurationMs
	}
	result.RebootRequired = outcome.RebootRequired
	result.KillStrategy = outcome.KillStrategy
	result.StdoutTail = outcome.StdoutTail
	result.StdoutTruncated = outcome.StdoutTruncated
	result.StdoutTotalBytes = outcome.StdoutTotalBytes
	result.StderrTail = outcome.StderrTail
	result.StderrTruncated = outcome.StderrTruncated
	result.StderrTotalBytes = outcome.StderrTotalBytes

	if outcome.TimedOut {
		// Best-effort post-probe under the parent context. If the parent
		// context is already done (true wall-clock exhaustion) the probe
		// fails fast; otherwise we still get a verdict even on timeout.
		post := runPostProbeBestEffort(parentCtx, opts.Probe, req.DetectionRule, wingetPath)
		result.PostProbe = post
		result.ProbeState = post.State
		if post.State == ProbeStateAbsent {
			// Timeout during winget but target IS absent post-mutation —
			// surface SUCCEEDED_VERIFIED with the timeout anomaly in
			// safeEvidence (Codex 019e8de2 iter-2 — post-probe
			// AUTHORITATIVE is the truth).
			result.FinalStatus = UninstallFinalStatusSucceededVerified
			result.SafeEvidence = mergeEvidence(post.SafeEvidence, map[string]interface{}{
				"absentReason": "post_probe_absent_after_timeout",
			})
			return result
		}
		result.FinalStatus = UninstallFinalStatusFailedTimeout
		result.FailedReasonCode = UninstallReasonTimeout
		return result
	}

	// 7. Post-uninstall probe. Always run for a definitive verdict.
	postCtx, postCancel := context.WithTimeout(parentCtx, UninstallProbeTimeout)
	post := opts.Probe(postCtx, req.DetectionRule, wingetPath)
	postCancel()
	if !IsKnownProbeState(post.State) {
		post.State = ProbeStateError
		if post.ReasonCode == "" {
			post.ReasonCode = "unknown_probe_state"
		}
	}
	result.PostProbe = post
	result.ProbeState = post.State
	if post.Authority != "" {
		result.Authority = post.Authority
	}
	result.SafeEvidence = post.SafeEvidence

	switch post.State {
	case ProbeStateAbsent:
		// Codex 019e8de2 iter-2 absorb: even on exit != 0 the AUTHORITATIVE
		// post-probe ABSENT is the truth. SUCCEEDED_VERIFIED + carry
		// exit-code anomaly in safeEvidence for forensic audit.
		result.FinalStatus = UninstallFinalStatusSucceededVerified
		if outcome.ExitCode != 0 {
			result.SafeEvidence = mergeEvidence(post.SafeEvidence, map[string]interface{}{
				"absentReason": "post_probe_absent_after_nonzero_exit",
			})
		}
	case ProbeStateMatched:
		if outcome.ExitCode == 0 {
			result.FinalStatus = UninstallFinalStatusFailedVerifyGhost
			result.FailedReasonCode = UninstallReasonExitNonzeroAbsenceUnverified
		} else {
			result.FinalStatus = UninstallFinalStatusFailedExit
			result.FailedReasonCode = UninstallReasonExitNonzeroAbsenceUnverified
		}
	case ProbeStatePresentMismatch:
		result.FinalStatus = UninstallFinalStatusPartialResidue
		result.FailedReasonCode = UninstallReasonPostProbeError
	case ProbeStateAmbiguous:
		result.FinalStatus = UninstallFinalStatusPartialInconclusive
		result.FailedReasonCode = UninstallReasonPostProbeAmbiguous
	case ProbeStateError:
		result.FinalStatus = UninstallFinalStatusPartialInconclusive
		result.FailedReasonCode = UninstallReasonPostProbeError
	case ProbeStateUnsupported:
		result.FinalStatus = UninstallFinalStatusPartialInconclusive
		result.FailedReasonCode = UninstallReasonPostProbeUnsupported
	default:
		result.FinalStatus = UninstallFinalStatusPartialInconclusive
		result.FailedReasonCode = UninstallReasonPostProbeError
	}
	return result
}

// ────────────────────────────────────────────────────────────────
// Helpers

// isAuthoritativeUninstallRule mirrors the backend
// `EndpointUninstallService.AUTHORITATIVE_UNINSTALL_RULES`. v1
// closed-allowlist (Codex 019e8de2 iter-1 absorb).
func isAuthoritativeUninstallRule(t DetectionRuleType) bool {
	switch t {
	case DetectionRuleTypeRegistryUninstall,
		DetectionRuleTypeFileExists,
		DetectionRuleTypeFileSha256,
		DetectionRuleTypeFileVersion:
		return true
	default:
		return false
	}
}

// runPostProbeBestEffort runs the post-probe under the PARENT context so
// a timed-out runner still gets a verdict if the parent has remaining
// budget. Returns ProbeStateError if the parent is already done.
func runPostProbeBestEffort(parentCtx context.Context,
	probe UninstallProbeFn, rule DetectionRule, wingetPath string,
) UninstallProbeResult {
	if parentCtx.Err() != nil {
		return UninstallProbeResult{
			State:      ProbeStateError,
			ReasonCode: UninstallReasonTimeout,
		}
	}
	postCtx, cancel := context.WithTimeout(parentCtx, UninstallProbeTimeout)
	defer cancel()
	return probe(postCtx, rule, wingetPath)
}

// mergeEvidence shallow-merges b into a, allocating a fresh map. Callers
// pass nil for `a` when populating from a clean post-probe.
func mergeEvidence(a, b map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// JSONOrErr is a small convenience to serialise an UninstallResult for
// logging / forensic dumps. Production hooks use the JSON marshaller
// implicitly via the command-result wire encoder; this helper is for
// agent debug stdout where readability matters.
func JSONOrErr(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("<marshal error: %v>", err)
	}
	return string(b)
}
