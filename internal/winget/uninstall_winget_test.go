package winget

import (
	"context"
	"strings"
	"testing"
	"time"
)

// AG-028 — RunUninstall pipeline tests (Faz 22.5.6). Cross-platform
// hermetic via injected seams. Each case asserts the closed-allowlist
// decision: finalStatus + probeState + (optional) safeEvidence.

func goodCatalogRule() DetectionRule {
	return DetectionRule{
		Type:        DetectionRuleTypeRegistryUninstall,
		DisplayName: "7-Zip",
		Publisher:   "Igor Pavlov",
	}
}

func goodReq() UninstallRequest {
	return UninstallRequest{
		Intent:           "UNINSTALL",
		RequestID:        "req-abc",
		PackageProvider:  "WINGET",
		PackageID:        "7zip.7zip",
		CatalogPackageID: "7zip.7zip",
		ArgsPolicyPreset: UninstallArgsPresetDefault,
		DetectionRule:    goodCatalogRule(),
	}
}

func stubLocator(path string) Locator {
	return func() (string, error) { return path, nil }
}

func stubProbeFixed(result UninstallProbeResult) UninstallProbeFn {
	return func(ctx context.Context, rule DetectionRule, wingetPath string) UninstallProbeResult {
		return result
	}
}

// stubProbeSequence returns successive results on each call.
func stubProbeSequence(results ...UninstallProbeResult) UninstallProbeFn {
	idx := 0
	return func(ctx context.Context, rule DetectionRule, wingetPath string) UninstallProbeResult {
		if idx < len(results) {
			r := results[idx]
			idx++
			return r
		}
		return results[len(results)-1]
	}
}

func stubRunner(outcome RunnerOutcome) UninstallRunnerFn {
	return func(ctx context.Context, wingetPath string, args []string) RunnerOutcome {
		return outcome
	}
}

func TestRunUninstall_PreAbsent_ShortCircuitsToSkip(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe:   stubProbeFixed(UninstallProbeResult{State: ProbeStateAbsent, Authority: DetectionReliabilityAuthoritative}),
		UninstallRunner: stubRunner(RunnerOutcome{
			ExitCode: 999, // would fail if the runner was called
		}),
		Now: func() time.Time { return time.Unix(0, 0) },
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusSkipAlreadyAbsent {
		t.Fatalf("expected SKIP_ALREADY_ABSENT, got %s", res.FinalStatus)
	}
	if res.ProbeState != ProbeStateAbsent {
		t.Fatalf("expected probeState=ABSENT, got %s", res.ProbeState)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0 (runner NOT called), got %d", res.ExitCode)
	}
}

func TestRunUninstall_MatchedThenAbsent_VerifiedSuccess(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe: stubProbeSequence(
			UninstallProbeResult{State: ProbeStateMatched, Authority: DetectionReliabilityAuthoritative},
			UninstallProbeResult{State: ProbeStateAbsent, Authority: DetectionReliabilityAuthoritative},
		),
		UninstallRunner: stubRunner(RunnerOutcome{ExitCode: 0}),
		Now:             time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusSucceededVerified {
		t.Fatalf("expected SUCCEEDED_VERIFIED, got %s", res.FinalStatus)
	}
	if res.ProbeState != ProbeStateAbsent {
		t.Fatalf("expected post-probe ABSENT, got %s", res.ProbeState)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d", res.ExitCode)
	}
	// No anomaly should be set on clean exit + absent.
	if v, ok := res.SafeEvidence["absentReason"]; ok && v != nil {
		t.Fatalf("did not expect absentReason on clean exit, got %v", v)
	}
}

// Codex 019e8de2 iter-2 exit-code decision: post-probe AUTHORITATIVE
// ABSENT overrides exit non-zero. SUCCEEDED_VERIFIED + safeEvidence
// carries the anomaly.
func TestRunUninstall_MatchedThenAbsent_ExitNonZero_StillVerified(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe: stubProbeSequence(
			UninstallProbeResult{State: ProbeStateMatched, Authority: DetectionReliabilityAuthoritative},
			UninstallProbeResult{State: ProbeStateAbsent, Authority: DetectionReliabilityAuthoritative},
		),
		UninstallRunner: stubRunner(RunnerOutcome{ExitCode: 1603}),
		Now:             time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusSucceededVerified {
		t.Fatalf("expected SUCCEEDED_VERIFIED (post-probe ABSENT is the truth), got %s", res.FinalStatus)
	}
	if res.ExitCode != 1603 {
		t.Fatalf("expected exit 1603 preserved for forensic audit, got %d", res.ExitCode)
	}
	got, ok := res.SafeEvidence["absentReason"]
	if !ok {
		t.Fatalf("expected safeEvidence.absentReason on exit-nonzero + post-absent")
	}
	if got != "post_probe_absent_after_nonzero_exit" {
		t.Fatalf("expected absentReason=post_probe_absent_after_nonzero_exit, got %v", got)
	}
}

func TestRunUninstall_MatchedThenMatched_CleanExit_VerifyGhost(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe: stubProbeSequence(
			UninstallProbeResult{State: ProbeStateMatched, Authority: DetectionReliabilityAuthoritative},
			UninstallProbeResult{State: ProbeStateMatched, Authority: DetectionReliabilityAuthoritative},
		),
		UninstallRunner: stubRunner(RunnerOutcome{ExitCode: 0}),
		Now:             time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusFailedVerifyGhost {
		t.Fatalf("expected FAILED_VERIFY_GHOST, got %s", res.FinalStatus)
	}
}

func TestRunUninstall_MatchedThenMatched_NonZeroExit_FailedExit(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe: stubProbeSequence(
			UninstallProbeResult{State: ProbeStateMatched, Authority: DetectionReliabilityAuthoritative},
			UninstallProbeResult{State: ProbeStateMatched, Authority: DetectionReliabilityAuthoritative},
		),
		UninstallRunner: stubRunner(RunnerOutcome{ExitCode: 1}),
		Now:             time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusFailedExit {
		t.Fatalf("expected FAILED_EXIT, got %s", res.FinalStatus)
	}
}

func TestRunUninstall_MatchedThenPresentMismatch_PartialResidue(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe: stubProbeSequence(
			UninstallProbeResult{State: ProbeStateMatched, Authority: DetectionReliabilityAuthoritative},
			UninstallProbeResult{State: ProbeStatePresentMismatch, Authority: DetectionReliabilityAuthoritative},
		),
		UninstallRunner: stubRunner(RunnerOutcome{ExitCode: 0}),
		Now:             time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusPartialResidue {
		t.Fatalf("expected PARTIAL_RESIDUE, got %s", res.FinalStatus)
	}
}

func TestRunUninstall_MatchedThenAmbiguous_PartialInconclusive(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe: stubProbeSequence(
			UninstallProbeResult{State: ProbeStateMatched, Authority: DetectionReliabilityAuthoritative},
			UninstallProbeResult{State: ProbeStateAmbiguous, Authority: DetectionReliabilityAuthoritative},
		),
		UninstallRunner: stubRunner(RunnerOutcome{ExitCode: 0}),
		Now:             time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusPartialInconclusive {
		t.Fatalf("expected PARTIAL_INCONCLUSIVE, got %s", res.FinalStatus)
	}
}

func TestRunUninstall_PreAmbiguous_FailedPrecheckInconclusive(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator:         stubLocator("/path/to/winget"),
		Probe:           stubProbeFixed(UninstallProbeResult{State: ProbeStateAmbiguous, Authority: DetectionReliabilityAuthoritative}),
		UninstallRunner: stubRunner(RunnerOutcome{ExitCode: 999}),
		Now:             time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusFailedPrecheckInconclusive {
		t.Fatalf("expected FAILED_PRECHECK_INCONCLUSIVE, got %s", res.FinalStatus)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0 (runner NOT called on pre-probe ambiguous), got %d", res.ExitCode)
	}
}

func TestRunUninstall_PreError_FailedPrecheckInconclusive(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator:         stubLocator("/path/to/winget"),
		Probe:           stubProbeFixed(UninstallProbeResult{State: ProbeStateError, Authority: DetectionReliabilityAuthoritative}),
		UninstallRunner: stubRunner(RunnerOutcome{ExitCode: 999}),
		Now:             time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusFailedPrecheckInconclusive {
		t.Fatalf("expected FAILED_PRECHECK_INCONCLUSIVE on pre-probe ERROR, got %s", res.FinalStatus)
	}
}

// Codex 019e8de2 iter-1 absorb — WINGET_PACKAGE v1 fail-closed.
func TestRunUninstall_WingetPackageRule_FailedUnsupportedVerification(t *testing.T) {
	req := goodReq()
	req.DetectionRule = DetectionRule{
		Type:      DetectionRuleTypeWingetPackage,
		PackageID: "7zip.7zip",
	}
	opts := UninstallOptions{
		Locator:         stubLocator("/path/to/winget"),
		Probe:           stubProbeFixed(UninstallProbeResult{State: ProbeStateMatched}),
		UninstallRunner: stubRunner(RunnerOutcome{ExitCode: 999}),
		Now:             time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusFailedUnsupportedVerification {
		t.Fatalf("expected FAILED_UNSUPPORTED_VERIFICATION for WINGET_PACKAGE v1, got %s", res.FinalStatus)
	}
	if res.FailedReasonCode != UninstallReasonDetectionRuleUnsupportedV1 {
		t.Fatalf("expected reason=%s, got %s", UninstallReasonDetectionRuleUnsupportedV1, res.FailedReasonCode)
	}
}

func TestRunUninstall_MissingRequestID_FailsValidation(t *testing.T) {
	req := goodReq()
	req.RequestID = ""
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe:   stubProbeFixed(UninstallProbeResult{State: ProbeStateMatched}),
		Now:     time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusFailedUnsupportedVerification {
		t.Fatalf("expected FAILED_UNSUPPORTED_VERIFICATION on missing requestId, got %s", res.FinalStatus)
	}
	if res.FailedReasonCode != UninstallReasonRequestIDMissing {
		t.Fatalf("expected reason=%s, got %s", UninstallReasonRequestIDMissing, res.FailedReasonCode)
	}
}

func TestRunUninstall_MissingPackageID_FailsValidation(t *testing.T) {
	req := goodReq()
	req.PackageID = ""
	req.CatalogPackageID = ""
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe:   stubProbeFixed(UninstallProbeResult{State: ProbeStateMatched}),
		Now:     time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusFailedUnsupportedVerification {
		t.Fatalf("expected FAILED_UNSUPPORTED_VERIFICATION on missing packageId, got %s", res.FinalStatus)
	}
	if res.FailedReasonCode != UninstallReasonPackageIDMissing {
		t.Fatalf("expected reason=%s, got %s", UninstallReasonPackageIDMissing, res.FailedReasonCode)
	}
}

func TestRunUninstall_UnknownArgsPreset_FailsUnsupported(t *testing.T) {
	req := goodReq()
	req.ArgsPolicyPreset = "DEFAULT" // install preset, NOT shared (Codex iter-1)
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe:   stubProbeFixed(UninstallProbeResult{State: ProbeStateMatched}),
		Now:     time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusFailedUnsupportedVerification {
		t.Fatalf("expected FAILED_UNSUPPORTED_VERIFICATION on install-DEFAULT preset, got %s", res.FinalStatus)
	}
	if res.FailedReasonCode != UninstallReasonArgsPresetUnknown {
		t.Fatalf("expected reason=%s, got %s", UninstallReasonArgsPresetUnknown, res.FailedReasonCode)
	}
}

func TestRunUninstall_NonWingetProvider_FailsUnsupported(t *testing.T) {
	req := goodReq()
	req.PackageProvider = "SCOOP"
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe:   stubProbeFixed(UninstallProbeResult{State: ProbeStateMatched}),
		Now:     time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusFailedUnsupportedVerification {
		t.Fatalf("expected FAILED_UNSUPPORTED_VERIFICATION for non-WINGET provider, got %s", res.FinalStatus)
	}
}

func TestRunUninstall_LocatorMissing_FailsUnsupportedPlatform(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator: nil, // simulate no winget
		Probe:   stubProbeFixed(UninstallProbeResult{State: ProbeStateMatched}),
		Now:     time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusFailedUnsupportedPlatform {
		t.Fatalf("expected FAILED_UNSUPPORTED_PLATFORM, got %s", res.FinalStatus)
	}
}

func TestRunUninstall_RunnerTimedOut_PostAbsent_SucceededWithAnomaly(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe: stubProbeSequence(
			UninstallProbeResult{State: ProbeStateMatched, Authority: DetectionReliabilityAuthoritative},
			UninstallProbeResult{State: ProbeStateAbsent, Authority: DetectionReliabilityAuthoritative},
		),
		UninstallRunner: stubRunner(RunnerOutcome{ExitCode: -1, TimedOut: true, KillStrategy: "taskkill_tree"}),
		Now:             time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusSucceededVerified {
		t.Fatalf("expected SUCCEEDED_VERIFIED on timeout+post-absent, got %s", res.FinalStatus)
	}
	got, ok := res.SafeEvidence["absentReason"]
	if !ok || got != "post_probe_absent_after_timeout" {
		t.Fatalf("expected absentReason=post_probe_absent_after_timeout, got %v", got)
	}
}

func TestRunUninstall_RunnerTimedOut_PostMatched_Timeout(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe: stubProbeSequence(
			UninstallProbeResult{State: ProbeStateMatched, Authority: DetectionReliabilityAuthoritative},
			UninstallProbeResult{State: ProbeStateMatched, Authority: DetectionReliabilityAuthoritative},
		),
		UninstallRunner: stubRunner(RunnerOutcome{ExitCode: -1, TimedOut: true, KillStrategy: "taskkill_tree"}),
		Now:             time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusPartialInconclusive {
		t.Fatalf("expected PARTIAL_INCONCLUSIVE on timeout+post-matched, got %s", res.FinalStatus)
	}
}

func TestUninstallArgsForPreset_DefaultBuildsValidArgv(t *testing.T) {
	args, err := UninstallArgsForPreset(UninstallArgsPresetDefault, "7zip.7zip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.HasPrefix(joined, "uninstall ") {
		t.Fatalf("expected argv to start with 'uninstall', got %q", joined)
	}
	if !strings.Contains(joined, "--exact") {
		t.Fatalf("expected --exact in argv, got %q", joined)
	}
	if !strings.Contains(joined, "--silent") {
		t.Fatalf("expected --silent in argv, got %q", joined)
	}
	if !strings.Contains(joined, "--disable-interactivity") {
		t.Fatalf("expected --disable-interactivity, got %q", joined)
	}
	if !strings.Contains(joined, "7zip.7zip") {
		t.Fatalf("expected packageId substituted, got %q", joined)
	}
}

func TestUninstallArgsForPreset_InstallDefaultRejected(t *testing.T) {
	// Codex 019e8de2 iter-1: install DEFAULT must NOT be reachable via
	// the uninstall preset registry. Different preset, different argv.
	_, err := UninstallArgsForPreset("DEFAULT", "7zip.7zip")
	if err == nil {
		t.Fatalf("expected error for install DEFAULT preset reuse, got nil")
	}
}

func TestUninstallArgsForPreset_EmptyPackageIDRejected(t *testing.T) {
	_, err := UninstallArgsForPreset(UninstallArgsPresetDefault, "")
	if err == nil {
		t.Fatalf("expected error for empty packageID")
	}
}

func TestIsKnownProbeState_KnownAndUnknown(t *testing.T) {
	for _, s := range []ProbeState{
		ProbeStateMatched, ProbeStateAbsent, ProbeStatePresentMismatch,
		ProbeStateAmbiguous, ProbeStateError, ProbeStateUnsupported,
	} {
		if !IsKnownProbeState(s) {
			t.Errorf("expected %q to be known", s)
		}
	}
	if IsKnownProbeState("EXTRA_GALACTIC") {
		t.Errorf("expected unknown state to be rejected")
	}
}

func TestRunUninstall_UnknownProbeState_NormalizesToError(t *testing.T) {
	req := goodReq()
	opts := UninstallOptions{
		Locator: stubLocator("/path/to/winget"),
		Probe:   stubProbeFixed(UninstallProbeResult{State: ProbeState("MARTIAN"), Authority: DetectionReliabilityAuthoritative}),
		UninstallRunner: stubRunner(RunnerOutcome{ExitCode: 0}),
		Now: time.Now,
	}
	res := RunUninstall(context.Background(), req, opts)
	if res.FinalStatus != UninstallFinalStatusFailedPrecheckInconclusive {
		t.Fatalf("expected unknown probe-state to normalise to ERROR → FAILED_PRECHECK_INCONCLUSIVE, got %s",
			res.FinalStatus)
	}
}
