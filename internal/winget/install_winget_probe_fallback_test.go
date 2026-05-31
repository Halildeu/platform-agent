package winget

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────
// AG-027 detection-probe source→no-source fallback
//
// LIVE evidence (7-Zip smoke, HALILKOOLUB735): under the SYSTEM
// Session-0 service context `winget list --id <pkg> --exact --source
// winget` cannot correlate an installed MSI (ARP) entry to the catalog
// source and returns a clean no-match even though the package IS
// installed, so pre-detect missed → pipeline installed → winget exit
// 0x8A150061 (already-installed) → FAILED_INSTALL. These tests lock the
// fix: the no-source ARP fallback finds the installed package, and the
// already-installed exit is verify-gated rather than terminal.

const probeFoundSourceOutput = `Name       Id         Version  Available  Source
-------    --------   -------  ---------  --------
7-Zip      7zip.7zip  24.07    24.10      winget
`

// Header + separator, no matching data row: a clean (exit 0) miss, which
// is exactly the source-correlation failure mode observed live.
const probeEmptyOutput = `Name       Id         Version
-------    --------   -------
`

type fakeProbeResult struct {
	stdout string
	err    error
}

type fakeProbeExec struct {
	results []fakeProbeResult
	calls   [][]string
}

func (f *fakeProbeExec) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	i := len(f.calls) - 1
	if i >= len(f.results) {
		return nil, fmt.Errorf("unexpected probe call #%d args=%v", i+1, args)
	}
	r := f.results[i]
	return []byte(r.stdout), r.err
}

// fakeExitError mirrors os/exec.ExitError's ExitCode() int surface so the
// probe's errors.As(err, &interface{ ExitCode() int }) classifies it as a
// soft "no matching package" miss.
type fakeExitError struct{ code int }

func (e fakeExitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }
func (e fakeExitError) ExitCode() int { return e.code }

func argsContainSourceWinget(args []string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--source" && args[i+1] == "winget" {
			return true
		}
	}
	return false
}

func wingetRule() DetectionRule {
	return DetectionRule{Type: DetectionRuleTypeWingetPackage, PackageID: "7zip.7zip"}
}

func TestProbeViaWingetList_SourceFound_NoFallback(t *testing.T) {
	exec := &fakeProbeExec{results: []fakeProbeResult{{stdout: probeFoundSourceOutput}}}
	res, err := ProbeViaWingetList(context.Background(), exec.run, wingetRule(), "winget")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Satisfied {
		t.Fatal("expected satisfied from source-scoped probe")
	}
	if res.DetectionMethod != DetectionMethodSource {
		t.Fatalf("detectionMethod = %q want %q", res.DetectionMethod, DetectionMethodSource)
	}
	if len(exec.calls) != 1 {
		t.Fatalf("expected exactly 1 probe call (no fallback), got %d", len(exec.calls))
	}
	if !argsContainSourceWinget(exec.calls[0]) {
		t.Fatalf("attempt 1 must be source-scoped, args=%v", exec.calls[0])
	}
}

func TestProbeViaWingetList_SourceEmptyCleanMiss_FallbackFound(t *testing.T) {
	exec := &fakeProbeExec{results: []fakeProbeResult{
		{stdout: probeEmptyOutput},       // attempt 1: source-scoped, exit 0 but no rows
		{stdout: probeFoundSourceOutput}, // attempt 2: no-source ARP, found
	}}
	res, err := ProbeViaWingetList(context.Background(), exec.run, wingetRule(), "winget")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Satisfied {
		t.Fatal("expected no-source fallback to find the installed package")
	}
	if res.DetectionMethod != DetectionMethodNoSourceFallback {
		t.Fatalf("detectionMethod = %q want %q", res.DetectionMethod, DetectionMethodNoSourceFallback)
	}
	if res.MatchedVersion != "24.07" {
		t.Fatalf("matchedVersion = %q want 24.07", res.MatchedVersion)
	}
	if len(exec.calls) != 2 {
		t.Fatalf("expected 2 probe calls, got %d", len(exec.calls))
	}
	if !argsContainSourceWinget(exec.calls[0]) {
		t.Fatalf("attempt 1 must be source-scoped, args=%v", exec.calls[0])
	}
	if argsContainSourceWinget(exec.calls[1]) {
		t.Fatalf("attempt 2 must drop --source winget, args=%v", exec.calls[1])
	}
}

func TestProbeViaWingetList_SourceNonzeroMiss_FallbackFound(t *testing.T) {
	exec := &fakeProbeExec{results: []fakeProbeResult{
		{err: fakeExitError{code: 1}},    // attempt 1: source-scoped, non-zero "no match"
		{stdout: probeFoundSourceOutput}, // attempt 2: no-source ARP, found
	}}
	res, err := ProbeViaWingetList(context.Background(), exec.run, wingetRule(), "winget")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Satisfied {
		t.Fatal("expected no-source fallback to find the installed package")
	}
	if res.DetectionMethod != DetectionMethodNoSourceFallback {
		t.Fatalf("detectionMethod = %q want %q", res.DetectionMethod, DetectionMethodNoSourceFallback)
	}
	if len(exec.calls) != 2 {
		t.Fatalf("expected 2 probe calls, got %d", len(exec.calls))
	}
}

func TestProbeViaWingetList_BothMiss_NotSatisfied(t *testing.T) {
	exec := &fakeProbeExec{results: []fakeProbeResult{
		{err: fakeExitError{code: 1}}, // source miss
		{stdout: probeEmptyOutput},    // no-source miss
	}}
	res, err := ProbeViaWingetList(context.Background(), exec.run, wingetRule(), "winget")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Satisfied {
		t.Fatal("expected not-satisfied when both attempts miss")
	}
	if len(exec.calls) != 2 {
		t.Fatalf("expected 2 probe calls, got %d", len(exec.calls))
	}
}

func TestProbeViaWingetList_HardErrorPropagates_NoFallback(t *testing.T) {
	// A non-exit error (e.g. winget launch failure) is a HARD error: it
	// must bubble up so the pipeline maps FAILED_INTERNAL, and it must NOT
	// trigger the no-source fallback (a genuine not-installed result must
	// never be masked by a probe that could not run).
	exec := &fakeProbeExec{results: []fakeProbeResult{
		{err: errors.New("winget.exe: file not found")},
	}}
	_, err := ProbeViaWingetList(context.Background(), exec.run, wingetRule(), "winget")
	if err == nil {
		t.Fatal("expected hard error to propagate")
	}
	if len(exec.calls) != 1 {
		t.Fatalf("hard error must NOT trigger fallback; got %d calls", len(exec.calls))
	}
}

func TestProbeViaWingetList_TimeoutPropagates(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()
	exec := &fakeProbeExec{results: []fakeProbeResult{{stdout: probeEmptyOutput}}}
	_, err := ProbeViaWingetList(ctx, exec.run, wingetRule(), "winget")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if len(exec.calls) != 1 {
		t.Fatalf("timeout must NOT trigger fallback; got %d calls", len(exec.calls))
	}
}

func TestProbeViaWingetList_NoFuzzyNameMatch(t *testing.T) {
	// Detection requires an exact package-id match even in the no-source
	// fallback — a row for a different id must not satisfy.
	other := `Name       Id         Version
-------    --------   -------
Notepad++  Notepadpp  8.6.5
`
	exec := &fakeProbeExec{results: []fakeProbeResult{
		{stdout: probeEmptyOutput}, // source miss
		{stdout: other},            // no-source: different package
	}}
	res, err := ProbeViaWingetList(context.Background(), exec.run, wingetRule(), "winget")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Satisfied {
		t.Fatal("a non-matching id must not satisfy detection")
	}
}

// ────────────────────────────────────────────────────────────────
// already-installed exit-code handling (0x8A150061)

func TestIsWingetAlreadyInstalledExit_NormalizesSignedAndUnsigned(t *testing.T) {
	if !isWingetAlreadyInstalledExit(2316632161) {
		t.Fatal("unsigned 2316632161 should match 0x8A150061")
	}
	if !isWingetAlreadyInstalledExit(-1978335135) {
		t.Fatal("signed int32 -1978335135 should match 0x8A150061")
	}
	for _, code := range []int{0, 1, 3010, 2} {
		if isWingetAlreadyInstalledExit(code) {
			t.Fatalf("exit %d must NOT be classified already-installed", code)
		}
	}
}

func TestRunInstall_AlreadyInstalledExit_Noop(t *testing.T) {
	// winget exit 0x8A150061 (already installed) is winget's own authority
	// → SUCCEEDED_NOOP. A positive post-verify confirms it (SATISFIED).
	req := baseRequest()
	pre := PreDetectResult{Satisfied: false}
	post := PreDetectResult{Satisfied: true, MatchedPackageID: "7zip.7zip", MatchedVersion: "26.01"}
	callCounter := false
	probe := &stubProbe{pre: pre, post: post, postCall: &callCounter}
	runner := func(_ context.Context, _ string, _ []string) RunnerOutcome {
		return RunnerOutcome{ExitCode: 2316632161, DurationMs: 700} // 0x8A150061
	}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, runner, okEgress()))
	if res.FinalStatus != FinalStatusSucceededNoop {
		t.Fatalf("got %s want SUCCEEDED_NOOP (already-installed is winget's authority)", res.FinalStatus)
	}
	if res.PostVerification.Status != PostVerifyStatusSatisfied {
		t.Fatalf("postVerification.status = %q want SATISFIED", res.PostVerification.Status)
	}
	if res.ExitCode != 2316632161 {
		t.Fatalf("winget exit code must be retained for audit, got %d", res.ExitCode)
	}
}

func TestRunInstall_AlreadyInstalledExitSigned_Noop(t *testing.T) {
	req := baseRequest()
	pre := PreDetectResult{Satisfied: false}
	post := PreDetectResult{Satisfied: true, MatchedPackageID: "7zip.7zip", MatchedVersion: "26.01"}
	callCounter := false
	probe := &stubProbe{pre: pre, post: post, postCall: &callCounter}
	runner := func(_ context.Context, _ string, _ []string) RunnerOutcome {
		return RunnerOutcome{ExitCode: -1978335135, DurationMs: 700} // 0x8A150061 as int32
	}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, runner, okEgress()))
	if res.FinalStatus != FinalStatusSucceededNoop {
		t.Fatalf("got %s want SUCCEEDED_NOOP for signed-int32 representation", res.FinalStatus)
	}
}

// THE live-repro: already-installed exit + post-verify MISS under
// Session-0 (winget list can't enumerate). LATEST predicate → the install
// exit authority stands: SUCCEEDED_NOOP + INCONCLUSIVE, no FailedReasonCode.
func TestRunInstall_AlreadyInstalledExitPostMiss_NoopInconclusive(t *testing.T) {
	req := baseRequest()
	pre := PreDetectResult{Satisfied: false}
	post := PreDetectResult{Satisfied: false, DetectionMethod: DetectionMethodNoSourceFallback}
	callCounter := false
	probe := &stubProbe{pre: pre, post: post, postCall: &callCounter}
	runner := func(_ context.Context, _ string, _ []string) RunnerOutcome {
		return RunnerOutcome{ExitCode: 2316632161, DurationMs: 700}
	}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, runner, okEgress()))
	if res.FinalStatus != FinalStatusSucceededNoop {
		t.Fatalf("got %s want SUCCEEDED_NOOP (inconclusive post-verify must not downgrade already-installed)", res.FinalStatus)
	}
	if res.PostVerification.Status != PostVerifyStatusInconclusive {
		t.Fatalf("postVerification.status = %q want INCONCLUSIVE", res.PostVerification.Status)
	}
	if res.PostVerification.ReasonCode != "winget_list_session0_enumeration_unreliable" {
		t.Fatalf("postVerification.reasonCode = %q", res.PostVerification.ReasonCode)
	}
	if res.FailedReasonCode != "" {
		t.Fatalf("SUCCEEDED_NOOP must not carry a FailedReasonCode, got %q", res.FailedReasonCode)
	}
	if res.ExitCode != 2316632161 {
		t.Fatalf("winget exit code must be retained for audit, got %d", res.ExitCode)
	}
}

// Versioned predicate + inconclusive post-verify → cannot prove the
// required version → fail closed (strict v1).
func TestRunInstall_VersionedPredicateInconclusivePostVerify_Fails(t *testing.T) {
	req := baseRequest()
	req.VersionPredicate = VersionPredicate{Type: VersionPredicateMinimum, Spec: "25.0"}
	pre := PreDetectResult{Satisfied: false}
	post := PreDetectResult{Satisfied: false}
	callCounter := false
	probe := &stubProbe{pre: pre, post: post, postCall: &callCounter}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, happyRunner(), okEgress()))
	if res.FinalStatus != FinalStatusFailedVerification {
		t.Fatalf("got %s want FAILED_VERIFICATION (versioned predicate needs version proof)", res.FinalStatus)
	}
	if res.FailedReasonCode != "post_verify_inconclusive_version_required" {
		t.Fatalf("failedReasonCode = %q want post_verify_inconclusive_version_required", res.FailedReasonCode)
	}
}

// A POSITIVE post-verify that reports a CONFLICTING version is an
// authoritative contradiction → downgrade even though install exited 0.
func TestRunInstall_PostVerifyPositiveVersionMismatch_Fails(t *testing.T) {
	req := baseRequest()
	req.VersionPredicate = VersionPredicate{Type: VersionPredicateMinimum, Spec: "25.0"}
	pre := PreDetectResult{Satisfied: false}
	post := PreDetectResult{Satisfied: true, MatchedPackageID: "7zip.7zip", MatchedVersion: "24.07"}
	callCounter := false
	probe := &stubProbe{pre: pre, post: post, postCall: &callCounter}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, happyRunner(), okEgress()))
	if res.FinalStatus != FinalStatusFailedVerification {
		t.Fatalf("got %s want FAILED_VERIFICATION (positive version mismatch)", res.FinalStatus)
	}
	if res.FailedReasonCode != "post_verify_version_predicate_failed" {
		t.Fatalf("failedReasonCode = %q want post_verify_version_predicate_failed", res.FailedReasonCode)
	}
}

// A probe ERROR (not just a miss) must be best-effort: a pre-detect error
// proceeds to the idempotent install, and a post-verify error is
// INCONCLUSIVE (keeps the clean install exit for LATEST). Pins the postErr
// path Codex flagged.
func TestRunInstall_ProbeErrorBestEffortInconclusiveSucceeds(t *testing.T) {
	req := baseRequest()
	probe := &stubProbe{
		pre:      PreDetectResult{Satisfied: false},
		post:     PreDetectResult{Satisfied: false},
		postCall: new(bool),
		err:      errors.New("winget list timed out"),
	}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, happyRunner(), okEgress()))
	if res.FinalStatus != FinalStatusSucceeded {
		t.Fatalf("got %s want SUCCEEDED (probe errors must be best-effort, not fatal)", res.FinalStatus)
	}
	if res.PostVerification.Status != PostVerifyStatusInconclusive {
		t.Fatalf("postVerification.status = %q want INCONCLUSIVE", res.PostVerification.Status)
	}
	if res.FailedReasonCode != "" {
		t.Fatalf("SUCCEEDED must not carry a FailedReasonCode, got %q", res.FailedReasonCode)
	}
}

func TestVersionPredicateRequiresVersionProof(t *testing.T) {
	needs := []VersionPredicate{
		{Type: VersionPredicateExact, Spec: "1.0"},
		{Type: VersionPredicateMinimum, Spec: "1.0"},
		{Type: VersionPredicateRange, Spec: "[1.0,2.0)"},
	}
	for _, p := range needs {
		if !versionPredicateRequiresVersionProof(p) {
			t.Fatalf("%s should require version proof", p.Type)
		}
	}
	for _, p := range []VersionPredicate{{Type: VersionPredicateLatest}, {}} {
		if versionPredicateRequiresVersionProof(p) {
			t.Fatalf("%q should NOT require version proof", p.Type)
		}
	}
}
