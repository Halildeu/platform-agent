package winget

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────
// Args preset table

func TestArgsForPreset_DefaultRendersPackageID(t *testing.T) {
	args, err := ArgsForPreset(ArgsPresetDefault, "7zip.7zip")
	if err != nil {
		t.Fatalf("ArgsForPreset(DEFAULT, 7zip.7zip) returned error: %v", err)
	}
	want := []string{
		"install",
		"--id", "7zip.7zip",
		"--exact",
		"--source", "winget",
		"--silent",
		"--accept-package-agreements",
		"--accept-source-agreements",
		"--disable-interactivity",
		"--no-upgrade",
	}
	if len(args) != len(want) {
		t.Fatalf("unexpected arg slice length: got %d want %d (%v)", len(args), len(want), args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("arg[%d] mismatch: got %q want %q", i, args[i], want[i])
		}
	}
}

func TestArgsForPreset_UnknownPresetRejected(t *testing.T) {
	if _, err := ArgsForPreset("RAW_SHELL_INJECTION", "7zip.7zip"); err == nil {
		t.Fatal("expected error for unknown preset, got nil")
	}
}

func TestArgsForPreset_EmptyPackageIDRejected(t *testing.T) {
	if _, err := ArgsForPreset(ArgsPresetDefault, ""); err == nil {
		t.Fatal("expected error for empty packageID, got nil")
	}
}

func TestIsKnownArgsPresetCoversBothPresets(t *testing.T) {
	if !IsKnownArgsPreset(ArgsPresetDefault) {
		t.Fatal("DEFAULT preset should be known")
	}
	if !IsKnownArgsPreset(ArgsPresetVendorRecommendedWingetNoUpgrade) {
		t.Fatal("VENDOR_RECOMMENDED_WINGET_NO_UPGRADE should be known")
	}
	if IsKnownArgsPreset("nope") {
		t.Fatal("unknown preset should NOT be reported known")
	}
}

// ────────────────────────────────────────────────────────────────
// Version predicate / range / compareVersions

func TestVersionPredicateSatisfied_LatestAlwaysTrue(t *testing.T) {
	if !versionPredicateSatisfied(VersionPredicate{Type: VersionPredicateLatest}, "", "") {
		t.Fatal("LATEST should always satisfy without installed version")
	}
	if !versionPredicateSatisfied(VersionPredicate{Type: VersionPredicateLatest}, "", "24.07") {
		t.Fatal("LATEST should always satisfy with installed version")
	}
}

func TestVersionPredicateSatisfied_ExactMatch(t *testing.T) {
	pred := VersionPredicate{Type: VersionPredicateExact, Spec: "24.07"}
	if !versionPredicateSatisfied(pred, "", "24.07") {
		t.Fatal("EXACT 24.07 should match installed 24.07")
	}
	if versionPredicateSatisfied(pred, "", "23.05") {
		t.Fatal("EXACT 24.07 should NOT match installed 23.05")
	}
}

func TestVersionPredicateSatisfied_MinimumOK(t *testing.T) {
	pred := VersionPredicate{Type: VersionPredicateMinimum, Spec: "24.0"}
	if !versionPredicateSatisfied(pred, "", "24.07") {
		t.Fatal("MINIMUM 24.0 should accept installed 24.07")
	}
	if versionPredicateSatisfied(pred, "", "23.99") {
		t.Fatal("MINIMUM 24.0 should reject installed 23.99")
	}
}

func TestVersionPredicateSatisfied_RangeInclusiveAndExclusive(t *testing.T) {
	pred := VersionPredicate{Type: VersionPredicateRange, Spec: "[24.0,25.0)"}
	if !versionPredicateSatisfied(pred, "", "24.0") {
		t.Fatal("[24.0,25.0) should include lower bound")
	}
	if !versionPredicateSatisfied(pred, "", "24.7") {
		t.Fatal("[24.0,25.0) should include 24.7")
	}
	if versionPredicateSatisfied(pred, "", "25.0") {
		t.Fatal("[24.0,25.0) should exclude upper bound")
	}
	if versionPredicateSatisfied(pred, "", "23.0") {
		t.Fatal("[24.0,25.0) should reject below lower bound")
	}
}

func TestVersionPredicateSatisfied_EmptyInstalledFails(t *testing.T) {
	pred := VersionPredicate{Type: VersionPredicateMinimum, Spec: "24.0"}
	if versionPredicateSatisfied(pred, "", "") {
		t.Fatal("empty installed version should not satisfy")
	}
}

func TestVersionPredicateSatisfied_ResolvedVersionOverridesSpec(t *testing.T) {
	pred := VersionPredicate{Type: VersionPredicateExact, Spec: "24.0"}
	if !versionPredicateSatisfied(pred, "24.07", "24.07") {
		t.Fatal("resolvedVersion=24.07 should override spec=24.0")
	}
}

// ────────────────────────────────────────────────────────────────
// CaptureTail / sanitizeForWire helpers

func TestCaptureTail_Below(t *testing.T) {
	tail, truncated, total := CaptureTail([]byte("short"), 100)
	if tail != "short" || truncated || total != 5 {
		t.Fatalf("unexpected: tail=%q truncated=%v total=%d", tail, truncated, total)
	}
}

func TestCaptureTail_Above(t *testing.T) {
	body := make([]byte, 5000)
	for i := range body {
		body[i] = 'X'
	}
	tail, truncated, total := CaptureTail(body, 1024)
	if !truncated {
		t.Fatal("expected truncated=true")
	}
	if total != 5000 {
		t.Fatalf("totalBytes=%d", total)
	}
	if len(tail) != 1024 {
		t.Fatalf("tail length=%d", len(tail))
	}
}

func TestSanitizeForWire_StripsCarriageReturns(t *testing.T) {
	in := "hello\rworld\r\n"
	got := sanitizeForWire(in)
	if strings.Contains(got, "\r") {
		t.Fatalf("expected no \\r in sanitised output: %q", got)
	}
}

// AG-027L Codex 019e73de iter-1 should_fix: integration assertion
// that the install pipeline wires runner stdout/stderr through
// sanitizeForWire (which now layers RedactInstallerString on top of
// the baseline). The runner returns crafted output containing every
// AG-027L pattern class; the test asserts the InstallResult tails
// have the credentials masked but keep the structural anchors.
func TestRunInstall_RedactsInstallerCredentialsFromRunnerOutput(t *testing.T) {
	postCallSeen := false
	probe := &stubProbe{
		pre:      PreDetectResult{Satisfied: false},
		post:     PreDetectResult{Satisfied: true, MatchedPackageID: "7zip.7zip", MatchedVersion: "24.07"},
		postCall: &postCallSeen,
	}

	req := baseRequest()

	dirty := strings.Join([]string{
		"Downloading https://operator:s3cret@vendor.example.com/installer.msi",
		"Applying LICENSEKEY=KEY-AAAA-BBBB-CCCC",
		"Token URL https://cdn.example.com/cb?client_secret=oauth-private-bytes",
	}, "\n")

	runner := func(_ context.Context, _ string, _ []string) RunnerOutcome {
		return RunnerOutcome{
			ExitCode:         0,
			DurationMs:       100,
			StdoutTail:       dirty,
			StdoutTotalBytes: len(dirty),
			StderrTail:       dirty,
			StderrTotalBytes: len(dirty),
		}
	}

	opts := InstallOptions{
		Locator: func() (string, error) { return "winget", nil },
		EgressVerify: func(context.Context) SourceEgressReadiness {
			return SourceEgressReadiness{
				Supported:    true,
				PackageQuery: PackageQueryResult{Found: true},
			}
		},
		DetectionProbe: probe.probe,
		InstallRunner:  runner,
		Now:            time.Now,
	}

	result := RunInstall(context.Background(), req, opts)

	for _, secret := range []string{
		"operator:s3cret",
		"KEY-AAAA-BBBB-CCCC",
		"oauth-private-bytes",
	} {
		if strings.Contains(result.StdoutTail, secret) {
			t.Errorf("expected %q masked in StdoutTail, got %q",
				secret, result.StdoutTail)
		}
		if strings.Contains(result.StderrTail, secret) {
			t.Errorf("expected %q masked in StderrTail, got %q",
				secret, result.StderrTail)
		}
	}

	for _, keep := range []string{
		"[REDACTED]",
		"vendor.example.com",
		"LICENSEKEY=",
		"client_secret=",
	} {
		if !strings.Contains(result.StdoutTail, keep) {
			t.Errorf("expected non-credential marker %q to survive in StdoutTail, got %q",
				keep, result.StdoutTail)
		}
	}
}

// ────────────────────────────────────────────────────────────────
// Decision pipeline — table-driven

type stubProbe struct {
	pre      PreDetectResult
	post     PreDetectResult
	postCall *bool
	err      error
}

func (s *stubProbe) probe(_ context.Context, _ DetectionRule, _ string) (PreDetectResult, error) {
	if s.postCall != nil && *s.postCall {
		return s.post, s.err
	}
	if s.postCall != nil {
		*s.postCall = true
	}
	return s.pre, s.err
}

func baseRequest() InstallRequest {
	return InstallRequest{
		CommandResultID:   "00000000-0000-0000-0000-000000000001",
		IdempotencyKey:    "00000000-0000-0000-0000-000000000002",
		CatalogItemID:     "00000000-0000-0000-0000-000000000003",
		CatalogItemKey:    "7zip.7zip",
		CatalogRowVersion: 1,
		Provider:          "WINGET",
		PackageID:         "7zip.7zip",
		ArgsPolicyPreset:  ArgsPresetDefault,
		VersionPredicate:  VersionPredicate{Type: VersionPredicateLatest},
		DetectionRule:     DetectionRule{Type: DetectionRuleTypeWingetPackage, PackageID: "7zip.7zip"},
	}
}

func okEgress() SourceEgressReadiness {
	return SourceEgressReadiness{
		Supported:     true,
		SchemaVersion: SourceEgressSchemaVersion,
		PackageQuery:  PackageQueryResult{PackageID: FixedPackageQueryID, Found: true},
	}
}

func mockLocator() Locator {
	return func() (string, error) { return "/usr/local/bin/winget", nil }
}

func baseOptions(probe DetectionProbeFn, runner InstallRunnerFn, egress SourceEgressReadiness) InstallOptions {
	now := time.Unix(1700000000, 0).UTC()
	return InstallOptions{
		Locator:        mockLocator(),
		EgressVerify:   func(_ context.Context) SourceEgressReadiness { return egress },
		DetectionProbe: probe,
		InstallRunner:  runner,
		Now:            func() time.Time { return now },
		Timeout:        time.Minute,
	}
}

func happyRunner() InstallRunnerFn {
	return func(_ context.Context, _ string, _ []string) RunnerOutcome {
		return RunnerOutcome{
			ExitCode:         0,
			DurationMs:       1000,
			KillStrategy:     "",
			TimedOut:         false,
			StdoutTail:       "Successfully installed",
			StdoutTotalBytes: 22,
		}
	}
}

func TestRunInstall_UnsupportedDetectionRuleFailsClosed(t *testing.T) {
	req := baseRequest()
	req.DetectionRule.Type = "REGISTRY_UNINSTALL"
	res := RunInstall(context.Background(), req, baseOptions(nil, nil, okEgress()))
	if res.FinalStatus != FinalStatusFailedUnsupportedDetectionRule {
		t.Fatalf("got %s want FAILED_UNSUPPORTED_DETECTION_RULE", res.FinalStatus)
	}
	if res.FailedReasonCode == "" {
		t.Fatal("failedReasonCode must be set")
	}
}

func TestRunInstall_UnsupportedArgsPolicyFailsClosed(t *testing.T) {
	req := baseRequest()
	req.ArgsPolicyPreset = "EVIL_PRESET"
	res := RunInstall(context.Background(), req, baseOptions(nil, nil, okEgress()))
	if res.FinalStatus != FinalStatusFailedUnsupportedArgsPolicy {
		t.Fatalf("got %s", res.FinalStatus)
	}
}

func TestRunInstall_EgressNotReady(t *testing.T) {
	req := baseRequest()
	badEgress := SourceEgressReadiness{Supported: true, ProbeError: "dns failed"}
	opts := baseOptions(nil, nil, badEgress)
	res := RunInstall(context.Background(), req, opts)
	if res.FinalStatus != FinalStatusFailedEgress {
		t.Fatalf("got %s want FAILED_EGRESS", res.FinalStatus)
	}
}

func TestRunInstall_PreDetectAlreadyInstalled_SatisfiesNoop(t *testing.T) {
	req := baseRequest()
	probe := &stubProbe{
		pre: PreDetectResult{Satisfied: true, MatchedPackageID: "7zip.7zip", MatchedVersion: "24.07"},
	}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, happyRunner(), okEgress()))
	if res.FinalStatus != FinalStatusSucceededNoop {
		t.Fatalf("got %s want SUCCEEDED_NOOP", res.FinalStatus)
	}
	if !res.PostVerification.Satisfied {
		t.Fatal("noop result should carry verification satisfied")
	}
}

func TestRunInstall_PreDetectVersionConflict(t *testing.T) {
	req := baseRequest()
	req.VersionPredicate = VersionPredicate{Type: VersionPredicateMinimum, Spec: "25.0"}
	probe := &stubProbe{
		pre: PreDetectResult{Satisfied: true, MatchedPackageID: "7zip.7zip", MatchedVersion: "24.07"},
	}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, happyRunner(), okEgress()))
	if res.FinalStatus != FinalStatusFailedPreexistingVersionConflict {
		t.Fatalf("got %s want FAILED_PREEXISTING_VERSION_CONFLICT", res.FinalStatus)
	}
}

func TestRunInstall_HappyPathSucceeds(t *testing.T) {
	req := baseRequest()
	pre := PreDetectResult{Satisfied: false}
	post := PreDetectResult{Satisfied: true, MatchedPackageID: "7zip.7zip", MatchedVersion: "24.07"}
	callCounter := false
	probe := &stubProbe{pre: pre, post: post, postCall: &callCounter}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, happyRunner(), okEgress()))
	if res.FinalStatus != FinalStatusSucceeded {
		t.Fatalf("got %s want SUCCEEDED", res.FinalStatus)
	}
	if !res.PostVerification.Satisfied {
		t.Fatal("happy path must surface postVerification.satisfied=true")
	}
	if res.PostVerification.MatchedVersion != "24.07" {
		t.Fatalf("postVerification version = %q", res.PostVerification.MatchedVersion)
	}
}

func TestRunInstall_RebootRequiredViaExitCode(t *testing.T) {
	req := baseRequest()
	pre := PreDetectResult{Satisfied: false}
	post := PreDetectResult{Satisfied: true, MatchedPackageID: "7zip.7zip", MatchedVersion: "24.07"}
	callCounter := false
	probe := &stubProbe{pre: pre, post: post, postCall: &callCounter}
	runner := func(_ context.Context, _ string, _ []string) RunnerOutcome {
		return RunnerOutcome{ExitCode: 3010, DurationMs: 500}
	}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, runner, okEgress()))
	if res.FinalStatus != FinalStatusSucceededRebootRequired {
		t.Fatalf("got %s want SUCCEEDED_REBOOT_REQUIRED", res.FinalStatus)
	}
	if !res.RebootRequired {
		t.Fatal("rebootRequired flag must be true")
	}
}

func TestRunInstall_InstallFailureExitCode(t *testing.T) {
	req := baseRequest()
	probe := &stubProbe{pre: PreDetectResult{Satisfied: false}}
	runner := func(_ context.Context, _ string, _ []string) RunnerOutcome {
		return RunnerOutcome{ExitCode: 1, DurationMs: 500, StderrTail: "MSI failure"}
	}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, runner, okEgress()))
	if res.FinalStatus != FinalStatusFailedInstall {
		t.Fatalf("got %s want FAILED_INSTALL", res.FinalStatus)
	}
	if !strings.Contains(res.FailedReasonCode, "winget_exit_1") {
		t.Fatalf("failedReasonCode = %q", res.FailedReasonCode)
	}
}

func TestRunInstall_PostVerifyMissingFailsVerification(t *testing.T) {
	req := baseRequest()
	pre := PreDetectResult{Satisfied: false}
	post := PreDetectResult{Satisfied: false}
	callCounter := false
	probe := &stubProbe{pre: pre, post: post, postCall: &callCounter}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, happyRunner(), okEgress()))
	if res.FinalStatus != FinalStatusFailedVerification {
		t.Fatalf("got %s want FAILED_VERIFICATION", res.FinalStatus)
	}
	if res.FailedReasonCode != "post_verify_not_satisfied" {
		t.Fatalf("failedReasonCode=%q", res.FailedReasonCode)
	}
}

func TestRunInstall_TimeoutSurface(t *testing.T) {
	req := baseRequest()
	probe := &stubProbe{pre: PreDetectResult{Satisfied: false}}
	runner := func(_ context.Context, _ string, _ []string) RunnerOutcome {
		return RunnerOutcome{
			ExitCode:     -1,
			DurationMs:   30000,
			TimedOut:     true,
			KillStrategy: "taskkill_tree",
		}
	}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, runner, okEgress()))
	if res.FinalStatus != FinalStatusFailedTimeout {
		t.Fatalf("got %s want FAILED_TIMEOUT", res.FinalStatus)
	}
	if res.KillStrategy != "taskkill_tree" {
		t.Fatalf("killStrategy = %q", res.KillStrategy)
	}
}

func TestRunInstall_LocatorMissingReportsUnsupportedPlatform(t *testing.T) {
	req := baseRequest()
	opts := baseOptions(nil, nil, okEgress())
	opts.Locator = func() (string, error) { return "", errors.New("not on PATH") }
	res := RunInstall(context.Background(), req, opts)
	if res.FinalStatus != FinalStatusFailedUnsupportedPlatform {
		t.Fatalf("got %s want FAILED_UNSUPPORTED_PLATFORM", res.FinalStatus)
	}
}

func TestRunInstall_PostVerifyVersionPredicateFailsVerification(t *testing.T) {
	req := baseRequest()
	req.VersionPredicate = VersionPredicate{Type: VersionPredicateMinimum, Spec: "25.0"}
	pre := PreDetectResult{Satisfied: false}
	// Installer reported success, but the post-install detection
	// returned 24.07 which violates the MINIMUM 25.0 predicate.
	post := PreDetectResult{Satisfied: true, MatchedPackageID: "7zip.7zip", MatchedVersion: "24.07"}
	callCounter := false
	probe := &stubProbe{pre: pre, post: post, postCall: &callCounter}
	res := RunInstall(context.Background(), req, baseOptions(probe.probe, happyRunner(), okEgress()))
	if res.FinalStatus != FinalStatusFailedVerification {
		t.Fatalf("got %s want FAILED_VERIFICATION", res.FinalStatus)
	}
	if res.FailedReasonCode != "post_verify_version_predicate_failed" {
		t.Fatalf("failedReasonCode=%q", res.FailedReasonCode)
	}
}

// ────────────────────────────────────────────────────────────────
// parseDetectionListOutput

func TestParseDetectionListOutput_MatchExtractsIDAndVersion(t *testing.T) {
	raw := `Name       Id         Version  Available  Source
-------    --------   -------  ---------  --------
7-Zip      7zip.7zip  24.07    24.10      winget
`
	id, ver, ok := parseDetectionListOutput(raw, "7zip.7zip")
	if !ok {
		t.Fatal("expected match")
	}
	if id != "7zip.7zip" {
		t.Fatalf("matched id = %q", id)
	}
	if ver != "24.07" {
		t.Fatalf("matched version = %q", ver)
	}
}

func TestParseDetectionListOutput_NoMatch(t *testing.T) {
	raw := `Name       Id         Version
-------    --------   -------
Notepad++  Notepadpp  8.6.5
`
	_, _, ok := parseDetectionListOutput(raw, "7zip.7zip")
	if ok {
		t.Fatal("expected no match")
	}
}
