package winget

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeArpReader struct {
	entries   []ArpEntry
	err       error // Enumerate error
	lookupErr error // Lookup error
}

func (f fakeArpReader) Enumerate(_ context.Context) ([]ArpEntry, error) {
	return f.entries, f.err
}

func (f fakeArpReader) Lookup(_ context.Context, keyName string) (ArpEntry, bool, error) {
	if f.lookupErr != nil {
		return ArpEntry{}, false, f.lookupErr
	}
	for _, e := range f.entries {
		if strings.EqualFold(strings.TrimSpace(e.KeyName), strings.TrimSpace(keyName)) {
			return e, true, nil
		}
	}
	return ArpEntry{}, false, nil
}

func sevenZipArp() []ArpEntry {
	return []ArpEntry{
		{KeyName: "{23170F69-40C1-2702-2601-000001000000}", DisplayName: "7-Zip 26.01 (x64)", DisplayVersion: "26.01", Publisher: "Igor Pavlov"},
		{KeyName: "Microsoft Edge", DisplayName: "Microsoft Edge", DisplayVersion: "148.0", Publisher: "Microsoft Corporation"},
	}
}

// ── matchString / globMatch ──────────────────────────────────────

func TestMatchString_Modes(t *testing.T) {
	cases := []struct {
		mode, pat, val string
		want           bool
	}{
		{MatchModeExact, "7-Zip", "7-zip", true}, // case-insensitive
		{MatchModeExact, "7-Zip", "7-Zip 26.01", false},
		{"", "7-Zip", "7-ZIP", true}, // empty mode → EXACT
		{MatchModePrefix, "7-Zip", "7-Zip 26.01 (x64)", true},
		{MatchModePrefix, "Zip", "7-Zip", false},
		{MatchModeContains, "zip", "7-Zip 26.01", true},
		{MatchModeContains, "vlc", "7-Zip", false},
		{MatchModeGlob, "7-Zip*", "7-Zip 26.01 (x64)", true},
		{MatchModeGlob, "7-Zip ??.??*", "7-Zip 26.01 (x64)", true},
		{MatchModeGlob, "*x64*", "7-Zip 26.01 (x64)", true},
		{MatchModeGlob, "8-Zip*", "7-Zip 26.01", false},
		{"BOGUS", "7-Zip", "7-Zip", false},      // unknown mode never matches
		{MatchModeExact, "", "anything", false}, // empty pattern never matches
	}
	for i, c := range cases {
		if got := matchString(c.mode, c.pat, c.val); got != c.want {
			t.Errorf("case %d matchString(%q,%q,%q)=%v want %v", i, c.mode, c.pat, c.val, got, c.want)
		}
	}
}

func TestGlobMatch_OnlyStarAndQuestion(t *testing.T) {
	if !globMatch("a*c", "abbbc") {
		t.Fatal("a*c should match abbbc")
	}
	if !globMatch("a?c", "abc") {
		t.Fatal("a?c should match abc")
	}
	if globMatch("a?c", "ac") {
		t.Fatal("a?c should NOT match ac (? requires one char)")
	}
	if !globMatch("*", "") {
		t.Fatal("* should match empty")
	}
	if !globMatch("**a", "xyza") {
		t.Fatal("consecutive * should collapse")
	}
}

// ── ProbeViaRegistry ─────────────────────────────────────────────

func TestProbeViaRegistry_ProductCodeMatch(t *testing.T) {
	rule := DetectionRule{Type: DetectionRuleTypeRegistryUninstall, ProductCode: "{23170F69-40C1-2702-2601-000001000000}"}
	res, err := ProbeViaRegistry(context.Background(), fakeArpReader{entries: sevenZipArp()}, rule)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Satisfied {
		t.Fatal("productCode should match")
	}
	if res.MatchedVersion != "26.01" {
		t.Fatalf("matchedVersion=%q", res.MatchedVersion)
	}
	if res.DetectionMethod != DetectionMethodRegistryUninstall {
		t.Fatalf("detectionMethod=%q", res.DetectionMethod)
	}
}

func TestProbeViaRegistry_DisplayNamePublisherFallback(t *testing.T) {
	rule := DetectionRule{
		Type: DetectionRuleTypeRegistryUninstall, DisplayName: "7-Zip*",
		DisplayNameMatch: MatchModeGlob, Publisher: "Igor Pavlov", PublisherMatch: MatchModeExact,
	}
	res, err := ProbeViaRegistry(context.Background(), fakeArpReader{entries: sevenZipArp()}, rule)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Satisfied || res.MatchedVersion != "26.01" {
		t.Fatalf("expected satisfied 26.01, got satisfied=%v ver=%q", res.Satisfied, res.MatchedVersion)
	}
}

func TestProbeViaRegistry_NoMatch(t *testing.T) {
	rule := DetectionRule{Type: DetectionRuleTypeRegistryUninstall, DisplayName: "VLC*", DisplayNameMatch: MatchModeGlob, Publisher: "VideoLAN"}
	res, err := ProbeViaRegistry(context.Background(), fakeArpReader{entries: sevenZipArp()}, rule)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Satisfied {
		t.Fatal("VLC should not match a 7-Zip/Edge inventory")
	}
}

func TestProbeViaRegistry_AmbiguousMultipleDistinct(t *testing.T) {
	entries := []ArpEntry{
		{KeyName: "k1", DisplayName: "Acme Tool", DisplayVersion: "1.0", Publisher: "Acme"},
		{KeyName: "k2", DisplayName: "Acme Tool Pro", DisplayVersion: "2.0", Publisher: "Acme"},
	}
	rule := DetectionRule{Type: DetectionRuleTypeRegistryUninstall, DisplayName: "Acme*", DisplayNameMatch: MatchModeGlob, Publisher: "Acme"}
	_, err := ProbeViaRegistry(context.Background(), fakeArpReader{entries: entries}, rule)
	if !errors.Is(err, ErrRegistryAmbiguous) {
		t.Fatalf("expected ErrRegistryAmbiguous, got %v", err)
	}
}

func TestProbeViaRegistry_DedupesIdentical3264(t *testing.T) {
	// Same product registered under both 32/64-bit views → one match.
	entries := []ArpEntry{
		{KeyName: "k64", DisplayName: "7-Zip 26.01 (x64)", DisplayVersion: "26.01", Publisher: "Igor Pavlov"},
		{KeyName: "k32", DisplayName: "7-Zip 26.01 (x64)", DisplayVersion: "26.01", Publisher: "Igor Pavlov"},
	}
	rule := DetectionRule{Type: DetectionRuleTypeRegistryUninstall, DisplayName: "7-Zip*", DisplayNameMatch: MatchModeGlob, Publisher: "Igor Pavlov"}
	res, err := ProbeViaRegistry(context.Background(), fakeArpReader{entries: entries}, rule)
	if err != nil {
		t.Fatalf("dedupe should avoid ambiguous, got err %v", err)
	}
	if !res.Satisfied {
		t.Fatal("deduped identical entries should satisfy")
	}
}

func TestProbeViaRegistry_EnumerateErrorPropagates(t *testing.T) {
	// A displayName rule uses Enumerate; a failed/truncated read must
	// propagate (an authoritative detector must not assume not-installed).
	rule := DetectionRule{Type: DetectionRuleTypeRegistryUninstall, DisplayName: "7-Zip", DisplayNameMatch: MatchModeExact, Publisher: "Igor Pavlov"}
	_, err := ProbeViaRegistry(context.Background(), fakeArpReader{err: ErrArpEnumTruncated}, rule)
	if err == nil {
		t.Fatal("enumerate error must propagate")
	}
}

func TestProbeViaRegistry_ProductCodeDirectLookup(t *testing.T) {
	pc := "{23170F69-40C1-2702-2601-000001000000}"
	rule := DetectionRule{Type: DetectionRuleTypeRegistryUninstall, ProductCode: pc}
	// found (direct lookup, cap-immune)
	res, err := ProbeViaRegistry(context.Background(), fakeArpReader{entries: sevenZipArp()}, rule)
	if err != nil || !res.Satisfied || res.MatchedVersion != "26.01" {
		t.Fatalf("productCode lookup: err=%v satisfied=%v ver=%q", err, res.Satisfied, res.MatchedVersion)
	}
	// absent → clean not-satisfied (no error)
	res, err = ProbeViaRegistry(context.Background(), fakeArpReader{entries: nil}, rule)
	if err != nil || res.Satisfied {
		t.Fatalf("absent productCode: err=%v satisfied=%v", err, res.Satisfied)
	}
	// lookup hard error → propagates (NOT a clean miss)
	_, err = ProbeViaRegistry(context.Background(), fakeArpReader{lookupErr: errors.New("registry lookup access denied")}, rule)
	if err == nil {
		t.Fatal("productCode lookup error must propagate")
	}
}

func TestIsMsiProductCode(t *testing.T) {
	good := []string{"{23170F69-40C1-2702-2601-000001000000}", "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"}
	for _, g := range good {
		if !isMsiProductCode(g) {
			t.Errorf("%q should be a valid MSI GUID", g)
		}
	}
	bad := []string{"{GUID}", "{x}", "23170F69-40C1-2702-2601-000001000000", "{23170F69-40C1-2702-2601-00000100000G}", `{..\..\Software}`, ""}
	for _, b := range bad {
		if isMsiProductCode(b) {
			t.Errorf("%q should NOT be a valid MSI GUID", b)
		}
	}
}

// ── validateDetectionRule ────────────────────────────────────────

func TestValidateDetectionRule(t *testing.T) {
	ok := []DetectionRule{
		{Type: DetectionRuleTypeWingetPackage, PackageID: "7zip.7zip"},
		{Type: DetectionRuleTypeRegistryUninstall, ProductCode: "{23170F69-40C1-2702-2601-000001000000}"},
		{Type: DetectionRuleTypeRegistryUninstall, DisplayName: "7-Zip", DisplayNameMatch: MatchModeExact, Publisher: "Igor Pavlov", PublisherMatch: MatchModeExact},
		{Type: DetectionRuleTypeRegistryUninstall, DisplayName: "7-Zip*", DisplayNameMatch: MatchModeGlob, Publisher: "Igor Pavlov", PublisherMatch: MatchModeContains},
		{Type: DetectionRuleTypeRegistryUninstall, DisplayName: "7-Zip", DisplayNameMatch: MatchModeExact, AllowPublisherMissing: true},
	}
	for i, r := range ok {
		if err := validateDetectionRule(r); err != nil {
			t.Errorf("ok[%d] unexpectedly rejected: %v", i, err)
		}
	}
	bad := []DetectionRule{
		{Type: DetectionRuleTypeWingetPackage},     // no packageId
		{Type: DetectionRuleTypeFileExists}, // FILE_EXISTS needs Path (Path C1)
		{Type: DetectionRuleTypeRegistryUninstall}, // no productCode/displayName
		{Type: DetectionRuleTypeRegistryUninstall, DisplayName: "7-Zip", DisplayNameMatch: MatchModeExact},                                         // fallback needs publisher
		{Type: DetectionRuleTypeRegistryUninstall, DisplayName: "7-Zip*", DisplayNameMatch: MatchModeGlob, AllowPublisherMissing: true},            // allowPublisherMissing needs EXACT
		{Type: DetectionRuleTypeRegistryUninstall, DisplayName: "7-Zip", DisplayNameMatch: "REGEX", Publisher: "x"},                                // bad mode
		{Type: DetectionRuleTypeRegistryUninstall, DisplayName: "7-[Zz]ip", DisplayNameMatch: MatchModeGlob, Publisher: "x"},                       // glob with []
		{Type: DetectionRuleTypeRegistryUninstall, DisplayName: "7-Zip", DisplayNameMatch: MatchModeExact, Publisher: "x", PublisherMatch: "GLOB"}, // publisher GLOB not allowed
		{Type: DetectionRuleTypeRegistryUninstall, ProductCode: "{GUID}"},                                                                          // not a real MSI GUID shape
		{Type: DetectionRuleTypeRegistryUninstall, ProductCode: `{..\..\SOFTWARE}`},                                                                // path-injection attempt rejected
	}
	for i, r := range bad {
		if err := validateDetectionRule(r); err == nil {
			t.Errorf("bad[%d] unexpectedly accepted: %+v", i, r)
		}
	}
}

// ── RunInstall authority paths (REGISTRY_UNINSTALL = AUTHORITATIVE) ──

func registryRequest() InstallRequest {
	r := baseRequest()
	r.DetectionRule = DetectionRule{
		Type: DetectionRuleTypeRegistryUninstall, DisplayName: "7-Zip*",
		DisplayNameMatch: MatchModeGlob, Publisher: "Igor Pavlov",
	}
	return r
}

func TestRunInstall_RegistryPreDetect_NoopAuthoritative(t *testing.T) {
	probe := &stubProbe{pre: PreDetectResult{Satisfied: true, MatchedPackageID: "{GUID}", MatchedVersion: "26.01", DetectionMethod: DetectionMethodRegistryUninstall}}
	res := RunInstall(context.Background(), registryRequest(), baseOptions(probe.probe, happyRunner(), okEgress()))
	if res.FinalStatus != FinalStatusSucceededNoop {
		t.Fatalf("got %s want SUCCEEDED_NOOP", res.FinalStatus)
	}
	if res.PostVerification.Authority != DetectionReliabilityAuthoritative {
		t.Fatalf("authority=%q want AUTHORITATIVE", res.PostVerification.Authority)
	}
}

func TestRunInstall_RegistryFreshInstall_Succeeds(t *testing.T) {
	cc := false
	probe := &stubProbe{
		pre:      PreDetectResult{Satisfied: false},
		post:     PreDetectResult{Satisfied: true, MatchedPackageID: "{GUID}", MatchedVersion: "26.01", DetectionMethod: DetectionMethodRegistryUninstall},
		postCall: &cc,
	}
	res := RunInstall(context.Background(), registryRequest(), baseOptions(probe.probe, happyRunner(), okEgress()))
	if res.FinalStatus != FinalStatusSucceeded {
		t.Fatalf("got %s want SUCCEEDED", res.FinalStatus)
	}
	if res.PostVerification.Status != PostVerifyStatusSatisfied || res.PostVerification.Authority != DetectionReliabilityAuthoritative {
		t.Fatalf("status=%q authority=%q", res.PostVerification.Status, res.PostVerification.Authority)
	}
}

// THE authority contrast: a registry (AUTHORITATIVE) post-verify miss IS a
// denial → FAILED_VERIFICATION, where a WINGET_PACKAGE miss would be
// INCONCLUSIVE-and-success (§11.3b).
func TestRunInstall_RegistryPostVerifyMiss_FailsVerification(t *testing.T) {
	cc := false
	probe := &stubProbe{pre: PreDetectResult{Satisfied: false}, post: PreDetectResult{Satisfied: false}, postCall: &cc}
	res := RunInstall(context.Background(), registryRequest(), baseOptions(probe.probe, happyRunner(), okEgress()))
	if res.FinalStatus != FinalStatusFailedVerification {
		t.Fatalf("got %s want FAILED_VERIFICATION (authoritative registry miss is a denial)", res.FinalStatus)
	}
	if res.FailedReasonCode != "post_verify_not_satisfied" {
		t.Fatalf("reason=%q", res.FailedReasonCode)
	}
	if res.PostVerification.Status != PostVerifyStatusNotSatisfied || res.PostVerification.Authority != DetectionReliabilityAuthoritative {
		t.Fatalf("status=%q authority=%q", res.PostVerification.Status, res.PostVerification.Authority)
	}
}

// An AUTHORITATIVE pre-detect probe error fails closed BEFORE mutation —
// the install must NOT run (the post-verify would use the same broken
// detector).
func TestRunInstall_RegistryPreDetectError_FailsClosedNoInstall(t *testing.T) {
	installed := false
	runner := func(_ context.Context, _ string, _ []string) RunnerOutcome {
		installed = true
		return RunnerOutcome{ExitCode: 0}
	}
	probe := &stubProbe{pre: PreDetectResult{Satisfied: false}, err: errors.New("registry open denied")}
	res := RunInstall(context.Background(), registryRequest(), baseOptions(probe.probe, runner, okEgress()))
	if res.FinalStatus != FinalStatusFailedVerification {
		t.Fatalf("got %s want FAILED_VERIFICATION (authoritative pre-detect error fails closed)", res.FinalStatus)
	}
	if res.FailedReasonCode != "pre_detect_probe_error" {
		t.Fatalf("reason=%q", res.FailedReasonCode)
	}
	if installed {
		t.Fatal("install must NOT run when an authoritative pre-detect probe errors")
	}
}

// A WINGET_PACKAGE post-verify miss stays INCONCLUSIVE+SUCCEEDED — proving
// the reliability split (contrast with the registry test above).
func TestRunInstall_WingetPostVerifyMiss_StaysInconclusiveSuccess(t *testing.T) {
	cc := false
	probe := &stubProbe{pre: PreDetectResult{Satisfied: false}, post: PreDetectResult{Satisfied: false}, postCall: &cc}
	res := RunInstall(context.Background(), baseRequest(), baseOptions(probe.probe, happyRunner(), okEgress()))
	if res.FinalStatus != FinalStatusSucceeded {
		t.Fatalf("got %s want SUCCEEDED (winget miss is CONFIRM_ONLY/INCONCLUSIVE)", res.FinalStatus)
	}
	if res.PostVerification.Authority != DetectionReliabilityConfirmOnly || res.PostVerification.Status != PostVerifyStatusInconclusive {
		t.Fatalf("authority=%q status=%q", res.PostVerification.Authority, res.PostVerification.Status)
	}
}
