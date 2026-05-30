package inventory

import (
	"context"
	"encoding/json"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestOutdatedSoftwareSchemaVersion(t *testing.T) {
	if OutdatedSoftwareSchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d; want 1", OutdatedSoftwareSchemaVersion)
	}
}

func TestMaxOutdatedPackages(t *testing.T) {
	if MaxOutdatedPackages != 512 {
		t.Errorf("MaxOutdatedPackages = %d; want 512", MaxOutdatedPackages)
	}
}

func TestLooksLikeVersion(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1.0.0", true},
		{"v1.0.0", true},
		{"24.09", true},
		{"1.91.0-preview", true},
		{"x1.0", false},
		{"", false},
	}
	for _, c := range cases {
		got := looksLikeVersion(c.in)
		if got != c.want {
			t.Errorf("looksLikeVersion(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

func TestIsNoUpgradeOutput(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"No applicable upgrade packages found.", true},
		{"No updates found.", true},
		{"NO APPLICABLE UPGRADE", true},
		{"7-Zip  7zip.7zip  24.09  25.01", false},
		{"", false},
	}
	for _, c := range cases {
		got := isNoUpgradeOutput(c.in)
		if got != c.want {
			t.Errorf("isNoUpgradeOutput(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

func TestProbeOutdatedSoftwareUnsupported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows stub behavior; Windows uses the live runner")
	}
	result := ProbeOutdatedSoftware(nil, time.Now)
	if result.Supported {
		t.Error("Supported should be false on non-Windows")
	}
	if result.SourceUsed != OutdatedSoftwareSourceNone {
		t.Errorf("SourceUsed = %v; want none", result.SourceUsed)
	}
	if len(result.ProbeErrors) == 0 {
		t.Error("Should have probe error on non-Windows")
	}
}

func TestDeriveUpgradeNeverNil(t *testing.T) {
	result := &OutdatedSoftwareResult{}
	deriveOutdatedSoftwareSummary(result)
	if result.Upgrade == nil {
		t.Error("Upgrade should not be nil after derive")
	}
	if result.MaxUpgrade != MaxOutdatedPackages {
		t.Errorf("MaxUpgrade = %d; want %d", result.MaxUpgrade, MaxOutdatedPackages)
	}
}

func TestIsNotFoundErr(t *testing.T) {
	if isNotFoundErr(nil) {
		t.Error("isNotFoundErr(nil) should be false")
	}
}

func TestProbeOutdatedSoftwareNilCtx(t *testing.T) {
	result := ProbeOutdatedSoftware(nil, time.Now)
	if result.SchemaVersion == 0 {
		t.Errorf("SchemaVersion = %d; should be 1", result.SchemaVersion)
	}
}

// ────────────────────────────────────────────────────────────────
// P1 #1 — JSON-keys redaction boundary (machine-enforced).
//
// Pins the per-package wire shape to EXACTLY {packageId,
// installedVersion, availableVersion}: asserts presence of the three
// allowed version/id keys AND absence of the excluded PII keys (name,
// publisher, install location, license, download URL). A future struct
// change that widens the PII surface fails here instead of silently
// leaking.

func jsonKeys(t *testing.T, v interface{}) []string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestOutdatedSoftwarePackage_JSONKeys(t *testing.T) {
	pkg := OutdatedSoftwarePackage{
		PackageID:        "7zip.7zip",
		InstalledVersion: "24.09",
		AvailableVersion: "25.01",
	}
	got := jsonKeys(t, pkg)
	want := []string{"availableVersion", "installedVersion", "packageId"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("package-level JSON keys = %v; want EXACTLY %v", got, want)
	}

	// Explicit absence guard for the excluded PII surface (belt &
	// suspenders over the exact-set check above).
	raw, _ := json.Marshal(pkg)
	s := string(raw)
	forbidden := []string{
		`"name"`, `"displayName"`, `"publisher"`,
		`"installLocation"`, `"installPath"`, `"location"`,
		`"license"`, `"licenseUrl"`,
		`"downloadUrl"`, `"installerUrl"`, `"url"`,
	}
	for _, frag := range forbidden {
		if strings.Contains(s, frag) {
			t.Errorf("forbidden PII key %q leaked to package JSON: %s", frag, s)
		}
	}
}

// TestSnapshotOutdatedSoftware_PackageJSONKeys marshals a full
// Snapshot.OutdatedSoftware and re-asserts the per-package key set on
// the nested upgrade[] entries — pinning the boundary at the real wire
// shape consumers see, not just the bare struct.
func TestSnapshotOutdatedSoftware_PackageJSONKeys(t *testing.T) {
	res := OutdatedSoftwareResult{
		SchemaVersion: OutdatedSoftwareSchemaVersion,
		Supported:     true,
		SourceUsed:    OutdatedSoftwareSourceWinGet,
		Upgrade: []OutdatedSoftwarePackage{
			{PackageID: "7zip.7zip", InstalledVersion: "24.09", AvailableVersion: "25.01"},
		},
	}
	deriveOutdatedSoftwareSummary(&res)
	snap := Snapshot{OutdatedSoftware: &res}

	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot failed: %v", err)
	}
	var decoded struct {
		OutdatedSoftware struct {
			Upgrade []map[string]json.RawMessage `json:"upgrade"`
		} `json:"outdatedSoftware"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal snapshot failed: %v", err)
	}
	if len(decoded.OutdatedSoftware.Upgrade) != 1 {
		t.Fatalf("expected 1 upgrade entry, got %d", len(decoded.OutdatedSoftware.Upgrade))
	}
	entry := decoded.OutdatedSoftware.Upgrade[0]
	keys := make([]string, 0, len(entry))
	for k := range entry {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"availableVersion", "installedVersion", "packageId"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("nested upgrade[] JSON keys = %v; want EXACTLY %v", keys, want)
	}
}

// ────────────────────────────────────────────────────────────────
// Hardening — upgrade always serializes as [] (never null).

func TestOutdatedSoftwareResult_UpgradeEmptyArrayNotNull(t *testing.T) {
	res := OutdatedSoftwareResult{
		SchemaVersion: OutdatedSoftwareSchemaVersion,
		Supported:     true,
		SourceUsed:    OutdatedSoftwareSourceWinGet,
	}
	deriveOutdatedSoftwareSummary(&res)
	raw, _ := json.Marshal(res)
	s := string(raw)
	if !strings.Contains(s, `"upgrade":[]`) {
		t.Fatalf(`expected "upgrade":[] in output, got %s`, s)
	}
	if strings.Contains(s, `"upgrade":null`) {
		t.Fatalf(`upgrade MUST NOT serialize as null, got %s`, s)
	}
}

// ────────────────────────────────────────────────────────────────
// Hardening — non-Windows stub normalized shape (mirrors AG-033).

func TestProbeOutdatedSoftware_NonWindowsStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses the live runner")
	}
	t0 := time.Unix(1700000000, 0)
	calls := 0
	clock := func() time.Time {
		calls++
		return t0.Add(time.Duration(calls-1) * 2 * time.Millisecond)
	}
	got := ProbeOutdatedSoftware(context.Background(), clock)
	if got.Supported {
		t.Fatalf("expected Supported=false on %s", runtime.GOOS)
	}
	if got.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false on stub")
	}
	if got.SchemaVersion != OutdatedSoftwareSchemaVersion {
		t.Fatalf("schemaVersion = %d, want %d", got.SchemaVersion, OutdatedSoftwareSchemaVersion)
	}
	if got.SourceUsed != OutdatedSoftwareSourceNone {
		t.Fatalf("expected SourceUsed=none, got %q", got.SourceUsed)
	}
	if got.Upgrade == nil || len(got.Upgrade) != 0 {
		t.Fatalf("expected empty non-nil Upgrade, got %#v", got.Upgrade)
	}
	if got.MaxUpgrade != MaxOutdatedPackages {
		t.Fatalf("expected MaxUpgrade=%d, got %d", MaxOutdatedPackages, got.MaxUpgrade)
	}
	if len(got.ProbeErrors) != 1 || got.ProbeErrors[0].Code != OutdatedSoftwareErrUnsupportedPlatform {
		t.Fatalf("expected single UNSUPPORTED_PLATFORM error, got %#v", got.ProbeErrors)
	}
	if got.ProbeErrors[0].Source != OutdatedSoftwareSourceNone {
		t.Fatalf("expected probe error source=none, got %q", got.ProbeErrors[0].Source)
	}
	if !strings.Contains(got.ProbeErrors[0].Summary, runtime.GOOS) {
		t.Fatalf("expected summary to mention runtime %q, got %q", runtime.GOOS, got.ProbeErrors[0].Summary)
	}
	if got.ProbeDurationMs <= 0 {
		t.Fatalf("expected ProbeDurationMs > 0, got %d", got.ProbeDurationMs)
	}
}

// ────────────────────────────────────────────────────────────────
// Hardening — error-code taxonomy stability.

func TestOutdatedSoftwareErrorCodes(t *testing.T) {
	wanted := map[string]string{
		"UNSUPPORTED_PLATFORM": OutdatedSoftwareErrUnsupportedPlatform,
		"WINGET_NOT_FOUND":     OutdatedSoftwareErrWinGetNotFound,
		"WINGET_TIMEOUT":       OutdatedSoftwareErrWinGetTimeout,
		"WINGET_FAILED":        OutdatedSoftwareErrWinGetFailed,
		"WINGET_EMPTY_OUTPUT":  OutdatedSoftwareErrWinGetEmptyOutput,
		"WINGET_PARSE_ERROR":   OutdatedSoftwareErrWinGetParseError,
	}
	for want, got := range wanted {
		if got != want {
			t.Errorf("expected code %q, got %q", want, got)
		}
	}
}

// ────────────────────────────────────────────────────────────────
// Opt-in / opt-out wiring (runs on the linux host — collect seam is
// platform-agnostic).

func TestCollectWithOptions_OutdatedSoftwareOptOut(t *testing.T) {
	invoked := false
	prev := collectOutdatedSoftwareForSnapshot
	collectOutdatedSoftwareForSnapshot = func(_ time.Time) OutdatedSoftwareResult {
		invoked = true
		return OutdatedSoftwareResult{}
	}
	defer func() { collectOutdatedSoftwareForSnapshot = prev }()

	snap := CollectWithOptions("test", time.Unix(1700000000, 0), CollectOptions{})
	if invoked {
		t.Fatalf("outdated-software probe must not run when opt-out")
	}
	if snap.OutdatedSoftware != nil {
		t.Fatalf("snapshot.OutdatedSoftware must be nil when opt-out")
	}
}

func TestCollectWithOptions_OutdatedSoftwareOptIn(t *testing.T) {
	sentinel := OutdatedSoftwareResult{
		SchemaVersion: OutdatedSoftwareSchemaVersion,
		Supported:     true,
		ProbeComplete: true,
		SourceUsed:    OutdatedSoftwareSourceWinGet,
	}
	calls := 0
	prev := collectOutdatedSoftwareForSnapshot
	collectOutdatedSoftwareForSnapshot = func(_ time.Time) OutdatedSoftwareResult {
		calls++
		return sentinel
	}
	defer func() { collectOutdatedSoftwareForSnapshot = prev }()

	snap := CollectWithOptions("test", time.Unix(1700000000, 0),
		CollectOptions{IncludeOutdatedSoftware: true})
	if calls != 1 {
		t.Fatalf("expected probe invocation count = 1, got %d", calls)
	}
	if snap.OutdatedSoftware == nil {
		t.Fatalf("snapshot.OutdatedSoftware must be set when opt-in")
	}
	if snap.OutdatedSoftware.SchemaVersion != OutdatedSoftwareSchemaVersion {
		t.Fatalf("schemaVersion mismatch")
	}
}
