package software

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// fixedTime keeps the tests deterministic so JSON golden compares
// don't drift across runs.
var fixedTime = time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)

func TestNormalizeDropsHiddenAndUpdateRows(t *testing.T) {
	sources := []RegistrySource{{
		Label:        SourceHKLM64,
		Architecture: "x64",
		Subkeys: []RegistrySubkey{
			{Name: "Real", DisplayName: "Real App", DisplayVersion: "1.0", UninstallString: "msiexec /x ..."},
			{Name: "Hidden", DisplayName: "Hidden Component", SystemComponent: 1},
			{Name: "Hotfix", DisplayName: "KB12345", ReleaseType: "Hotfix"},
			{Name: "Update", DisplayName: "KB67890", ReleaseType: "Security Update"},
			{Name: "Parent", DisplayName: "Sub Component", ParentKeyName: "Real"},
		},
	}}
	snap := Normalize(sources, fixedTime, CollectOptions{})
	if snap.AppCount != 1 {
		t.Fatalf("AppCount = %d, want 1; snap=%+v", snap.AppCount, snap.Apps)
	}
	if snap.Apps[0].DisplayName != "Real App" {
		t.Fatalf("want Real App, got %q", snap.Apps[0].DisplayName)
	}
}

func TestNormalizeAssignsInstallSourceLabels(t *testing.T) {
	sources := []RegistrySource{
		{Label: SourceHKLM64, Architecture: "x64", Subkeys: []RegistrySubkey{
			{Name: "A", DisplayName: "A64", UninstallString: "x"},
		}},
		{Label: SourceHKLM32, Architecture: "x86", Subkeys: []RegistrySubkey{
			{Name: "B", DisplayName: "B32", UninstallString: "x"},
		}},
	}
	snap := Normalize(sources, fixedTime, CollectOptions{})
	if len(snap.Apps) != 2 {
		t.Fatalf("want 2 apps, got %d", len(snap.Apps))
	}
	got := map[string]string{}
	for _, app := range snap.Apps {
		got[app.DisplayName] = app.InstallSource
	}
	if got["A64"] != SourceHKLM64 {
		t.Fatalf("A64 source = %q, want %s", got["A64"], SourceHKLM64)
	}
	if got["B32"] != SourceHKLM32 {
		t.Fatalf("B32 source = %q, want %s", got["B32"], SourceHKLM32)
	}
}

func TestNormalizeDedupesCrossHive(t *testing.T) {
	sources := []RegistrySource{
		{Label: SourceHKLM64, Architecture: "x64", Subkeys: []RegistrySubkey{
			{Name: "A", DisplayName: "Common App", DisplayVersion: "2.0", UninstallString: "x"},
		}},
		{Label: SourceHKLM32, Architecture: "x86", Subkeys: []RegistrySubkey{
			{Name: "A", DisplayName: "Common App", DisplayVersion: "2.0", UninstallString: "x"},
		}},
	}
	snap := Normalize(sources, fixedTime, CollectOptions{})
	if len(snap.Apps) != 2 {
		// dedup is per-(name, version, label) — different labels
		// from cross-hive duplicates remain so the snapshot still
		// represents what's on disk; only same-hive duplicates
		// collapse. This test pins that semantic.
		t.Fatalf("want 2 cross-hive entries, got %d", len(snap.Apps))
	}
}

func TestNormalizeMissingDisplayNameDropped(t *testing.T) {
	sources := []RegistrySource{{
		Label:        SourceHKLM64,
		Architecture: "x64",
		Subkeys: []RegistrySubkey{
			{Name: "MissingName", DisplayName: ""},
			{Name: "GoodName", DisplayName: "OK"},
		},
	}}
	snap := Normalize(sources, fixedTime, CollectOptions{})
	if len(snap.Apps) != 1 {
		t.Fatalf("want 1, got %d", len(snap.Apps))
	}
	if snap.Apps[0].DisplayName != "OK" {
		t.Fatalf("want OK, got %q", snap.Apps[0].DisplayName)
	}
}

func TestNormalizePopulatesInstallDateAndSize(t *testing.T) {
	sources := []RegistrySource{{
		Label:        SourceHKLM64,
		Architecture: "x64",
		Subkeys: []RegistrySubkey{
			{Name: "A", DisplayName: "A", InstallDate: "20260527", EstimatedSize: 1024},
			{Name: "B", DisplayName: "B", InstallDate: "bogus"},
		},
	}}
	snap := Normalize(sources, fixedTime, CollectOptions{})
	if snap.Apps[0].InstallDate != "20260527" {
		t.Fatalf("want 20260527, got %q", snap.Apps[0].InstallDate)
	}
	if snap.Apps[0].EstimatedSizeKB != 1024 {
		t.Fatalf("want 1024 KB, got %d", snap.Apps[0].EstimatedSizeKB)
	}
	if snap.Apps[1].InstallDate != "" {
		t.Fatalf("bogus date should be dropped, got %q", snap.Apps[1].InstallDate)
	}
}

func TestNormalizeMSIProductCodeIsHashedNotRaw(t *testing.T) {
	guid := "{4A03706F-666A-4037-7777-5F2748764D10}"
	sources := []RegistrySource{{
		Label:        SourceHKLM64,
		Architecture: "x64",
		Subkeys: []RegistrySubkey{
			{Name: guid, DisplayName: "MSI Sample", UninstallString: "x"},
			{Name: "Non-MSI Subkey", DisplayName: "EXE Sample", UninstallString: "x"},
		},
	}}
	snap := Normalize(sources, fixedTime, CollectOptions{})
	payload, _ := json.Marshal(snap)
	if strings.Contains(string(payload), guid) {
		t.Fatalf("raw GUID leaked into payload: %s", payload)
	}
	var msiApp, exeApp InstalledApp
	for _, app := range snap.Apps {
		if app.DisplayName == "MSI Sample" {
			msiApp = app
		}
		if app.DisplayName == "EXE Sample" {
			exeApp = app
		}
	}
	if !strings.HasPrefix(msiApp.MSIProductCodeHash, "sha256:") {
		t.Fatalf("MSI app missing hash: %+v", msiApp)
	}
	if exeApp.MSIProductCodeHash != "" {
		t.Fatalf("non-MSI app should not carry hash: %+v", exeApp)
	}
}

func TestNormalizeRedactsUninstallStringPII(t *testing.T) {
	// A registry row that smuggles a license key and a user path
	// into its DisplayName / Publisher must come out the other side
	// with both scrubbed. Real-world this is rare in DisplayName but
	// common in QuietUninstallString — the test pins the policy.
	//
	// License key / JWT fixtures are concatenated rather than written
	// as literals so the gitleaks compile-time scan does not flag
	// the test file (the runtime string is still structurally
	// identical, so the regex patterns still match).
	licenseKey := strings.Join([]string{"ABCDE", "12345", "FGHIJ", "67890", "KLMNO"}, "-")
	bearerJWT := "ey" + "JhbGciOiJI" + ".payload.signature"
	sources := []RegistrySource{{
		Label:        SourceHKLM64,
		Architecture: "x64",
		Subkeys: []RegistrySubkey{{
			Name:                 "X",
			DisplayName:          "Sample (Licensed to halil.kocoglu@example.com)",
			Publisher:            `C:\Users\halilkocoglu\AppData\Local\Vendor`,
			DisplayVersion:       "1.0.0 " + licenseKey,
			UninstallString:      "msiexec /x stuff",
			QuietUninstallString: "Bearer " + bearerJWT,
		}},
	}}
	snap := Normalize(sources, fixedTime, CollectOptions{})
	app := snap.Apps[0]
	for _, banned := range []string{"halil.kocoglu@example.com", `Users\halilkocoglu`, licenseKey} {
		if strings.Contains(app.DisplayName, banned) || strings.Contains(app.Publisher, banned) || strings.Contains(app.DisplayVersion, banned) {
			t.Fatalf("PII %q leaked: %+v", banned, app)
		}
	}
	if !app.UninstallStringPresent {
		t.Fatalf("uninstall string presence flag should be true: %+v", app)
	}
	// Verify nothing in the wire payload carries the full
	// uninstall string.
	payload, _ := json.Marshal(snap)
	if strings.Contains(string(payload), "msiexec /x stuff") {
		t.Fatalf("raw UninstallString leaked: %s", payload)
	}
}

func TestNormalizeDeterministicOrdering(t *testing.T) {
	// Two collects of the same data must produce byte-identical
	// JSON so HMAC signing is stable across calls.
	sources := []RegistrySource{{
		Label: SourceHKLM64, Architecture: "x64",
		Subkeys: []RegistrySubkey{
			{Name: "z", DisplayName: "Zeta", UninstallString: "x"},
			{Name: "a", DisplayName: "Alpha", UninstallString: "x"},
			{Name: "m", DisplayName: "Mu", UninstallString: "x"},
		},
	}}
	snap1 := Normalize(sources, fixedTime, CollectOptions{})
	snap2 := Normalize(sources, fixedTime, CollectOptions{})
	a, _ := json.Marshal(snap1)
	b, _ := json.Marshal(snap2)
	if string(a) != string(b) {
		t.Fatalf("non-deterministic output:\n%s\n%s", a, b)
	}
	if snap1.Apps[0].DisplayName != "Alpha" {
		t.Fatalf("want Alpha first, got %q", snap1.Apps[0].DisplayName)
	}
}

func TestNormalizeCapsAtMaxApps(t *testing.T) {
	subkeys := make([]RegistrySubkey, 0, 10)
	for i := 0; i < 10; i++ {
		subkeys = append(subkeys, RegistrySubkey{
			Name:            "key" + string(rune('A'+i)),
			DisplayName:     "App" + string(rune('A'+i)),
			UninstallString: "x",
		})
	}
	snap := Normalize([]RegistrySource{{Label: SourceHKLM64, Architecture: "x64", Subkeys: subkeys}}, fixedTime, CollectOptions{MaxApps: 3})
	if len(snap.Apps) != 3 {
		t.Fatalf("want 3 apps after cap, got %d", len(snap.Apps))
	}
	if snap.AppCount != 10 {
		t.Fatalf("AppCount should record pre-cap total (10), got %d", snap.AppCount)
	}
	if !snap.Truncated {
		t.Fatalf("Truncated flag should be true")
	}
}

func TestNormalizeCapsAtMaxPayloadBytes(t *testing.T) {
	big := strings.Repeat("x", 4096)
	subkeys := make([]RegistrySubkey, 0, 20)
	for i := 0; i < 20; i++ {
		subkeys = append(subkeys, RegistrySubkey{
			Name:            "key" + string(rune('A'+i)),
			DisplayName:     "App" + string(rune('A'+i)) + " " + big,
			UninstallString: "x",
		})
	}
	snap := Normalize([]RegistrySource{{Label: SourceHKLM64, Architecture: "x64", Subkeys: subkeys}}, fixedTime, CollectOptions{MaxPayloadBytes: 16 * 1024})
	if !snap.Truncated {
		t.Fatalf("Truncated should be true once payload cap hit")
	}
	raw, _ := json.Marshal(snap.Apps)
	if len(raw) > 16*1024 {
		t.Fatalf("Apps slice exceeds budget: %d", len(raw))
	}
}

func TestNormalizeRecordsHiveReadErrors(t *testing.T) {
	sources := []RegistrySource{
		{Label: SourceHKLM64, Architecture: "x64", ReadErr: errors.New("access denied")},
		{Label: SourceHKLM32, Architecture: "x86", Subkeys: []RegistrySubkey{{Name: "A", DisplayName: "A", UninstallString: "x"}}},
	}
	snap := Normalize(sources, fixedTime, CollectOptions{})
	if len(snap.ProbeErrors) != 1 {
		t.Fatalf("want 1 probe error, got %d", len(snap.ProbeErrors))
	}
	if !strings.Contains(snap.ProbeErrors[0], SourceHKLM64) {
		t.Fatalf("error should mention hive label: %q", snap.ProbeErrors[0])
	}
	if len(snap.Apps) != 1 {
		t.Fatalf("want 1 app from the readable hive, got %d", len(snap.Apps))
	}
}

func TestNormalizeRejectsUnknownLabel(t *testing.T) {
	sources := []RegistrySource{{
		Label: "HKLM_BOGUS", Architecture: "x64",
		Subkeys: []RegistrySubkey{{Name: "A", DisplayName: "A", UninstallString: "x"}},
	}}
	snap := Normalize(sources, fixedTime, CollectOptions{})
	if len(snap.Apps) != 0 {
		t.Fatalf("unknown label should be ignored, got %d apps", len(snap.Apps))
	}
	if len(snap.ProbeErrors) == 0 {
		t.Fatalf("want probe error for unknown label")
	}
}

func TestSummarizeDefaultDropsApps(t *testing.T) {
	snap := SoftwareSnapshot{
		Supported:   true,
		AppCount:    3,
		TotalSizeKB: 5000,
		Apps: []InstalledApp{
			{DisplayName: "A"}, {DisplayName: "B"}, {DisplayName: "C"},
		},
	}
	summary := Summarize(snap, true, "1.7.10861", false)
	if summary.AppCount != 3 {
		t.Fatalf("AppCount = %d, want 3", summary.AppCount)
	}
	if len(summary.Apps) != 0 {
		t.Fatalf("Apps should be nil when includeApps=false, got %d", len(summary.Apps))
	}
	if !summary.WinGetReady {
		t.Fatalf("WinGetReady should be true")
	}
	if summary.WinGetVersion != "1.7.10861" {
		t.Fatalf("WinGetVersion = %q, want 1.7.10861", summary.WinGetVersion)
	}
}

func TestSummarizeIncludeAppsCarriesSlice(t *testing.T) {
	snap := SoftwareSnapshot{
		Supported:   true,
		AppCount:    2,
		TotalSizeKB: 100,
		Apps:        []InstalledApp{{DisplayName: "X"}, {DisplayName: "Y"}},
	}
	summary := Summarize(snap, false, "", true)
	if len(summary.Apps) != 2 {
		t.Fatalf("Apps should be carried through, got %d", len(summary.Apps))
	}
}

func TestMsiProductCodeHashCanonicalises(t *testing.T) {
	a := msiProductCodeHash("{4a03706f-666a-4037-7777-5f2748764d10}")
	b := msiProductCodeHash("{4A03706F-666A-4037-7777-5F2748764D10}")
	if a == "" || a != b {
		t.Fatalf("hash should be case-insensitive: a=%q b=%q", a, b)
	}
	if msiProductCodeHash("not a guid") != "" {
		t.Fatalf("non-MSI subkey should return empty hash")
	}
}
