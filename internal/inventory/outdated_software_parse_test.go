package inventory

// AG-036 — build-tag-agnostic parser tests. This file has NO
// //go:build windows tag, so the winget `upgrade` table parser is
// exercised on EVERY platform — including the linux CI host where the
// //go:build windows runner is skipped. Pinning the parser table tests
// here is the systemic fix for the off-by-one regression that escaped
// because the only coverage lived behind a skipped Windows-only test.

import (
	"strings"
	"testing"
)

// Column-aligned winget `upgrade` fixture. The dashed separator widths
// match the header column starts (Id@21, Version@46, Available@55,
// Source@66) so the layout-aware parser resolves real columns.
const wingetHeader = "Name                 Id                       Version  Available  Source"
const wingetSep = "-------------------- ------------------------ -------- ---------- -------"

func wingetTable(rows ...string) string {
	all := append([]string{wingetHeader, wingetSep}, rows...)
	return strings.Join(all, "\n") + "\n"
}

// TestParseUpgradeOutput_SinglePackage_NotDropped is the direct
// regression for the off-by-one: the first (and here only) data row sits
// IMMEDIATELY after the dashed separator. The old `headerIdx+2` start
// skipped it, yielding zero packages (-> PARSE_ERROR upstream). The
// correct `headerIdx+1` keeps it.
func TestParseUpgradeOutput_SinglePackage_NotDropped(t *testing.T) {
	out := wingetTable(
		"7-Zip                7zip.7zip                24.09    25.01      winget",
	)
	got, err := parseUpgradeOutput(out)
	if err != nil {
		t.Fatalf("parseUpgradeOutput error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 (first row must NOT be dropped); got %#v", len(got), got)
	}
	want := OutdatedSoftwarePackage{PackageID: "7zip.7zip", InstalledVersion: "24.09", AvailableVersion: "25.01"}
	if got[0] != want {
		t.Fatalf("pkg = %#v, want %#v", got[0], want)
	}
}

// TestParseUpgradeOutput_MultiPackage_FirstKept asserts the first row of
// a multi-row table is retained (the old +2 silently omitted it).
func TestParseUpgradeOutput_MultiPackage_FirstKept(t *testing.T) {
	out := wingetTable(
		"7-Zip                7zip.7zip                24.09    25.01      winget",
		"Git                  Git.Git                  2.43.0   2.44.0     winget",
		"Visual Studio Code   Microsoft.VisualStudioCode 1.85.0 1.86.0    winget",
	)
	got, err := parseUpgradeOutput(out)
	if err != nil {
		t.Fatalf("parseUpgradeOutput error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3; got %#v", len(got), got)
	}
	if got[0].PackageID != "7zip.7zip" {
		t.Errorf("first package id = %q, want 7zip.7zip (first row dropped?)", got[0].PackageID)
	}
	ids := []string{got[0].PackageID, got[1].PackageID, got[2].PackageID}
	wantIDs := []string{"7zip.7zip", "Git.Git", "Microsoft.VisualStudioCode"}
	for i := range wantIDs {
		if ids[i] != wantIDs[i] {
			t.Errorf("ids[%d] = %q, want %q", i, ids[i], wantIDs[i])
		}
	}
}

// TestParseUpgradeOutput_DottedDisplayName_CorrectID is the P2 #1
// hardening fixture: a display name that itself contains a dot/dash must
// NOT be mis-reported as the package id. The layout-aware column slice
// (and the token fallback that anchors on the version pair) takes the Id
// column, not the first dotted token in the name.
func TestParseUpgradeOutput_DottedDisplayName_CorrectID(t *testing.T) {
	out := wingetTable(
		"Node.js              OpenJS.NodeJS            20.10.0  20.11.0    winget",
		"Adobe Acrobat-Reader Adobe.Acrobat.Reader.64-bit 23.1 24.1      winget",
	)
	got, err := parseUpgradeOutput(out)
	if err != nil {
		t.Fatalf("parseUpgradeOutput error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2; got %#v", len(got), got)
	}
	if got[0].PackageID != "OpenJS.NodeJS" {
		t.Errorf("dotted-name row: id = %q, want OpenJS.NodeJS (NOT 'Node.js')", got[0].PackageID)
	}
	if got[0].InstalledVersion != "20.10.0" || got[0].AvailableVersion != "20.11.0" {
		t.Errorf("dotted-name row versions = (%q,%q), want (20.10.0,20.11.0)", got[0].InstalledVersion, got[0].AvailableVersion)
	}
	if got[1].PackageID != "Adobe.Acrobat.Reader.64-bit" {
		t.Errorf("dash-name row: id = %q, want Adobe.Acrobat.Reader.64-bit (NOT 'Acrobat-Reader')", got[1].PackageID)
	}
}

// TestParseUpgradeOutput_SkipsProgressAndContinuation ensures
// leading-whitespace progress / continuation lines are skipped while
// real digit-leading display names (e.g. "7-Zip") are still parsed.
func TestParseUpgradeOutput_SkipsProgressAndContinuation(t *testing.T) {
	out := wingetTable(
		"7-Zip                7zip.7zip                24.09    25.01      winget",
		"  - extra wrapped continuation text",
		"   12% progress bar artifact",
		"Git                  Git.Git                  2.43.0   2.44.0     winget",
	)
	got, err := parseUpgradeOutput(out)
	if err != nil {
		t.Fatalf("parseUpgradeOutput error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (continuation/progress lines skipped); got %#v", len(got), got)
	}
}

// TestParseUpgradeOutput_NoSeparator_Errors confirms the parse-error
// path when no dashed separator is present.
func TestParseUpgradeOutput_NoSeparator_Errors(t *testing.T) {
	_, err := parseUpgradeOutput("some random text without table markers\nstill nothing")
	if err == nil {
		t.Fatal("expected error when no header separator found")
	}
}

// TestParseUpgradeOutput_SeparatorIsLastLine_NoPanic guards the boundary
// where the separator is the final line (no data rows).
func TestParseUpgradeOutput_SeparatorIsLastLine_NoPanic(t *testing.T) {
	out := wingetHeader + "\n" + wingetSep + "\n"
	got, err := parseUpgradeOutput(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len = %d, want 0", len(got))
	}
}

// TestParseUpgradeLine_TokenFallback exercises the whitespace-token
// fallback directly (used when the fixed-width layout can't be
// resolved). It must anchor on the adjacent version pair and take the
// preceding id token.
func TestParseUpgradeLine_TokenFallback(t *testing.T) {
	cases := []struct {
		name string
		line string
		want OutdatedSoftwarePackage
	}{
		{
			"canonical",
			"7-Zip 7zip.7zip 24.09 25.01 winget",
			OutdatedSoftwarePackage{"7zip.7zip", "24.09", "25.01"},
		},
		{
			"dotted display name",
			"Node.js OpenJS.NodeJS 20.10.0 20.11.0 winget",
			OutdatedSoftwarePackage{"OpenJS.NodeJS", "20.10.0", "20.11.0"},
		},
		{
			"no version pair",
			"Some Name Without Versions Here",
			OutdatedSoftwarePackage{},
		},
		{
			"too few tokens",
			"OnlyThree Tokens Here",
			OutdatedSoftwarePackage{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseUpgradeLine(tc.line)
			if got != tc.want {
				t.Fatalf("parseUpgradeLine(%q) = %#v, want %#v", tc.line, got, tc.want)
			}
		})
	}
}

// TestIsWinGetPackageID validates the package-id charset gate.
func TestIsWinGetPackageID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"7zip.7zip", true},
		{"Microsoft.VisualStudioCode", true},
		{"Adobe.Acrobat.Reader.64-bit", true},
		{"Git.Git", true},
		{"NoSeparatorHere", false}, // no '.' or '-'
		{"", false},
		{"bad id", false},        // space
		{"weird/slash.x", false}, // '/'
		{"semi;colon.x", false},  // ';'
	}
	for _, c := range cases {
		if got := isWinGetPackageID(c.in); got != c.want {
			t.Errorf("isWinGetPackageID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
