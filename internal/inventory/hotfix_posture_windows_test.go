//go:build windows

package inventory

import (
	"context"
	"strings"
	"testing"
	"time"
)

// AG-037 Windows-tagged unit tests covering the Codex 019e8167 iter-2
// REVISE absorb points the cross-platform tests cannot exercise:
//
//   - Microsoft Update classification GUID mapping (P1.1)
//   - Pinned PowerShell script invariants — no install / no reboot
//     trigger / no service mutation (read-only contract)
//   - Driver pending filter removed (P1.2)
//   - ACCESS_DENIED / WSUS_UNREACHABLE classify codepoints in the
//     PowerShell script (P1.4)
//   - Service-state Get-CimInstance pattern + SERVICE_QUERY_FAILED
//     error append (P1.3)
//   - Nil ctx guard (P2.5)
//   - Redaction broadened path-prefix list (P2.6)

// ────────────────────────────────────────────────────────────────
// P1.1 — GUID mapping (the iter-2 P1 blocker)

func TestPrimaryCategoryFromGuids_KnownGUIDs(t *testing.T) {
	cases := []struct {
		name string
		guid string
		want HotfixPostureCategory
	}{
		{"security", "0fa1201d-4330-4fa8-8ae9-b877473b6441", HotfixPostureCategorySecurity},
		{"critical", "e6cf1350-c01b-414d-a61f-263d14d133b4", HotfixPostureCategoryCritical},
		{"definition", "e0789628-ce08-4437-be74-2495b842f43b", HotfixPostureCategoryDefinition},
		{"servicePack", "68c5b0a3-d1a6-4553-ae49-01d3a7827828", HotfixPostureCategoryServicePack},
		{"featurePack", "b54e7d24-7add-428f-8b75-90a396fa584f", HotfixPostureCategoryFeaturePack},
		{"driver", "ebfd1a04-a2cc-49f1-9bce-6d93f0d5694b", HotfixPostureCategoryDriver},
		{"updateRollup", "28bc880e-0592-4cbf-8f95-c79b17911d5f", HotfixPostureCategoryUpdateRollup},
		{"tools", "b4832bd8-e735-4761-8daf-37f882276dab", HotfixPostureCategoryTools},
		{"updates-uncategorized", "cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83", HotfixPostureCategoryUncategorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := primaryCategoryFromGuids([]string{tc.guid})
			if got != tc.want {
				t.Errorf("guid %s: got %s, want %s", tc.guid, got, tc.want)
			}
		})
	}
}

func TestPrimaryCategoryFromGuids_UpperCaseGUID(t *testing.T) {
	// Map keys are lowercase; normaliser uses ToLower(TrimSpace).
	got := primaryCategoryFromGuids([]string{"0FA1201D-4330-4FA8-8AE9-B877473B6441"})
	if got != HotfixPostureCategorySecurity {
		t.Errorf("uppercase GUID: got %s, want SECURITY", got)
	}
}

func TestPrimaryCategoryFromGuids_PrecedenceSecurityOverDriver(t *testing.T) {
	// An update tagged as both Security and Driver must resolve to
	// Security (rank 0 vs Driver rank 4).
	got := primaryCategoryFromGuids([]string{
		"ebfd1a04-a2cc-49f1-9bce-6d93f0d5694b", // Driver (official WUA GUID)
		"0fa1201d-4330-4fa8-8ae9-b877473b6441", // Security
	})
	if got != HotfixPostureCategorySecurity {
		t.Errorf("expected SECURITY (highest precedence), got %s", got)
	}
}

func TestPrimaryCategoryFromGuids_UnknownGUID(t *testing.T) {
	got := primaryCategoryFromGuids([]string{"00000000-0000-0000-0000-000000000000"})
	if got != HotfixPostureCategoryUncategorized {
		t.Errorf("expected UNCATEGORIZED for unknown GUID, got %s", got)
	}
}

func TestPrimaryCategoryFromGuids_EmptyList(t *testing.T) {
	got := primaryCategoryFromGuids(nil)
	if got != HotfixPostureCategoryUncategorized {
		t.Errorf("expected UNCATEGORIZED for empty list, got %s", got)
	}
}

// ────────────────────────────────────────────────────────────────
// P1.2 — Driver filter must NOT be in the pinned script

func TestHotfixProbeScript_NoDriverFilter(t *testing.T) {
	// The probe must NOT filter on Type='Software' — that would
	// silently exclude driver updates from the pending list (iter-2
	// P1.2). The contract surfaces drivers via category resolution.
	if strings.Contains(hotfixProbeScript, "Type='Software'") {
		t.Errorf("pinned script still contains Type='Software' filter — driver updates would be excluded")
	}
	// Sanity: the pending Search line is still present.
	if !strings.Contains(hotfixProbeScript, "Search(\"IsInstalled=0 AND IsHidden=0\")") {
		t.Errorf("pending Search line missing or altered shape")
	}
}

// ────────────────────────────────────────────────────────────────
// PowerShell script read-only invariants

func TestHotfixProbeScript_ReadOnlyInvariant(t *testing.T) {
	// Forbidden cmdlets / verbs — these would mutate Windows Update
	// state. The pinned script must NEVER contain any of these.
	forbidden := []string{
		"Install-WindowsUpdate",
		"Install-Module",
		"Install-Package",
		"wuauclt /detectnow",
		"wuauclt.exe /detectnow",
		"Start-Service ",
		"Stop-Service ",
		"Set-Service ",
		"Restart-Service ",
		"Set-ItemProperty ", // registry write
		"New-ItemProperty ",
		"Remove-ItemProperty ",
		"sconfig",
		"Restart-Computer",
		"Stop-Computer",
	}
	for _, f := range forbidden {
		if strings.Contains(hotfixProbeScript, f) {
			t.Errorf("pinned script contains forbidden cmdlet/verb %q — read-only contract broken", f)
		}
	}
}

// ────────────────────────────────────────────────────────────────
// P1.3 — Service-state via Get-CimInstance + SERVICE_QUERY_FAILED append

func TestHotfixProbeScript_ServiceStateCIMPattern(t *testing.T) {
	// Codex iter-2 P1.3: must use Get-CimInstance Win32_Service +
	// StartMode/State (not $svc.StartType which is unsafe under
	// Windows PowerShell 5.1 ServiceController).
	if !strings.Contains(hotfixProbeScript, "Get-CimInstance -ClassName Win32_Service") {
		t.Errorf("pinned script missing Get-CimInstance Win32_Service pattern")
	}
	if strings.Contains(hotfixProbeScript, "$svc.StartType") {
		t.Errorf("pinned script still references unsafe $svc.StartType")
	}
	// Must append SERVICE_QUERY_FAILED on failure rather than silently
	// returning UNKNOWN.
	if !strings.Contains(hotfixProbeScript, "SERVICE_QUERY_FAILED") {
		t.Errorf("pinned script missing SERVICE_QUERY_FAILED error append on service query failure")
	}
}

// ────────────────────────────────────────────────────────────────
// P1.4 — Exception classify codepoints

func TestHotfixProbeScript_ExceptionClassifyCodepoints(t *testing.T) {
	// The pinned script's WUA catch blocks must classify the
	// exception type / HRESULT rather than collapsing every failure
	// to COM_FAILED (iter-2 P1.4).
	expectedCodepoints := []string{
		"UnauthorizedAccessException",     // typed exception classify
		"0x80070005",                      // HRESULT for ACCESS_DENIED
		"ACCESS_DENIED",                   // typed code emitted
		"WSUS_UNREACHABLE",                // typed code emitted
		"^0x80244[0-9A-F]{3}$",            // WSUS HRESULT family regex
	}
	for _, codepoint := range expectedCodepoints {
		if !strings.Contains(hotfixProbeScript, codepoint) {
			t.Errorf("pinned script missing exception-classify codepoint %q", codepoint)
		}
	}
}

func TestCanonicalHotfixErrorCode_ACCESS_DENIED(t *testing.T) {
	got := canonicalHotfixErrorCode("ACCESS_DENIED")
	if got != HotfixPostureAccessDenied {
		t.Errorf("canonicalHotfixErrorCode(ACCESS_DENIED) = %q, want %q", got, HotfixPostureAccessDenied)
	}
}

func TestCanonicalHotfixErrorCode_WSUS_UNREACHABLE(t *testing.T) {
	got := canonicalHotfixErrorCode("WSUS_UNREACHABLE")
	if got != HotfixPostureWSUSUnreachable {
		t.Errorf("canonicalHotfixErrorCode(WSUS_UNREACHABLE) = %q, want %q", got, HotfixPostureWSUSUnreachable)
	}
}

// ────────────────────────────────────────────────────────────────
// P2.5 — Nil context guard (no panic, normalises to background)

func TestProbeHotfixPosture_NilContextNormalised(t *testing.T) {
	// Codex iter-2 P2.5: ProbeHotfixPosture must not panic on a nil
	// ctx. We can't easily intercept the actual exec.CommandContext
	// from here, but we can call the entry point with nil and rely
	// on the test-seam pattern + the assertion that we don't panic
	// in `context.WithTimeout(nil, ...)`.
	//
	// Defer-recover lets us assert no panic occurred regardless of
	// the powershell.exe path (the real WUA path may fail on the
	// Parallels lab and still surface a typed error, but it must not
	// panic).
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ProbeHotfixPosture panicked with nil ctx: %v", r)
		}
	}()
	_ = ProbeHotfixPosture(nil, func() time.Time { return time.Unix(0, 0).UTC() })
}

// ────────────────────────────────────────────────────────────────
// P2.6 — Redaction broadened

func TestRedactHotfixSummary_BroadenedPathPrefixes(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		mustHave string
	}{
		{"user-profile-c-backslash", `error in C:\Users\halil\foo`, "<redacted>"},
		{"user-profile-d-forward", `error in D:/Users/halil/foo`, "<redacted>"},
		{"windows-root", `failed at C:\Windows\System32`, "<redacted>"},
		{"program-files", `error in C:\Program Files\App`, "<redacted>"},
		{"program-data", `cache at C:\ProgramData\App`, "<redacted>"},
		{"unc", `error \\fileshare\public\foo`, "<redacted>"},
		{"forward-slash-unc", `error //fileshare/public/foo`, "<redacted>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactHotfixSummary(tc.in)
			if !strings.Contains(got, tc.mustHave) {
				t.Errorf("redactHotfixSummary(%q) = %q; expected to contain %q",
					tc.in, got, tc.mustHave)
			}
		})
	}
}

func TestRedactHotfixSummary_CRLFStripped(t *testing.T) {
	in := "line1\r\nline2\tline3"
	got := redactHotfixSummary(in)
	for _, ch := range []string{"\r", "\n", "\t"} {
		if strings.Contains(got, ch) {
			t.Errorf("expected CRLF/tab to be stripped, got %q", got)
		}
	}
}

func TestRedactHotfixSummary_LengthCap(t *testing.T) {
	in := strings.Repeat("a", 500)
	got := redactHotfixSummary(in)
	if len(got) > 200 {
		t.Errorf("expected length cap at 200, got %d", len(got))
	}
}

// Compile-time guards that the test helpers we reference do exist.
var (
	_ = ProbeHotfixPosture
	_ context.Context
)
