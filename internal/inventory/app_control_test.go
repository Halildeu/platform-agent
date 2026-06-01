package inventory

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Cross-platform AG-041 tests. Codex 019e83ce iter-2 absorb — table-
// driven enum allowlist + WDAC mode derivation + AppLocker DWORD
// mapping + redaction boundary + wire-shape stability.

func TestAppControlSchemaVersionPinned(t *testing.T) {
	if AppControlSchemaVersion != 1 {
		t.Fatalf("schemaVersion must stay 1 for v1; got %d", AppControlSchemaVersion)
	}
}

func TestWdacModeEnumAllowlist(t *testing.T) {
	allowed := map[WdacMode]bool{
		WdacModeOff:     true,
		WdacModeAudit:   true,
		WdacModeEnforce: true,
		WdacModeUnknown: true,
	}
	for got := range allowed {
		// Enum members must be non-empty + uppercase + match canonical
		// SCREAMING_SNAKE_CASE / wire labels.
		s := string(got)
		if s == "" {
			t.Errorf("empty WdacMode value")
		}
		if strings.ToUpper(s) != s {
			t.Errorf("WdacMode %q must be SCREAMING_CASE", s)
		}
	}
}

func TestAppLockerEnforcementModeEnumAllowlist(t *testing.T) {
	allowed := []AppLockerEnforcementMode{
		AppLockerNotConfigured,
		AppLockerAuditOnly,
		AppLockerEnforce,
		AppLockerUnknown,
	}
	wantStrs := []string{"NOT_CONFIGURED", "AUDIT_ONLY", "ENFORCE", "UNKNOWN"}
	for i, m := range allowed {
		if string(m) != wantStrs[i] {
			t.Errorf("AppLockerEnforcementMode[%d] expected %q got %q", i, wantStrs[i], string(m))
		}
	}
}

func TestAppControlProbeErrorSourceEnum(t *testing.T) {
	allowed := []AppControlProbeErrorSource{
		AppControlProbeErrSourceWdac,
		AppControlProbeErrSourceAppLocker,
		AppControlProbeErrSourceFilesystem,
	}
	wantStrs := []string{"wdac", "appLocker", "filesystem"}
	for i, s := range allowed {
		if string(s) != wantStrs[i] {
			t.Errorf("ProbeErrorSource[%d] expected %q got %q", i, wantStrs[i], string(s))
		}
	}
}

// TestDeriveWdacModeTable — Codex 019e83ce iter-1 P0 #2 + iter-2
// finalisation. Conservative derivation: UNKNOWN dominant.
func TestDeriveWdacModeTable(t *testing.T) {
	tPtr := func(b bool) *bool { return &b }
	iPtr := func(i int) *int { return &i }

	cases := []struct {
		name string
		ev   WdacEvidence
		want WdacMode
	}{
		{
			name: "queryable=false → UNKNOWN regardless of other evidence",
			ev:   WdacEvidence{Queryable: false, ExplicitEnforce: tPtr(true)},
			want: WdacModeUnknown,
		},
		{
			name: "decisionCriticalReadFailed → UNKNOWN",
			ev: WdacEvidence{
				Queryable:                  true,
				DecisionCriticalReadFailed: true,
				ExplicitEnforce:            tPtr(true),
			},
			want: WdacModeUnknown,
		},
		{
			name: "ExplicitEnforce=true → ENFORCE (highest priority)",
			ev:   WdacEvidence{Queryable: true, ExplicitEnforce: tPtr(true)},
			want: WdacModeEnforce,
		},
		{
			name: "ExplicitAudit=true → AUDIT",
			ev:   WdacEvidence{Queryable: true, ExplicitAudit: tPtr(true)},
			want: WdacModeAudit,
		},
		{
			name: "both explicit → ENFORCE (safety-prioritised)",
			ev: WdacEvidence{
				Queryable:       true,
				ExplicitEnforce: tPtr(true),
				ExplicitAudit:   tPtr(true),
			},
			want: WdacModeEnforce,
		},
		{
			name: "no explicit scalars + cipCount=0 + legacyAbsent → OFF",
			ev: WdacEvidence{
				Queryable:             true,
				ActiveCipPolicyCount:  iPtr(0),
				LegacySipolicyPresent: tPtr(false),
			},
			want: WdacModeOff,
		},
		{
			name: "no explicit scalars + cipCount>0 → UNKNOWN (policy evidence present but mode ambiguous)",
			ev: WdacEvidence{
				Queryable:             true,
				ActiveCipPolicyCount:  iPtr(2),
				LegacySipolicyPresent: tPtr(false),
			},
			want: WdacModeUnknown,
		},
		{
			name: "no explicit scalars + cipCount=0 + legacyPresent → UNKNOWN",
			ev: WdacEvidence{
				Queryable:             true,
				ActiveCipPolicyCount:  iPtr(0),
				LegacySipolicyPresent: tPtr(true),
			},
			want: WdacModeUnknown,
		},
		{
			name: "no explicit scalars + cipCount=nil → UNKNOWN (filesystem read failed)",
			ev: WdacEvidence{
				Queryable:             true,
				ActiveCipPolicyCount:  nil,
				LegacySipolicyPresent: tPtr(false),
			},
			want: WdacModeUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveWdacMode(tc.ev)
			if got != tc.want {
				t.Errorf("DeriveWdacMode(%+v) = %q want %q", tc.ev, got, tc.want)
			}
		})
	}
}

// TestAppendProbeErrorCapTruncationMarker — Codex iter-2 #4 absorb.
func TestAppendProbeErrorCapTruncationMarker(t *testing.T) {
	errs := []AppControlProbeError{}
	for i := 0; i < MaxAppControlProbeErrors+5; i++ {
		errs = AppendProbeError(errs, AppControlProbeError{Code: "TEST_FILL"})
	}
	if len(errs) != MaxAppControlProbeErrors {
		t.Fatalf("expected cap to MaxAppControlProbeErrors=%d, got %d", MaxAppControlProbeErrors, len(errs))
	}
	if errs[len(errs)-1].Code != AppControlErrProbeErrorsTruncated {
		t.Errorf("last entry must be PROBE_ERRORS_TRUNCATED sentinel, got %q", errs[len(errs)-1].Code)
	}
	// Earlier entries should still be TEST_FILL (proves the cap-1 errors
	// were preserved, only the LAST slot becomes the marker).
	if errs[0].Code != "TEST_FILL" {
		t.Errorf("first entry should still be TEST_FILL, got %q", errs[0].Code)
	}
}

// TestProbeAppControlNonWindowsStub — runs on Linux CI to lock the
// stable wire shape contract for non-Windows builds. Codex iter-2 #5:
// every key must be present, enums UNKNOWN, nullable evidence nil.
func TestProbeAppControlNonWindowsStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows-tagged probe runs in app_control_windows_test.go")
	}
	res := ProbeAppControl(context.Background(), func() time.Time { return time.Unix(0, 0) })

	if res.SchemaVersion != AppControlSchemaVersion {
		t.Errorf("SchemaVersion %d != AppControlSchemaVersion %d", res.SchemaVersion, AppControlSchemaVersion)
	}
	if res.Supported {
		t.Errorf("non-Windows Supported must be false")
	}
	if res.ProbeComplete {
		t.Errorf("non-Windows ProbeComplete must be false")
	}
	if res.WdacQueryable || res.AppLockerQueryable {
		t.Errorf("non-Windows both facets must be Queryable=false")
	}
	if res.WdacMode != WdacModeUnknown {
		t.Errorf("non-Windows WdacMode must be UNKNOWN, got %q", res.WdacMode)
	}
	if res.AppLockerExeRule != AppLockerUnknown ||
		res.AppLockerDllRule != AppLockerUnknown ||
		res.AppLockerScriptRule != AppLockerUnknown ||
		res.AppLockerMsiRule != AppLockerUnknown ||
		res.AppLockerAppxRule != AppLockerUnknown {
		t.Errorf("non-Windows all AppLocker rules must be UNKNOWN")
	}
	if res.AppLockerAppIdSvcState != ServiceStateUnknown {
		t.Errorf("non-Windows AppIDSvc state must be UNKNOWN")
	}
	if res.AppLockerAppIdSvcStartup != StartupModeUnknown {
		t.Errorf("non-Windows AppIDSvc startup must be UNKNOWN")
	}
	if res.WdacBootEnforcementPresent != nil ||
		res.WdacActiveCipPolicyCount != nil ||
		res.WdacLegacySipolicyPresent != nil ||
		res.WdacMultiPolicyMode != nil ||
		res.AppLockerAppIdSvcPresent != nil {
		t.Errorf("non-Windows pointer evidence fields must be nil")
	}
	if len(res.ProbeErrors) == 0 {
		t.Errorf("non-Windows must emit at least one probe error (NO_EVIDENCE)")
	}
	if res.ProbeErrors[0].Code != AppControlErrNoEvidence {
		t.Errorf("first probe error must be NO_EVIDENCE on non-Windows; got %q", res.ProbeErrors[0].Code)
	}
}

// TestAppControlWireShapeStableKeys — Codex iter-2 #2 absorb.
// `omitempty` was DROPPED from the nullable evidence fields so the
// keys persist with explicit JSON null. This test marshals a result
// with mixed nil evidence and asserts the keys appear in the output.
func TestAppControlWireShapeStableKeys(t *testing.T) {
	res := AppControlResult{
		SchemaVersion:            1,
		Supported:                false,
		ProbeComplete:            false,
		WdacQueryable:            false,
		AppLockerQueryable:       false,
		WdacMode:                 WdacModeUnknown,
		AppLockerExeRule:         AppLockerUnknown,
		AppLockerDllRule:         AppLockerUnknown,
		AppLockerScriptRule:      AppLockerUnknown,
		AppLockerMsiRule:         AppLockerUnknown,
		AppLockerAppxRule:        AppLockerUnknown,
		AppLockerAppIdSvcState:   ServiceStateUnknown,
		AppLockerAppIdSvcStartup: StartupModeUnknown,
		ProbeErrors:              []AppControlProbeError{},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	js := string(b)
	requiredKeys := []string{
		`"wdacBootEnforcementPresent":null`,
		`"wdacActiveCipPolicyCount":null`,
		`"wdacLegacySipolicyPresent":null`,
		`"wdacMultiPolicyMode":null`,
		`"appLockerAppIdSvcPresent":null`,
		`"probeErrors":[]`,
	}
	for _, k := range requiredKeys {
		if !strings.Contains(js, k) {
			t.Errorf("wire JSON missing stable key %s\nfull: %s", k, js)
		}
	}
}

// TestRedactionBoundary — guard against accidental wire-shape widening.
func TestRedactionBoundary(t *testing.T) {
	// Codex 019e83ce iter-1 P0 #1 + iter-2 finalisation:
	// NO file names / GUIDs / hashes / rule lists / publisher
	// signatures / event log content / process enumeration.
	//
	// The wire only carries SchemaVersion + 2 facet enums + 5 AppLocker
	// rule enums + 2 service-state enums + ~5 evidence scalars +
	// probeErrors. New fields must be explicitly added here AND in the
	// backend AdminAppControlSnapshotResponse — drift detector.
	expectedJsonKeys := []string{
		"schemaVersion", "supported", "probeComplete",
		"wdacQueryable", "appLockerQueryable",
		"wdacMode",
		"wdacBootEnforcementPresent", "wdacActiveCipPolicyCount",
		"wdacLegacySipolicyPresent", "wdacMultiPolicyMode",
		"appLockerExeRule", "appLockerDllRule", "appLockerScriptRule",
		"appLockerMsiRule", "appLockerAppxRule",
		"appLockerAppIdSvcState", "appLockerAppIdSvcStartup",
		"appLockerAppIdSvcPresent",
		"probeDurationMs", "probeErrors",
	}
	res := AppControlResult{
		ProbeErrors: []AppControlProbeError{},
	}
	b, _ := json.Marshal(res)
	js := string(b)
	for _, k := range expectedJsonKeys {
		if !strings.Contains(js, `"`+k+`"`) {
			t.Errorf("wire shape missing expected key %q (drift: did you forget to add it OR is contract widening unintentional?)", k)
		}
	}
	// Forbidden substrings — guard against accidental redaction-boundary
	// regressions (e.g. someone adds a file-name or publisher field).
	forbidden := []string{
		"policyName", "policyId", "policyGuid", "policyHash",
		"ruleName", "ruleId", "publisher", "signerThumbprint",
		"commandLine", "processName", "exePath", "filePath",
		"eventLog", "kbId",
	}
	for _, f := range forbidden {
		if strings.Contains(js, `"`+f+`"`) {
			t.Errorf("wire shape contains forbidden key %q (redaction boundary regression)", f)
		}
	}
}
