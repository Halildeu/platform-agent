package inventory

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

// AG-032 — cross-platform tests for the local admin group probe.
// Tests in this file run on every platform (Windows live runner
// has its own //go:build windows test file). They lock the wire
// shape, enum stability, helper invariants, and opt-in / opt-out
// behavior via the test seam.

// ────────────────────────────────────────────────────────────────
// deriveLocalAdminGroupSummary

func TestDeriveLocalAdminGroupSummary_EmptyErrorsProbeComplete(t *testing.T) {
	result := LocalAdminGroupResult{}
	deriveLocalAdminGroupSummary(&result)
	if !result.ProbeComplete {
		t.Fatalf("expected ProbeComplete=true with no errors")
	}
}

func TestDeriveLocalAdminGroupSummary_AnyErrorFlipsProbeComplete(t *testing.T) {
	result := LocalAdminGroupResult{
		ProbeErrors: []LocalAdminProbeError{
			{Source: LocalAdminSourceNetAPI, Code: LocalAdminErrNetAPIFailed},
		},
	}
	deriveLocalAdminGroupSummary(&result)
	if result.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false with probe errors")
	}
}

// MF-2 (iter-4): Members never nil; always serializes as `[]`.
func TestDeriveLocalAdminGroupSummary_MembersNeverNil(t *testing.T) {
	result := LocalAdminGroupResult{Members: nil}
	deriveLocalAdminGroupSummary(&result)
	if result.Members == nil {
		t.Fatalf("expected non-nil Members after derive")
	}
	raw, _ := json.Marshal(result)
	if !strings.Contains(string(raw), `"members":[]`) {
		t.Fatalf("expected JSON to contain members:[], got %s", string(raw))
	}
}

func TestDeriveLocalAdminGroupSummary_RiskFlagsRollUp(t *testing.T) {
	result := LocalAdminGroupResult{
		DomainGroupCount:    1,
		BroadWellKnownCount: 2,
		CloudPrincipalCount: 3,
		LocalUserCount:      4,
	}
	deriveLocalAdminGroupSummary(&result)
	if !result.HasDomainScopedPrincipal {
		t.Errorf("expected HasDomainScopedPrincipal=true")
	}
	if !result.HasBroadWellKnownPrincipal {
		t.Errorf("expected HasBroadWellKnownPrincipal=true")
	}
	if !result.HasCloudPrincipal {
		t.Errorf("expected HasCloudPrincipal=true")
	}
	if !result.HasNonBuiltinLocalUser {
		t.Errorf("expected HasNonBuiltinLocalUser=true when LocalUserCount>0")
	}
}

func TestDeriveLocalAdminGroupSummary_NoLocalUserNoFlag(t *testing.T) {
	result := LocalAdminGroupResult{LocalUserCount: 0}
	deriveLocalAdminGroupSummary(&result)
	if result.HasNonBuiltinLocalUser {
		t.Errorf("expected HasNonBuiltinLocalUser=false when LocalUserCount=0")
	}
}

// ────────────────────────────────────────────────────────────────
// JSON contract — members serializes as [], counts are present,
// no name / SID / RID identifier fields leak.

func TestLocalAdminGroupResult_JSONContract_NoRawIdentifierFields(t *testing.T) {
	// Build a full result with one of every member Kind.
	result := LocalAdminGroupResult{
		SchemaVersion: LocalAdminGroupSchemaVersion,
		Supported:     true,
		Members: []LocalAdminMember{
			{Kind: LocalAdminKindLocalUser, IsLocalScoped: true},
			{Kind: LocalAdminKindDomainGroup, IsDomainScoped: true},
			{Kind: LocalAdminKindBuiltinAlias, IsPrivilegedBuiltinAlias: true},
			{Kind: LocalAdminKindBroadWellKnown, IsBroadWellKnown: true},
			{Kind: LocalAdminKindCloudPrincipal, IsCloudPrincipal: true},
		},
		LocalUserCount:      1,
		DomainGroupCount:    1,
		BuiltinAliasCount:   1,
		BroadWellKnownCount: 1,
		CloudPrincipalCount: 1,
		DirectMemberCount:   5,
		SourceUsed:          LocalAdminSourceNetAPI,
	}
	deriveLocalAdminGroupSummary(&result)
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	s := string(raw)

	// Codex 019e74d7 HARD BOUNDARY: these field names must NEVER
	// appear in the wire payload. Each substring check would
	// catch a regression where a developer accidentally added a
	// name/SID/RID field.
	forbidden := []string{
		`"sid"`, `"SID"`, `"sidString"`, `"sidValue"`,
		`"sidFamily"`, `"SIDFamily"`,
		`"sidRelativeId"`, `"sidRelativeID"`, `"SIDRelativeID"`,
		`"rid"`, `"RID"`,
		`"sidAuthority"`, `"identifierAuthority"`,
		`"domainSid"`, `"DomainSid"`, `"domainSID"`,
		`"name"`, `"accountName"`, `"AccountName"`,
		`"displayName"`, `"DisplayName"`,
		`"description"`, `"principalPath"`, `"principalSource"`,
		`"domain"`, `"domainName"`, `"DomainName"`,
		`"upn"`, `"UPN"`,
	}
	for _, frag := range forbidden {
		if strings.Contains(s, frag) {
			t.Errorf("forbidden identifier field %q leaked to JSON: %s", frag, s)
		}
	}

	// Required structural fields.
	required := []string{
		`"members":[`,
		`"directMemberCount":5`,
		`"localUserCount":1`,
		`"domainGroupCount":1`,
		`"builtinAliasCount":1`,
		`"broadWellKnownCount":1`,
		`"cloudPrincipalCount":1`,
		`"sourceUsed":"netapi"`,
		`"schemaVersion":1`,
		`"kind":"localUser"`,
		`"isLocalScoped":true`,
		`"hasBroadWellKnownPrincipal":true`,
	}
	for _, frag := range required {
		if !strings.Contains(s, frag) {
			t.Errorf("expected required field %q in JSON, got %s", frag, s)
		}
	}
}

func TestLocalAdminGroupResult_JSONContract_EmptyMembersSerializesAsArray(t *testing.T) {
	result := LocalAdminGroupResult{
		SchemaVersion: LocalAdminGroupSchemaVersion,
		Supported:     true,
		SourceUsed:    LocalAdminSourceNone,
	}
	deriveLocalAdminGroupSummary(&result)
	raw, _ := json.Marshal(result)
	s := string(raw)
	if !strings.Contains(s, `"members":[]`) {
		t.Fatalf(`expected "members":[] in JSON output, got %s`, s)
	}
	if strings.Contains(s, `"members":null`) {
		t.Fatalf(`members MUST NOT serialize as null, got %s`, s)
	}
}

// ────────────────────────────────────────────────────────────────
// Source / Error enum stability

func TestLocalAdminProbeSource_Values(t *testing.T) {
	cases := map[LocalAdminProbeSource]string{
		LocalAdminSourceNetAPI:                  "netapi",
		LocalAdminSourcePowerShellLocalAccounts: "powershellLocalAccounts",
		LocalAdminSourceWMIGroupUser:            "wmiGroupUser",
		LocalAdminSourceNone:                    "none",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("LocalAdminProbeSource %q != %q", string(got), want)
		}
	}
}

func TestLocalAdminMemberKind_Values(t *testing.T) {
	wanted := []string{
		"localUser", "localGroup",
		"domainUser", "domainGroup", "domainComputer",
		"builtinAlias",
		"serviceSid",
		"wellKnownPrivileged",
		"broadWellKnown",
		"cloudPrincipal",
		"capability",
		"unknown",
	}
	values := []LocalAdminMemberKind{
		LocalAdminKindLocalUser, LocalAdminKindLocalGroup,
		LocalAdminKindDomainUser, LocalAdminKindDomainGroup, LocalAdminKindDomainComputer,
		LocalAdminKindBuiltinAlias,
		LocalAdminKindServiceSID,
		LocalAdminKindWellKnownPrivileged,
		LocalAdminKindBroadWellKnown,
		LocalAdminKindCloudPrincipal,
		LocalAdminKindCapability,
		LocalAdminKindUnknown,
	}
	for i, kind := range values {
		if string(kind) != wanted[i] {
			t.Errorf("kind %d: got %q, want %q", i, string(kind), wanted[i])
		}
	}
}

func TestLocalAdminProbeError_Codes(t *testing.T) {
	codes := []string{
		LocalAdminErrUnsupportedPlatform,
		LocalAdminErrNetAPIFailed,
		LocalAdminErrNetAPIAccessDenied,
		LocalAdminErrNetAPIGroupNotFound,
		LocalAdminErrPowerShellTimeout,
		LocalAdminErrPowerShellFailed,
		LocalAdminErrPowerShellEmptyOutput,
		LocalAdminErrPowerShellParseError,
		LocalAdminErrCmdletUnavailable,
		LocalAdminErrAccessDenied,
		LocalAdminErrWMIFailed,
		LocalAdminErrWellKnownSIDFailed,
		LocalAdminErrMachineSIDResolutionFailed,
		LocalAdminErrNoEvidence,
	}
	expected := []string{
		"UNSUPPORTED_PLATFORM",
		"NETAPI_FAILED",
		"NETAPI_ACCESS_DENIED",
		"NETAPI_GROUP_NOT_FOUND",
		"POWERSHELL_TIMEOUT",
		"POWERSHELL_FAILED",
		"POWERSHELL_EMPTY_OUTPUT",
		"POWERSHELL_PARSE_ERROR",
		"CMDLET_UNAVAILABLE",
		"ACCESS_DENIED",
		"WMI_FAILED",
		"WELL_KNOWN_SID_FAILED",
		"MACHINE_SID_RESOLUTION_FAILED",
		"NO_EVIDENCE",
	}
	for i, c := range codes {
		if c != expected[i] {
			t.Errorf("code %d: got %q, want %q", i, c, expected[i])
		}
	}
}

// ────────────────────────────────────────────────────────────────
// Non-Windows stub semantics

func TestProbeLocalAdminGroup_NonWindowsStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses the live runner")
	}
	t0 := time.Unix(1700000000, 0)
	calls := 0
	clock := func() time.Time {
		calls++
		return t0.Add(time.Duration(calls-1) * 2 * time.Millisecond)
	}
	got := ProbeLocalAdminGroup(nil, clock)
	if got.Supported {
		t.Fatalf("expected Supported=false on %s", runtime.GOOS)
	}
	if got.ProbeComplete {
		t.Fatalf("expected ProbeComplete=false on stub")
	}
	if got.SchemaVersion != LocalAdminGroupSchemaVersion {
		t.Fatalf("schemaVersion = %d, want %d", got.SchemaVersion, LocalAdminGroupSchemaVersion)
	}
	if got.SourceUsed != LocalAdminSourceNone {
		t.Fatalf("expected SourceUsed=none, got %q", got.SourceUsed)
	}
	if got.MaxMembers != maxLocalAdminMembers {
		t.Fatalf("expected MaxMembers=%d, got %d", maxLocalAdminMembers, got.MaxMembers)
	}
	if got.Members == nil {
		t.Fatalf("expected non-nil Members (empty slice)")
	}
	if len(got.Members) != 0 {
		t.Fatalf("expected empty Members on stub, got %d", len(got.Members))
	}
	if len(got.ProbeErrors) != 1 {
		t.Fatalf("expected exactly 1 probe error, got %d", len(got.ProbeErrors))
	}
	if got.ProbeErrors[0].Code != LocalAdminErrUnsupportedPlatform {
		t.Fatalf("expected code %q, got %q",
			LocalAdminErrUnsupportedPlatform, got.ProbeErrors[0].Code)
	}
	if !strings.Contains(got.ProbeErrors[0].Summary, runtime.GOOS) {
		t.Fatalf("expected summary to mention runtime %q, got %q",
			runtime.GOOS, got.ProbeErrors[0].Summary)
	}
}

// ────────────────────────────────────────────────────────────────
// CollectWithOptions opt-in / opt-out

func TestCollectWithOptions_LocalAdminGroupOptOut(t *testing.T) {
	invoked := false
	restore := withCollectLocalAdminGroupForSnapshot(func(_ time.Time) LocalAdminGroupResult {
		invoked = true
		return LocalAdminGroupResult{}
	})
	defer restore()
	snap := CollectWithOptions("test", time.Unix(1700000000, 0), CollectOptions{})
	if invoked {
		t.Fatalf("local admin group probe must not run when opt-out")
	}
	if snap.LocalAdminGroup != nil {
		t.Fatalf("snapshot.LocalAdminGroup must be nil when opt-out")
	}
}

func TestCollectWithOptions_LocalAdminGroupOptIn(t *testing.T) {
	sentinel := LocalAdminGroupResult{
		SchemaVersion: LocalAdminGroupSchemaVersion,
		Supported:     true,
		ProbeComplete: true,
		SourceUsed:    LocalAdminSourceNetAPI,
	}
	calls := 0
	restore := withCollectLocalAdminGroupForSnapshot(func(_ time.Time) LocalAdminGroupResult {
		calls++
		return sentinel
	})
	defer restore()
	snap := CollectWithOptions("test", time.Unix(1700000000, 0),
		CollectOptions{IncludeLocalAdminGroup: true})
	if calls != 1 {
		t.Fatalf("expected probe invocation count = 1, got %d", calls)
	}
	if snap.LocalAdminGroup == nil {
		t.Fatalf("snapshot.LocalAdminGroup must be set when opt-in")
	}
	if snap.LocalAdminGroup.SchemaVersion != LocalAdminGroupSchemaVersion {
		t.Fatalf("schemaVersion = %d, want %d",
			snap.LocalAdminGroup.SchemaVersion, LocalAdminGroupSchemaVersion)
	}
}

// ────────────────────────────────────────────────────────────────
// helpers

func withCollectLocalAdminGroupForSnapshot(stub func(time.Time) LocalAdminGroupResult) func() {
	prev := collectLocalAdminGroupForSnapshot
	collectLocalAdminGroupForSnapshot = stub
	return func() { collectLocalAdminGroupForSnapshot = prev }
}
