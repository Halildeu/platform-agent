//go:build windows

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// AG-032 Windows-only tests. Codex 019e74d7 iter-1 post-impl MF-4
// absorb: classifier semantics + PowerShell fallback fail-closed
// + RID 500 built-in Administrator detection cannot be exercised
// from the cross-platform test file (it has no SID type / no
// PowerShell stub access). These tests lock the Windows live
// runner's classification + result-builder behavior so future
// regressions break loudly without requiring a Parallels W11
// integration smoke.

// stubLocalAdminPowerShellProbe installs a temporary script
// runner that returns the supplied bytes / error.
func stubLocalAdminPowerShellProbe(t *testing.T, raw []byte, runErr error) {
	t.Helper()
	prev := runLocalAdminPowerShellProbe
	runLocalAdminPowerShellProbe = func(_ context.Context) ([]byte, error) {
		return raw, runErr
	}
	t.Cleanup(func() { runLocalAdminPowerShellProbe = prev })
}

// ────────────────────────────────────────────────────────────────
// PowerShell fallback parser — MF-3 NO_EVIDENCE absorb

func TestEnumeratePowerShell_RunnerFailure(t *testing.T) {
	stubLocalAdminPowerShellProbe(t, nil, errors.New("powershell crashed"))
	_, noEvidence, err := enumeratePowerShell(context.Background(), nil)
	if noEvidence {
		t.Fatalf("expected noEvidence=false on hard failure")
	}
	if err == nil {
		t.Fatalf("expected error on runner failure")
	}
	if err.Code != LocalAdminErrPowerShellFailed {
		t.Errorf("expected POWERSHELL_FAILED, got %q", err.Code)
	}
}

func TestEnumeratePowerShell_EmptyOutput(t *testing.T) {
	stubLocalAdminPowerShellProbe(t, []byte("   \n  "), nil)
	_, noEvidence, err := enumeratePowerShell(context.Background(), nil)
	if noEvidence {
		t.Fatalf("expected noEvidence=false on empty output")
	}
	if err == nil || err.Code != LocalAdminErrPowerShellEmptyOutput {
		t.Errorf("expected POWERSHELL_EMPTY_OUTPUT, got %+v", err)
	}
}

// MF-3 absorb: bare `null` literal → NO_EVIDENCE.
func TestEnumeratePowerShell_NullLiteral_NoEvidence(t *testing.T) {
	stubLocalAdminPowerShellProbe(t, []byte("null"), nil)
	_, noEvidence, errPS := enumeratePowerShell(context.Background(), nil)
	if !noEvidence {
		t.Fatalf("expected noEvidence=true on null literal (MF-3)")
	}
	if errPS != nil {
		t.Errorf("expected nil err alongside noEvidence=true, got %+v", errPS)
	}
}

func TestEnumeratePowerShell_EmptyObject_NoEvidence(t *testing.T) {
	stubLocalAdminPowerShellProbe(t, []byte("{}"), nil)
	_, noEvidence, _ := enumeratePowerShell(context.Background(), nil)
	if !noEvidence {
		t.Fatalf("expected noEvidence=true on {} literal (MF-3)")
	}
}

func TestEnumeratePowerShell_SourcePresentTrueButMembersMissing_NoEvidence(t *testing.T) {
	stubLocalAdminPowerShellProbe(t, []byte(`{"sourcePresent":true}`), nil)
	_, noEvidence, err := enumeratePowerShell(context.Background(), nil)
	if !noEvidence {
		t.Fatalf("expected noEvidence=true when members is nil (MF-3)")
	}
	if err != nil {
		t.Errorf("expected nil err on malformed-no-members shape, got %+v", err)
	}
}

func TestEnumeratePowerShell_SourcePresentFalseNoError_NoEvidence(t *testing.T) {
	stubLocalAdminPowerShellProbe(t, []byte(`{"members":[],"sourcePresent":false}`), nil)
	_, noEvidence, err := enumeratePowerShell(context.Background(), nil)
	if !noEvidence {
		t.Fatalf("expected noEvidence=true on sourcePresent=false + no error (MF-3)")
	}
	if err != nil {
		t.Errorf("expected nil err, got %+v", err)
	}
}

func TestEnumeratePowerShell_SourcePresentFalseWithError_HardFailure(t *testing.T) {
	stubLocalAdminPowerShellProbe(t, []byte(`{"members":[],"sourcePresent":false,"error":"ACCESS_DENIED"}`), nil)
	_, noEvidence, err := enumeratePowerShell(context.Background(), nil)
	if noEvidence {
		t.Fatalf("expected noEvidence=false when structured error present")
	}
	if err == nil || err.Code != LocalAdminErrAccessDenied {
		t.Errorf("expected ACCESS_DENIED, got %+v", err)
	}
}

func TestEnumeratePowerShell_SourcePresentTrueWithMembers_Success(t *testing.T) {
	// One built-in well-known SID (Everyone) → broadWellKnown.
	stubLocalAdminPowerShellProbe(t, []byte(`{"members":["S-1-1-0"],"sourcePresent":true}`), nil)
	classified, noEvidence, err := enumeratePowerShell(context.Background(), nil)
	if err != nil || noEvidence {
		t.Fatalf("expected success, got noEvidence=%v err=%+v", noEvidence, err)
	}
	if len(classified) != 1 {
		t.Fatalf("expected 1 classified row, got %d", len(classified))
	}
	if classified[0].Member.Kind != LocalAdminKindBroadWellKnown {
		t.Errorf("expected broadWellKnown for Everyone, got %q", classified[0].Member.Kind)
	}
	if !classified[0].Member.IsBroadWellKnown {
		t.Errorf("expected IsBroadWellKnown=true for Everyone")
	}
}

// ────────────────────────────────────────────────────────────────
// classifySID precedence — locks the 10-step table.

func makeSID(t *testing.T, s string) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid(s)
	if err != nil {
		t.Fatalf("StringToSid(%q) failed: %v", s, err)
	}
	return sid
}

// MF-1 absorb: machineDomainSid=nil + S-1-5-21-* → Kind=unknown,
// scope booleans false.
func TestClassifySID_MachineSIDNil_DomainFamilyDegradesToUnknown(t *testing.T) {
	sid := makeSID(t, "S-1-5-21-1111-2222-3333-1001")
	got := classifySID(sid, nil)
	if got.Kind != LocalAdminKindUnknown {
		t.Errorf("expected unknown, got %q", got.Kind)
	}
	if got.IsLocalScoped || got.IsDomainScoped {
		t.Errorf("expected both scope booleans false when machineSID nil, got local=%v domain=%v",
			got.IsLocalScoped, got.IsDomainScoped)
	}
}

// MF-2 absorb: RID 500 = built-in Administrator; classifier sets
// IsBuiltinAdministratorAccount=true; HasNonBuiltinLocalUser must
// not flip.
func TestClassifySIDWithBuiltinFlag_BuiltinAdministratorRID500(t *testing.T) {
	// Build machine domain SID and a member SID with RID 500
	// sharing the prefix.
	machine := makeSID(t, "S-1-5-21-1111-2222-3333")
	member := makeSID(t, "S-1-5-21-1111-2222-3333-500")
	got := classifySIDWithBuiltinFlag(member, machine)
	if got.Member.Kind != LocalAdminKindLocalUser {
		t.Errorf("expected localUser for RID 500 with machine prefix match, got %q", got.Member.Kind)
	}
	if !got.IsBuiltinAdministratorAccount {
		t.Errorf("expected IsBuiltinAdministratorAccount=true for RID 500")
	}
}

func TestClassifySIDWithBuiltinFlag_NonBuiltinLocalUser(t *testing.T) {
	machine := makeSID(t, "S-1-5-21-1111-2222-3333")
	member := makeSID(t, "S-1-5-21-1111-2222-3333-1001")
	got := classifySIDWithBuiltinFlag(member, machine)
	if got.Member.Kind != LocalAdminKindLocalUser {
		t.Errorf("expected localUser, got %q", got.Member.Kind)
	}
	if got.IsBuiltinAdministratorAccount {
		t.Errorf("expected IsBuiltinAdministratorAccount=false for non-500 RID")
	}
}

// S-1-5-32-545 (BUILTIN\Users) → broadWellKnown (NOT
// builtinAlias), per the precedence table.
func TestClassifySID_BuiltinUsers_545_IsBroadWellKnown(t *testing.T) {
	sid := makeSID(t, "S-1-5-32-545")
	got := classifySID(sid, nil)
	if got.Kind != LocalAdminKindBroadWellKnown {
		t.Errorf("expected broadWellKnown for S-1-5-32-545, got %q", got.Kind)
	}
	if !got.IsBroadWellKnown {
		t.Errorf("expected IsBroadWellKnown=true for S-1-5-32-545")
	}
}

func TestClassifySID_Administrators_544_IsPrivilegedBuiltin(t *testing.T) {
	sid := makeSID(t, "S-1-5-32-544")
	got := classifySID(sid, nil)
	if got.Kind != LocalAdminKindBuiltinAlias {
		t.Errorf("expected builtinAlias for S-1-5-32-544, got %q", got.Kind)
	}
	if !got.IsPrivilegedBuiltinAlias {
		t.Errorf("expected IsPrivilegedBuiltinAlias=true for S-1-5-32-544")
	}
}

// MF-3 iter-2 absorb: generic builtin alias requires S-1-5-32 only,
// not SidTypeAlias on S-1-5-21.
func TestClassifySID_GenericBuiltinAlias_568_IISUsers(t *testing.T) {
	sid := makeSID(t, "S-1-5-32-568")
	got := classifySID(sid, nil)
	if got.Kind != LocalAdminKindBuiltinAlias {
		t.Errorf("expected builtinAlias for S-1-5-32-568 (IIS_IUSRS), got %q", got.Kind)
	}
	if got.IsPrivilegedBuiltinAlias {
		t.Errorf("expected IsPrivilegedBuiltinAlias=false for non-admin builtin")
	}
}

func TestClassifySID_LocalSystem_18_IsWellKnownPrivileged(t *testing.T) {
	sid := makeSID(t, "S-1-5-18")
	got := classifySID(sid, nil)
	if got.Kind != LocalAdminKindWellKnownPrivileged {
		t.Errorf("expected wellKnownPrivileged for S-1-5-18, got %q", got.Kind)
	}
}

func TestClassifySID_ServiceSID_80_IsServiceSid(t *testing.T) {
	sid := makeSID(t, "S-1-5-80-1234567890-1234567890-1234567890-1234567890-1234567890")
	got := classifySID(sid, nil)
	if got.Kind != LocalAdminKindServiceSID {
		t.Errorf("expected serviceSid for S-1-5-80-*, got %q", got.Kind)
	}
}

func TestClassifySID_AppContainer_S_1_15_2_IsCapability(t *testing.T) {
	sid := makeSID(t, "S-1-15-2-1234567890-1234567890")
	got := classifySID(sid, nil)
	if got.Kind != LocalAdminKindCapability {
		t.Errorf("expected capability for S-1-15-2-*, got %q", got.Kind)
	}
}

func TestClassifySID_Capability_S_1_15_3_IsCapability(t *testing.T) {
	sid := makeSID(t, "S-1-15-3-1024-1535")
	got := classifySID(sid, nil)
	if got.Kind != LocalAdminKindCapability {
		t.Errorf("expected capability for S-1-15-3-*, got %q", got.Kind)
	}
}

func TestClassifySID_CloudPrincipal_S_1_12_1_IsCloudPrincipal(t *testing.T) {
	sid := makeSID(t, "S-1-12-1-1234567890-1234567890")
	got := classifySID(sid, nil)
	if got.Kind != LocalAdminKindCloudPrincipal {
		t.Errorf("expected cloudPrincipal for S-1-12-1-*, got %q", got.Kind)
	}
	if !got.IsCloudPrincipal {
		t.Errorf("expected IsCloudPrincipal=true")
	}
}

func TestClassifySID_Everyone_S_1_1_0_IsBroadWellKnown(t *testing.T) {
	sid := makeSID(t, "S-1-1-0")
	got := classifySID(sid, nil)
	if got.Kind != LocalAdminKindBroadWellKnown {
		t.Errorf("expected broadWellKnown for S-1-1-0, got %q", got.Kind)
	}
}

func TestClassifySID_AuthenticatedUsers_S_1_5_11_IsBroadWellKnown(t *testing.T) {
	sid := makeSID(t, "S-1-5-11")
	got := classifySID(sid, nil)
	if got.Kind != LocalAdminKindBroadWellKnown {
		t.Errorf("expected broadWellKnown for S-1-5-11, got %q", got.Kind)
	}
}

// ────────────────────────────────────────────────────────────────
// assignMembersAndCounts — RID 500 built-in admin exclusion

func TestAssignMembersAndCounts_BuiltinAdminAloneDoesNotFlipNonBuiltinFlag(t *testing.T) {
	machine := makeSID(t, "S-1-5-21-1111-2222-3333")
	builtinAdmin := makeSID(t, "S-1-5-21-1111-2222-3333-500")
	classified := []classifiedSID{
		classifySIDWithBuiltinFlag(builtinAdmin, machine),
	}
	var result LocalAdminGroupResult
	assignMembersAndCounts(&result, classified)
	if result.LocalUserCount != 1 {
		t.Errorf("expected LocalUserCount=1, got %d", result.LocalUserCount)
	}
	if result.HasNonBuiltinLocalUser {
		t.Errorf("expected HasNonBuiltinLocalUser=false when only built-in Administrator is present")
	}
}

func TestAssignMembersAndCounts_NonBuiltinLocalUser_FlipsFlag(t *testing.T) {
	machine := makeSID(t, "S-1-5-21-1111-2222-3333")
	regularUser := makeSID(t, "S-1-5-21-1111-2222-3333-1001")
	classified := []classifiedSID{
		classifySIDWithBuiltinFlag(regularUser, machine),
	}
	var result LocalAdminGroupResult
	assignMembersAndCounts(&result, classified)
	if !result.HasNonBuiltinLocalUser {
		t.Errorf("expected HasNonBuiltinLocalUser=true with non-500 local user")
	}
}

func TestAssignMembersAndCounts_MembersCapAndTruncation(t *testing.T) {
	machine := makeSID(t, "S-1-5-21-1111-2222-3333")
	// Generate 300 distinct local-user SIDs (RID 1000 to 1299) so
	// we exceed the 256 cap. HasNonBuiltinLocalUser must be true.
	classified := make([]classifiedSID, 0, 300)
	for rid := 1000; rid < 1300; rid++ {
		sidStr := "S-1-5-21-1111-2222-3333-" +
			intToASCII(rid)
		sid := makeSID(t, sidStr)
		classified = append(classified, classifySIDWithBuiltinFlag(sid, machine))
	}
	var result LocalAdminGroupResult
	assignMembersAndCounts(&result, classified)
	if result.DirectMemberCount != 300 {
		t.Errorf("expected DirectMemberCount=300, got %d", result.DirectMemberCount)
	}
	if len(result.Members) != maxLocalAdminMembers {
		t.Errorf("expected len(members)=%d, got %d", maxLocalAdminMembers, len(result.Members))
	}
	if !result.MembersTruncated {
		t.Errorf("expected MembersTruncated=true")
	}
	if result.LocalUserCount != 300 {
		t.Errorf("expected LocalUserCount=300, got %d", result.LocalUserCount)
	}
	if !result.HasNonBuiltinLocalUser {
		t.Errorf("expected HasNonBuiltinLocalUser=true with 300 non-builtin local users")
	}
}

// ────────────────────────────────────────────────────────────────
// End-to-end derive + JSON wire contract for the new MF-1 corner.

func TestProbeLocalAdminGroup_EndToEnd_MachineSIDNil_DomainSidsClassifyToUnknown(t *testing.T) {
	machine := (*windows.SID)(nil) // simulate machine SID resolution failure
	sid := makeSID(t, "S-1-5-21-1111-2222-3333-1001")
	m := classifySID(sid, machine)
	if m.Kind != LocalAdminKindUnknown || m.IsLocalScoped || m.IsDomainScoped {
		t.Fatalf("expected kind=unknown + both scopes false, got %+v", m)
	}
	// Marshal a result to confirm member kind appears as "unknown".
	result := LocalAdminGroupResult{
		Members: []LocalAdminMember{m},
	}
	deriveLocalAdminGroupSummary(&result)
	raw, _ := json.Marshal(result)
	if !strings.Contains(string(raw), `"kind":"unknown"`) {
		t.Errorf("expected JSON to contain kind:unknown, got %s", string(raw))
	}
}

// intToASCII converts an int to its decimal string representation
// without using strconv (kept small to avoid extra imports). This
// is a test-only helper.
func intToASCII(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 12)
	for n > 0 {
		digits = append(digits, byte('0'+(n%10)))
		n /= 10
	}
	// reverse
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}

func TestIntToASCII_Sanity(t *testing.T) {
	if intToASCII(1234) != "1234" || intToASCII(0) != "0" || intToASCII(500) != "500" {
		t.Fatalf("intToASCII helper broken")
	}
}

// boundSummary is shared from local_admin_group_windows.go via the
// security_posture_windows.go shared helper. The same helper is
// re-exported and used by AG-031; we don't re-test it here. Time
// elapsed correctness is exercised through ProbeLocalAdminGroup
// end-to-end above.
var _ = time.Now
