//go:build windows

package users

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// TestLockoutGuardWindowsIntegration exercises the READ-ONLY guard gathering
// (#85 RID + #86 last-admin lockout) against the real local SAM — no mutation.
// Gated by an env var so it never runs in CI; intended for a live Windows host.
func TestLockoutGuardWindowsIntegration(t *testing.T) {
	if os.Getenv("ENDPOINT_AGENT_LOCAL_USER_GUARD_TEST") != "1" {
		t.Skip("set ENDPOINT_AGENT_LOCAL_USER_GUARD_TEST=1 on a Windows host")
	}

	// 1. RID guard: the built-in Administrator must resolve to RID 500 and be refused.
	rid, err := localUserRID("Administrator")
	if err != nil {
		t.Fatalf("localUserRID(Administrator): %v", err)
	}
	t.Logf("localUserRID(Administrator) = %d", rid)
	if rid != 500 {
		t.Errorf("Administrator RID = %d, want 500", rid)
	}
	if err := GuardProtectedRID(rid); err == nil {
		t.Errorf("GuardProtectedRID(%d) = nil; want refusal", rid)
	}

	// 2. Administrators membership enumeration must succeed, be non-empty, and
	//    include the built-in Administrator SID.
	members, err := administratorsMemberSIDStrings()
	if err != nil {
		t.Fatalf("administratorsMemberSIDStrings: %v", err)
	}
	t.Logf("Administrators membership: %d SIDs", len(members))
	if len(members) == 0 {
		t.Fatal("Administrators membership empty; enumeration failed")
	}
	adminSid, _, _, err := windows.LookupSID("", "Administrator")
	if err != nil {
		t.Fatalf("LookupSID(Administrator): %v", err)
	}
	if _, ok := members[adminSid.String()]; !ok {
		t.Errorf("Administrator SID %s not in Administrators membership", adminSid.String())
	}

	// 3. gatherLockoutFacts for the built-in Administrator → it is a local admin.
	facts, err := gatherLockoutFacts("Administrator", adminSid)
	if err != nil {
		t.Fatalf("gatherLockoutFacts(Administrator): %v", err)
	}
	t.Logf("lockout facts (Administrator): TargetIsLocalAdmin=%v TargetEnabled=%v OtherEnabledLocalAdmins=%d",
		facts.TargetIsLocalAdmin, facts.TargetEnabled, facts.OtherEnabledLocalAdmins)
	if !facts.TargetIsLocalAdmin {
		t.Error("Administrator TargetIsLocalAdmin=false; want true")
	}

	// 4. If a test target name is provided, log its facts too (read-only).
	if name := os.Getenv("ENDPOINT_AGENT_LOCAL_USER_TEST_NAME"); name != "" {
		if sid, _, _, e := windows.LookupSID("", name); e == nil {
			if f, e2 := gatherLockoutFacts(name, sid); e2 == nil {
				t.Logf("lockout facts (%s): TargetIsLocalAdmin=%v TargetEnabled=%v OtherEnabledLocalAdmins=%d",
					name, f.TargetIsLocalAdmin, f.TargetEnabled, f.OtherEnabledLocalAdmins)
			}
		}
	}
}
