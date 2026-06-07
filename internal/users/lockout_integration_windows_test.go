//go:build windows

package users

import (
	"os"
	"testing"
)

// TestLockoutGuardWindowsIntegration exercises the READ-ONLY guard gathering
// (#84: RID guard + local-scope proof + recursive nested-group Administrators
// membership + last-admin lockout facts) against the real local SAM — no
// mutation. Gated by an env var so it never runs in CI; for a live Windows host.
func TestLockoutGuardWindowsIntegration(t *testing.T) {
	if os.Getenv("ENDPOINT_AGENT_LOCAL_USER_GUARD_TEST") != "1" {
		t.Skip("set ENDPOINT_AGENT_LOCAL_USER_GUARD_TEST=1 on a Windows host")
	}

	// 1. Local-scope proof + RID guard: the built-in Administrator must resolve to
	//    a proven-local SAM identity with RID 500, refused by the RID guard.
	id, err := resolveLocalUserIdentity("Administrator")
	if err != nil {
		t.Fatalf("resolveLocalUserIdentity(Administrator): %v", err)
	}
	t.Logf("Administrator SID = %s, RID = %d", id.sidString, id.rid)
	if id.rid != 500 {
		t.Errorf("Administrator RID = %d, want 500", id.rid)
	}
	if err := GuardProtectedRID(id.rid); err == nil {
		t.Errorf("GuardProtectedRID(%d) = nil; want refusal", id.rid)
	}

	// 2. Direct-membership cross-check (diagnostic): must include Administrator.
	direct, err := administratorsMemberSIDStrings()
	if err != nil {
		t.Fatalf("administratorsMemberSIDStrings: %v", err)
	}
	t.Logf("Administrators direct members: %d SIDs", len(direct))
	if _, ok := direct[id.sidString]; !ok {
		t.Errorf("Administrator SID %s not in direct Administrators membership", id.sidString)
	}

	// 3. Recursive flattened effective LOCAL admins (the authoritative path): must
	//    include the built-in Administrator.
	admins, err := adminLocalUserSIDStrings()
	if err != nil {
		t.Fatalf("adminLocalUserSIDStrings: %v", err)
	}
	t.Logf("effective local admins (flattened): %d SIDs", len(admins))
	if _, ok := admins[id.sidString]; !ok {
		t.Errorf("Administrator SID %s not in flattened effective local admins", id.sidString)
	}

	// 4. gatherLockoutFacts for the built-in Administrator → it is a local admin.
	facts, err := gatherLockoutFacts("Administrator", id.sid)
	if err != nil {
		t.Fatalf("gatherLockoutFacts(Administrator): %v", err)
	}
	t.Logf("lockout facts (Administrator): TargetIsLocalAdmin=%v TargetEnabled=%v OtherEnabledLocalAdmins=%d",
		facts.TargetIsLocalAdmin, facts.TargetEnabled, facts.OtherEnabledLocalAdmins)
	if !facts.TargetIsLocalAdmin {
		t.Error("Administrator TargetIsLocalAdmin=false; want true")
	}

	// 5. Optional: log facts for a named target (read-only).
	if name := os.Getenv("ENDPOINT_AGENT_LOCAL_USER_TEST_NAME"); name != "" {
		if sid, e := localAccountSID(name); e == nil {
			if f, e2 := gatherLockoutFacts(name, sid); e2 == nil {
				t.Logf("lockout facts (%s): TargetIsLocalAdmin=%v TargetEnabled=%v OtherEnabledLocalAdmins=%d",
					name, f.TargetIsLocalAdmin, f.TargetEnabled, f.OtherEnabledLocalAdmins)
			} else {
				t.Logf("gatherLockoutFacts(%s): %v", name, e2)
			}
		} else {
			t.Logf("localAccountSID(%s): %v", name, e)
		}
	}

	// 6. Optional #84 residual #2 acceptance: a user that is an admin ONLY via a
	//    nested local group (a member of a custom local group that is itself a
	//    member of Administrators) MUST appear in the recursively-flattened
	//    effective-admin set — and is expected NOT to be a direct member, proving
	//    the recursion catches what direct/indirect enumeration misses.
	if name := os.Getenv("ENDPOINT_AGENT_LOCAL_USER_INDIRECT_ADMIN_TEST_NAME"); name != "" {
		sid, e := localAccountSID(name)
		if e != nil {
			t.Fatalf("localAccountSID(%s): %v", name, e)
		}
		_, inFlattened := admins[sid.String()]
		_, inDirect := direct[sid.String()]
		t.Logf("nested-group admin %q: SID=%s inFlattened=%v inDirect=%v", name, sid.String(), inFlattened, inDirect)
		if !inFlattened {
			t.Errorf("nested-group admin %q (SID %s) not in flattened effective admins; recursion failed", name, sid.String())
		}
		if inDirect {
			t.Logf("note: %q is ALSO a direct member; pick a purely-nested account to fully exercise the recursion", name)
		}
	}
}
