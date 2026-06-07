package users

import "testing"

func TestGuardReservedUsername_DeniesReservedAndSID(t *testing.T) {
	denied := []string{
		"Administrator", "administrator", "ADMINISTRATOR", "  Administrator  ",
		"Guest", "DefaultAccount", "WDAGUtilityAccount", "DefaultUser0",
		"krbtgt", "SYSTEM", "LocalSystem", "NetworkService", "LocalService",
		"S-1-5-21-1004336348-1177238915-682003330-512",
		"s-1-5-18",
		"", "   ",
	}
	for _, name := range denied {
		if err := GuardReservedUsername(name); err == nil {
			t.Errorf("GuardReservedUsername(%q) = nil; want refusal", name)
		}
	}
}

func TestGuardProtectedRID(t *testing.T) {
	for _, rid := range []uint32{500, 501, 502, 503, 504} {
		if err := GuardProtectedRID(rid); err == nil {
			t.Errorf("GuardProtectedRID(%d) = nil; want refusal (reserved built-in RID)", rid)
		}
	}
	for _, rid := range []uint32{499, 505, 512, 1000, 1001, 1234, 0} {
		if err := GuardProtectedRID(rid); err != nil {
			t.Errorf("GuardProtectedRID(%d) = %v; want nil (normal RID)", rid, err)
		}
	}
}

func TestGuardReservedUsername_AllowsNormalAccounts(t *testing.T) {
	allowed := []string{
		"alice", "bob.smith", "svc-backup", "operator1", "jdoe",
		"Administrator2", "guest-user", "systemd-user", "localadmin",
	}
	for _, name := range allowed {
		if err := GuardReservedUsername(name); err != nil {
			t.Errorf("GuardReservedUsername(%q) = %v; want nil (normal account)", name, err)
		}
	}
}
