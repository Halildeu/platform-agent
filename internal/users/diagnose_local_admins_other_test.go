//go:build !windows

package users

import (
	"errors"
	"testing"
)

// On non-Windows hosts DiagnoseLocalAdmins is unsupported (no local SAM), so it
// must return the shared unsupported error and an empty snapshot — never panic.
func TestDiagnoseLocalAdmins_UnsupportedOnNonWindows(t *testing.T) {
	got, err := DiagnoseLocalAdmins()
	if !errors.Is(err, ErrLocalUserListingUnsupported) {
		t.Fatalf("expected ErrLocalUserListingUnsupported, got %v", err)
	}
	if got.MachineDomainSID != "" || len(got.DirectMembers) != 0 || got.EffectiveLocalAdminUserCount != 0 {
		t.Fatalf("expected zero-value diagnostic on unsupported platform, got %+v", got)
	}
}
