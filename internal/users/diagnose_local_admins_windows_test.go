//go:build windows

package users

import (
	"testing"

	"golang.org/x/sys/windows"
)

// sidTypeName must render every SID_NAME_USE the classifier branches on, plus a
// stable fallback for unexpected values, so the diagnostic JSON never carries a
// bare integer the operator can't read.
func TestSidTypeName(t *testing.T) {
	cases := map[uint32]string{
		windows.SidTypeUser:           "user",
		windows.SidTypeGroup:          "group",
		windows.SidTypeAlias:          "alias",
		windows.SidTypeWellKnownGroup: "well-known-group",
		windows.SidTypeDomain:         "domain",
		windows.SidTypeComputer:       "computer",
		windows.SidTypeDeletedAccount: "deleted",
	}
	for use, want := range cases {
		if got := sidTypeName(use); got != want {
			t.Errorf("sidTypeName(%d) = %q, want %q", use, got, want)
		}
	}
	if got := sidTypeName(9999); got != "type-9999" {
		t.Errorf("sidTypeName(9999) = %q, want fallback type-9999", got)
	}
}
