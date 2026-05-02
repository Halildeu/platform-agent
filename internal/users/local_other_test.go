//go:build !windows

package users

import (
	"errors"
	"testing"
)

func TestListLocalUnsupportedOutsideWindows(t *testing.T) {
	_, err := ListLocal()
	if !errors.Is(err, ErrLocalUserListingUnsupported) {
		t.Fatalf("err = %v, want ErrLocalUserListingUnsupported", err)
	}
}
