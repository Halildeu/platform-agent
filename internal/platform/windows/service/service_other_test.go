//go:build !windows

package service

import "testing"

func TestServiceCommandsUnsupportedOutsideWindows(t *testing.T) {
	if err := Install(DefaultOptions()); err == nil {
		t.Fatal("Install returned nil outside Windows")
	}
	status, err := QueryStatus(DefaultOptions())
	if err == nil {
		t.Fatal("QueryStatus returned nil outside Windows")
	}
	if status.State != "unsupported" {
		t.Fatalf("status = %q, want unsupported", status.State)
	}
}
