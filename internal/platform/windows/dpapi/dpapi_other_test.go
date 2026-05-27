//go:build !windows

package dpapi

import (
	"context"
	"errors"
	"testing"

	"platform-agent/internal/autoenroll"
)

func TestStore_NonWindowsReturnsErrUnsupportedOS(t *testing.T) {
	s := New("/tmp/never-used.dpapi", nil)
	if _, err := s.Read(context.Background()); !errors.Is(err, autoenroll.ErrUnsupportedOS) {
		t.Fatalf("Read non-Windows: got %v, want ErrUnsupportedOS", err)
	}
	if err := s.Write(context.Background(), autoenroll.PersistedConfig{DeviceID: "x"}); !errors.Is(err, autoenroll.ErrUnsupportedOS) {
		t.Fatalf("Write non-Windows: got %v, want ErrUnsupportedOS", err)
	}
}

func TestDefaultPath_NonEmpty(t *testing.T) {
	if DefaultPath() == "" {
		t.Fatal("DefaultPath should return a non-empty string")
	}
}
