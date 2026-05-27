//go:build !windows

package certstore

import (
	"context"
	"errors"
	"testing"

	"platform-agent/internal/autoenroll"
)

func TestProvider_NonWindowsReturnsErrUnsupportedOS(t *testing.T) {
	p := New()
	_, err := p.LoadEligibleCert(context.Background(), autoenroll.DefaultCertFilter())
	if !errors.Is(err, autoenroll.ErrUnsupportedOS) {
		t.Fatalf("expected ErrUnsupportedOS, got %v", err)
	}
}
