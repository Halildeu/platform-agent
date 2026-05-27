//go:build !windows

package certstore

import (
	"context"

	"platform-agent/internal/autoenroll"
)

// LoadEligibleCert always returns ErrUnsupportedOS on non-Windows builds.
// The auto-enroll mode is a Windows-only feature (ADR-0029 Katman 3); the
// stub lets the rest of the agent compile on darwin/linux CI so unit tests
// for jitter, cert selection, persisted config, and the wire client can
// run on every push without a Windows runner.
func (p *Provider) LoadEligibleCert(_ context.Context, _ autoenroll.CertFilter) (autoenroll.CertMaterial, error) {
	return autoenroll.CertMaterial{}, autoenroll.ErrUnsupportedOS
}
