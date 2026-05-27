//go:build !windows

package dpapi

import (
	"context"

	"platform-agent/internal/autoenroll"
)

// Read always returns ErrUnsupportedOS on non-Windows builds. The
// auto-enroll mode requires DPAPI machine scope which is a Windows-only
// primitive; darwin/linux are supported only for compile-time and unit
// coverage of the platform-agnostic parts of the runner.
func (s *Store) Read(_ context.Context) (autoenroll.PersistedConfig, error) {
	return autoenroll.PersistedConfig{}, autoenroll.ErrUnsupportedOS
}

// Write always returns ErrUnsupportedOS on non-Windows builds.
func (s *Store) Write(_ context.Context, _ autoenroll.PersistedConfig) error {
	return autoenroll.ErrUnsupportedOS
}
