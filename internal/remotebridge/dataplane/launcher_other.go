//go:build !windows

package dataplane

import "errors"

// Build-tag parity stubs: interactive-session launching is Windows-only. Off
// Windows the constructor fails fast (the real launcher lives in
// launcher_windows.go).
var (
	ErrNoInteractiveSession = errors.New("dataplane: interactive-session launch is windows-only")
	ErrUserTokenUnavailable = errors.New("dataplane: interactive-session launch is windows-only")
	ErrPrivilegeMissing     = errors.New("dataplane: interactive-session launch is windows-only")
)

// LaunchedHelper stub.
type LaunchedHelper struct {
	Pid       uint32
	SessionID uint32
}

// Close is a no-op on the stub.
func (h *LaunchedHelper) Close() error { return nil }

// Terminate is a no-op on the stub.
func (h *LaunchedHelper) Terminate() error { return nil }

// LaunchInActiveSession is not supported off Windows.
func LaunchInActiveSession(_ string, _ ...string) (*LaunchedHelper, error) {
	return nil, ErrNoInteractiveSession
}
