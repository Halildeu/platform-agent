//go:build !windows

package dataplane

import (
	"context"
	"errors"
	"net"
	"time"
)

// ErrEmptyUserSID mirrors the windows error for build-tag parity.
var ErrEmptyUserSID = errors.New("dataplane: empty user SID for pipe DACL")

var errPipeUnsupported = errors.New("dataplane: secure named-pipe transport is windows-only")

// ActiveSessionUserSID is windows-only.
func ActiveSessionUserSID() (string, error) { return "", errPipeUnsupported }

// ListenSecurePipe is windows-only.
func ListenSecurePipe(_, _ string) (net.Listener, error) { return nil, errPipeUnsupported }

// AcceptAndVerify is windows-only.
func AcceptAndVerify(_ net.Listener, _ []byte, _ time.Duration) (net.Conn, error) {
	return nil, errPipeUnsupported
}

// DialAndHandshake is windows-only.
func DialAndHandshake(_ context.Context, _ string, _ []byte) (net.Conn, error) {
	return nil, errPipeUnsupported
}
