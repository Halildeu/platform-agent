//go:build !windows

package ptyexec

import (
	"context"
	"errors"
)

// ErrConPTYUnsupported is returned off Windows — the pseudo-console is a Windows facility. Keeps
// RunConPTY callable in OS-agnostic code (build-tag parity with conpty_windows.go), fail-closed.
var ErrConPTYUnsupported = errors.New("ptyexec: conpty not supported on this platform")

// RunConPTY is the not-supported stub off Windows.
func RunConPTY(_ context.Context, _ string, _ string, _ int16, _ int16) ([]byte, uint32, error) {
	return nil, 0, ErrConPTYUnsupported
}
