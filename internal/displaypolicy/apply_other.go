//go:build !windows

package displaypolicy

import (
	"context"
	"runtime"
)

// Apply is the non-Windows stub. SET_DISPLAY_POLICY is advertised as a
// capability only on Windows (RuntimeCapabilitiesWithOptions), so the backend
// capability gate normally prevents dispatch here; the stub stays fail-loud for
// a stale queued command, a test fixture, or a manual DB insertion. Mirrors the
// INSTALL_SOFTWARE / UNINSTALL_SOFTWARE non-Windows behaviour.
func Apply(_ context.Context, cmd Command) Result {
	return Result{
		FinalStatus:    StatusFailedUnsupportedOS,
		Operation:      cmd.Operation,
		TargetModel:    targetModel,
		TargetedSIDs:   []string{},
		WrittenValues:  []string{},
		DeletedValues:  []string{},
		EffectiveState: "not applied",
		Summary:        "SET_DISPLAY_POLICY unsupported on " + runtime.GOOS,
	}
}
