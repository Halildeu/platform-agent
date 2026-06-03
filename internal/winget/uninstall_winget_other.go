//go:build !windows

package winget

import "context"

// UninstallWinGet is the non-Windows stub for the AG-028 managed
// uninstall execution adapter. Non-Windows agents return
// FAILED_UNSUPPORTED_PLATFORM without attempting any mutation; this
// matches AG-027 install_winget_other.go and the
// `RuntimeCapabilities()` advertise: non-Windows builds never advertise
// `UNINSTALL_SOFTWARE`, so the backend approve gate rejects with 422
// before this stub is reachable in normal flow. Defense in depth.
func UninstallWinGet(_ context.Context, _ UninstallRequest) UninstallResult {
	return UninstallResult{
		FinalStatus:      UninstallFinalStatusFailedUnsupportedPlatform,
		FailedReasonCode: "uninstall_unsupported_non_windows",
		SchemaVersion:    UninstallSchemaVersion,
		Supported:        false,
	}
}
