//go:build !windows

package winget

import "context"

// InstallWinGet on non-Windows builds returns
// FinalStatusFailedUnsupportedPlatform. The inventory / command
// wiring relies on this so the cross-platform agent build keeps a
// uniform call shape; the OS gate lives here (and in
// install_winget_windows.go) rather than at every caller site.
//
// FAILED_UNSUPPORTED_PLATFORM is distinct from FAILED_INTERNAL —
// the audit chain shows the operator that the device simply does
// not run Windows, not that a runtime bug occurred.
func InstallWinGet(ctx context.Context, req InstallRequest) InstallResult {
	_ = ctx
	_ = req
	return InstallResult{
		FinalStatus:      FinalStatusFailedUnsupportedPlatform,
		SchemaVersion:    InstallSchemaVersion,
		Supported:        false,
		FailedReasonCode: "platform_not_windows",
	}
}
