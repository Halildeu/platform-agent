//go:build !windows

package screenview

import "platform-agent/internal/remotebridge/dataplane"

func IndicatorLossAcceptanceHostPreflight(protectedMode string) error {
	if !AcceptanceModeEnabled() {
		return ErrAcceptanceModeDisabled
	}
	if protectedMode != acceptanceModeTest {
		return ErrAcceptanceProtectedMode
	}
	return dataplane.ErrBannerUnsupported
}

// TriggerIndicatorLossAcceptance preserves fail-closed build parity. Even with
// valid test authorization there is no Win32 banner to target off Windows.
func TriggerIndicatorLossAcceptance(sessionID, maintenanceToken, expectedTokenHash, protectedMode string) error {
	return triggerIndicatorLossAcceptance(sessionID, maintenanceToken, expectedTokenHash, protectedMode, acceptanceTriggerDeps{
		isElevated: func() bool { return true },
		trigger:    dataplane.TriggerIndicatorLoss,
	})
}
