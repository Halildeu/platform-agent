//go:build windows

package screenview

import (
	"golang.org/x/sys/windows"

	"platform-agent/internal/remotebridge/dataplane"
)

func IndicatorLossAcceptanceHostPreflight(protectedMode string) error {
	return acceptanceHostPreflight(protectedMode, func() bool { return windows.GetCurrentProcessToken().IsElevated() })
}

// TriggerIndicatorLossAcceptance closes only the exact session-bound awareness
// banner after the common non-production, maintenance-token, and elevation gates.
func TriggerIndicatorLossAcceptance(sessionID, maintenanceToken, expectedTokenHash, protectedMode string) error {
	return triggerIndicatorLossAcceptance(sessionID, maintenanceToken, expectedTokenHash, protectedMode, acceptanceTriggerDeps{
		isElevated: func() bool { return windows.GetCurrentProcessToken().IsElevated() },
		trigger:    dataplane.TriggerIndicatorLoss,
	})
}
