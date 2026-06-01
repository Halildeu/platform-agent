//go:build !windows

package inventory

import (
	"context"
	"time"
)

// Non-Windows AG-041 stub. Returns the stable wire shape with
// supported=false + facet queryable flags false + UNKNOWN enums +
// null evidence + a single NO_EVIDENCE probe error. Mirrors the AG-039
// / AG-040 stub pattern.
//
// Codex 019e83ce iter-2 #5 absorb: the non-Windows stub MUST return
// the FULL stable shape — every key present, enums set to UNKNOWN,
// nullable evidence fields set to nil (rendered as JSON `null` by the
// json package because the pointer fields drop `omitempty`). Consumers
// downstream (backend, web view) rely on this stability for fail-closed
// rendering — they MUST NOT interpret an absent facet as "no
// application control on this device" or as a clean state.
func probeAppControlImpl(_ context.Context, _ func() time.Time) AppControlResult {
	src := AppControlProbeErrSourceWdac
	return AppControlResult{
		Supported:     false,
		ProbeComplete: false,

		WdacQueryable:      false,
		AppLockerQueryable: false,

		WdacMode:                   WdacModeUnknown,
		WdacBootEnforcementPresent: nil,
		WdacActiveCipPolicyCount:   nil,
		WdacLegacySipolicyPresent:  nil,
		WdacMultiPolicyMode:        nil,

		AppLockerExeRule:         AppLockerUnknown,
		AppLockerDllRule:         AppLockerUnknown,
		AppLockerScriptRule:      AppLockerUnknown,
		AppLockerMsiRule:         AppLockerUnknown,
		AppLockerAppxRule:        AppLockerUnknown,
		AppLockerAppIdSvcState:   ServiceStateUnknown,
		AppLockerAppIdSvcStartup: StartupModeUnknown,
		AppLockerAppIdSvcPresent: nil,

		// Single NO_EVIDENCE error pinned to `wdac` source — the
		// non-Windows runtime is unable to attempt ANY WDAC reads, so
		// surfacing the source is honest. Web view will treat the whole
		// snapshot as fail-closed via supported=false.
		ProbeErrors: []AppControlProbeError{
			{
				Code:    AppControlErrNoEvidence,
				Source:  &src,
				Summary: appControlSummaryPtr("Non-Windows runtime; Application Control probe unsupported"),
			},
		},
	}
}
