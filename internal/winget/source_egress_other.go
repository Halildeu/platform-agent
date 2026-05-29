//go:build !windows

package winget

import "time"

// DetectSourceEgress on non-Windows builds returns an unsupported
// SourceEgressReadiness. Callers do NOT need to branch on OS family
// before invoking — the inventory wiring relies on this to keep the
// shape uniform across platforms when the explicit
// CollectOptions{IncludeWinGetEgress: true} path runs. The AG-025H
// lightweight default and the heartbeat / auto-enroll loops never
// call DetectSourceEgress at all.
//
// Returning Supported=false with everything else trivially false /
// zero preserves the wire contract: the backend can store the
// snapshot and surface "this device does not support WinGet
// preflight" instead of treating the absence of the field as a
// failed probe.
func DetectSourceEgress(now time.Time) SourceEgressReadiness {
	_ = now
	return SourceEgressReadiness{
		Supported:     false,
		SchemaVersion: SourceEgressSchemaVersion,
		PackageQuery: PackageQueryResult{
			PackageID: FixedPackageQueryID,
		},
		// AG-026A iter-1 (Codex 019e7164 P0): keep the wire shape
		// uniform across platforms. Backend tolerates `null` for
		// supported=false, but always emitting `[]` keeps the
		// invariant easier to reason about and matches the
		// Windows preflight constructor.
		Egress: emptyEgressSummary(),
	}
}
