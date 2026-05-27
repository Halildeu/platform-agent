//go:build !windows

package winget

import "time"

// Detect on non-Windows builds returns an unsupported Readiness with
// every probe flag false. Callers do NOT need to branch on OS family
// before invoking — the inventory wiring relies on this to keep the
// COLLECT_INVENTORY default payload uniform across platforms.
func Detect(now time.Time) Readiness {
	return Readiness{
		Supported:     false,
		SchemaVersion: SchemaVersion,
	}
}
