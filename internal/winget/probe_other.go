//go:build !windows

package winget

import "time"

// Detect on non-Windows builds returns an unsupported Readiness with
// every probe flag false. Callers do NOT need to branch on OS family
// before invoking — the inventory wiring relies on this to keep the
// shape uniform across platforms when the explicit
// CollectOptions{IncludeSoftwareApps: true} path runs. The AG-025H
// lightweight default never calls Detect at all (the inventory code
// short-circuits before reaching this probe).
func Detect(now time.Time) Readiness {
	return Readiness{
		Supported:     false,
		SchemaVersion: SchemaVersion,
	}
}
