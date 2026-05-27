//go:build !windows

package software

import "time"

// Collect on non-Windows builds returns a clearly-labelled empty
// snapshot rather than an error: COLLECT_INVENTORY runs on every
// platform and we want it to succeed with "no software inventory on
// this OS" rather than fail the whole command. The reason string is
// stable so callers can branch on it.
func Collect(now time.Time, opts CollectOptions) SoftwareSnapshot {
	return SoftwareSnapshot{
		Supported:     false,
		Reason:        "unsupported_os",
		SchemaVersion: SchemaVersion,
		AppCount:      0,
		CollectedAt:   now.UTC(),
	}
}
