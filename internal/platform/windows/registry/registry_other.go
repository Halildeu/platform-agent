//go:build !windows

package registry

// ReadInt always returns def on non-Windows builds (Codex F9 absorb:
// non-Windows registry lookups are silently ignored).
func (reader) ReadInt(_, _ string, def int) int { return def }

// ReadString always returns def on non-Windows builds.
func (reader) ReadString(_, _, def string) string { return def }
