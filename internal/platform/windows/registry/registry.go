// Package registry wraps the small subset of the Windows registry the
// auto-enroll runner needs: HKLM reads for the EnrollmentJitterSeconds knob
// and the Mode=auto-enroll service-mode fallback. Non-Windows builds
// silently return defaults (Codex F9 absorb) — production behaviour comes
// only from the windows_registry build.
package registry

// Reader is the autoenroll.RegistryReader interface satisfied by Default.
// Centralising the methods here avoids a circular import between the
// autoenroll package (which owns the abstract interface) and the platform
// package.
type Reader interface {
	ReadInt(key, value string, def int) int
	ReadString(key, value, def string) string
}

// reader is the unexported implementation type; New returns it as the
// Reader interface so the windows/non-windows builds can keep their
// platform-specific receivers without exporting them.
type reader struct{}

// New returns a Reader that talks to the live Windows registry on Windows
// builds and returns defaults silently on non-Windows builds.
func New() Reader { return reader{} }
