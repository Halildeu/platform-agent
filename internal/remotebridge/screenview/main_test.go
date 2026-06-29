package screenview

import (
	"os"
	"testing"
)

// TestMain lets the screenview test binary double as the active-session VIEW_ONLY
// capture helper: the production factory (NewWindowsProducerFactory) launches
// os.Executable() with the screenview helper flags, so when the gold-proof runs
// this binary as SYSTEM and the factory relaunches it into the interactive
// session, that child must dispatch into the helper (not re-run the suite). Off
// Windows the helper is a no-op (returns false), so the suite runs normally.
func TestMain(m *testing.M) {
	if handled, code := MaybeRunActiveSessionScreenViewHelper(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}
