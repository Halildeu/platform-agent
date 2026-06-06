package selfupdate

import (
	"crypto/rand"
	"encoding/hex"
	"runtime"
)

// platform.go — small cross-platform helpers shared by the stager.

// defaultGOOS returns the real runtime platform. Indirected so a single
// override point exists if the platform string ever needs shaping.
func defaultGOOS() string { return runtime.GOOS }

// randomStagingID mints an opaque, unpredictable correlation handle (16 random
// bytes, hex). It is NOT derived from the URL or version, so a staged filename
// cannot be predicted/targeted by a caller (must-fix #4). On the vanishingly
// rare RNG failure it returns a fixed sentinel rather than a guessable value;
// the staging Commit then fails closed on the duplicate.
func randomStagingID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "rng-unavailable"
	}
	return hex.EncodeToString(b[:])
}
