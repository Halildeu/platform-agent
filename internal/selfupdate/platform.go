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
// rare RNG failure it FAILS CLOSED (returns an error) rather than a guessable
// sentinel — entropy failure must abort staging, never produce a predictable
// activation handle (Codex 019e9d35).
func randomStagingID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// validStagingID enforces the opaque-handle shape: exactly 32 hex chars (a
// 16-byte random id). It rejects empty, path-ish ("../x"), sentinel, or
// non-hex ids, so neither an RNG fallback nor a bad NewStagingID injection can
// produce a predictable / traversal-prone staged filename or activation handle
// (Codex 019e9d35).
func validStagingID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
