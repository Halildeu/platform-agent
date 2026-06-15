package dataplane

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Faz 22.6 T-4 slice-3a-ii-B — the production transport for the service↔helper
// frame-IPC protocol (slice-3a-ii-A): a Windows named pipe whose DACL is
// restricted to SYSTEM + the interactive user, carrying the nonce-handshake +
// length-prefixed frames. This file holds the OS-agnostic helpers (pipe name +
// SDDL builder); the winio-backed listen/dial is pipe_windows.go. Disabled-by-
// default; LIVE owner-gated (ADR-0034 §13/D10).

// RandomPipeName returns an unguessable local named-pipe path. Unguessability
// is defence-in-depth on top of the restrictive DACL + the launch-nonce
// handshake (a peer must ALSO hold the nonce to be accepted).
func RandomPipeName() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("dataplane: pipe name: %w", err)
	}
	return `\\.\pipe\dpcap-` + hex.EncodeToString(b[:]), nil
}

// pipeSDDL builds a protected (no-inheritance) DACL granting full access ONLY
// to LocalSystem (SY) and the given user SID — so only the SYSTEM service and
// the interactive user can open the pipe. An empty userSID is rejected by the
// caller (fail-closed) rather than producing a SYSTEM-only or world pipe.
func pipeSDDL(userSID string) string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;" + userSID + ")"
}
