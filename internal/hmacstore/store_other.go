//go:build !windows

package hmacstore

import "context"

// Read on non-Windows builds returns ErrUnsupportedOS. Codex 019e7314
// constraint #2 — persistence is a Windows-only invariant of the
// production agent; the runner is expected to skip persistence wiring
// entirely on non-Windows.
//
// We do NOT fall back to a plaintext / in-memory store on non-Windows
// because:
//
//   - The macOS/linux agent runs only in dev/test workflows; sourcing a
//     fresh token via env on every restart is acceptable there.
//   - A plaintext-on-disk store on non-Windows would silently weaken
//     the production threat model if production deployment were ever
//     accidentally enabled on a non-Windows host.
func (s *Store) Read(_ context.Context) (Credential, error) {
	return Credential{}, ErrUnsupportedOS
}

// Write on non-Windows builds returns ErrUnsupportedOS. Callers that
// receive this MUST log it as a sentinel and continue with in-memory
// credentials; on the next process restart the agent will require a
// fresh enrollment token from env.
func (s *Store) Write(_ context.Context, _ Credential) error {
	return ErrUnsupportedOS
}
