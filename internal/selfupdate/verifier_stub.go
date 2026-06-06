package selfupdate

import "context"

// verifier_stub.go — fail-closed default collaborators. Self-update is
// windows-only (the preflight platform gate refuses other OSes), so on a
// non-windows build there is no Authenticode/PE-version facility; these stubs
// make that explicit and safe. PR2 wiring injects the REAL windows
// implementations (PR1b) on windows and may use these stubs elsewhere.

// StubVerifier always fails Authenticode verification.
type StubVerifier struct{}

// Verify implements AuthenticodeVerifier, failing closed.
func (StubVerifier) Verify(_ context.Context, _ string) (AuthenticodeEvidence, error) {
	return AuthenticodeEvidence{}, errStubVerifier
}

// StubVersionReader always fails to read a version stamp.
type StubVersionReader struct{}

// ReadVersion implements PEVersionReader, failing closed.
func (StubVersionReader) ReadVersion(_ context.Context, _ string) (string, error) {
	return "", errStubVerifier
}
