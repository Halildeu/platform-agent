//go:build !windows

package selfupdate

// NewNativeAuthenticodeVerifier returns a fail-closed verifier on non-Windows
// platforms. UPDATE_AGENT is Windows-only; tests and non-Windows callers can
// still exercise orchestration with an injected AuthenticodeVerifier.
func NewNativeAuthenticodeVerifier() AuthenticodeVerifier {
	return AuthenticodeVerifierFunc(func(string) (AuthenticodeEvidence, ErrorCode, string) {
		return AuthenticodeEvidence{}, ErrUnsupportedPlatform, "native authenticode verifier is windows-only"
	})
}
