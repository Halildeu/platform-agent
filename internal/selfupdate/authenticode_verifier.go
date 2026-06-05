package selfupdate

// AuthenticodeVerifier extracts signature evidence from a staged binary. PR1
// keeps this as an injectable boundary so unit tests can prove orchestration
// without invoking Windows trust APIs; the platform implementation is wired in
// a later slice.
type AuthenticodeVerifier interface {
	VerifyAuthenticode(path string) (AuthenticodeEvidence, ErrorCode, string)
}

// AuthenticodeVerifierFunc adapts a function into an AuthenticodeVerifier.
type AuthenticodeVerifierFunc func(path string) (AuthenticodeEvidence, ErrorCode, string)

func (f AuthenticodeVerifierFunc) VerifyAuthenticode(path string) (AuthenticodeEvidence, ErrorCode, string) {
	return f(path)
}

func fixedAuthenticodeVerifier(evidence AuthenticodeEvidence) AuthenticodeVerifier {
	return AuthenticodeVerifierFunc(func(string) (AuthenticodeEvidence, ErrorCode, string) {
		return evidence, "", ""
	})
}
