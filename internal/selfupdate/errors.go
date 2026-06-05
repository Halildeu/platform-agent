// Package selfupdate is the AG-029 signed self-update PURE POLICY CORE
// (Faz 22.5). PR0 scope: contract types + version / URL / signer / tier /
// Authenticode DECISION logic + a bounded error taxonomy, with NO I/O, NO
// binary mutation, and NO command/capability wiring. The verifier+stager
// (PR1), executor wiring (PR2), activation helper (PR3) and backend
// command-create (PR4) build on top of this package.
//
// Security posture (Codex 019e94fd REVISE→AGREE): the backend command
// payload is AUDIT EVIDENCE, never trust authority. The agent's LOCAL
// signer-policy allowlist is the only authority for "may I run this
// binary"; lab-only-evidence self-update is refused unless a LOCAL opt-in
// is present; binary sources come from a backend-resolved trusted release
// catalog, never a freeform admin URL; downgrades/replays are refused
// locally; and activation is a SEPARATE phase that never reports through
// the staging command result. See docs/AG-029-self-update-threat-model.md.
package selfupdate

// ErrorCode is the bounded, wire-stable taxonomy for self-update STAGING
// failures (Codex 019e94fd checklist #8). Activation-phase outcomes use a
// separate ActivationStatus enum (checklist #1) and are NOT represented
// here — staging code can never observe an activation outcome.
//
// The set is closed: TestErrorCodeSetStable pins it so a rename/removal is
// a deliberate, reviewed contract change.
type ErrorCode string

const (
	// Policy refusals (fail-closed BEFORE any download/mutation).
	ErrUnsupportedPlatform ErrorCode = "POLICY_UNSUPPORTED_PLATFORM"
	ErrLabTierRefused      ErrorCode = "POLICY_LAB_TIER_REFUSED"
	ErrVersionDowngrade    ErrorCode = "POLICY_VERSION_DOWNGRADE"
	ErrVersionReplay       ErrorCode = "POLICY_VERSION_REPLAY"
	// ErrVersionUnparseable — PR0 addition to Codex's starting taxonomy:
	// an unparseable current/target/maxSeen version fails closed rather
	// than being treated as "0" (which would silently allow updates).
	ErrVersionUnparseable ErrorCode = "POLICY_VERSION_UNPARSEABLE"
	ErrURLRejected        ErrorCode = "POLICY_URL_REJECTED"

	// Download / integrity failures (PR1 surfaces these; PR0 defines them).
	ErrDownloadFailed   ErrorCode = "DOWNLOAD_FAILED"
	ErrDownloadTooLarge ErrorCode = "DOWNLOAD_TOO_LARGE"
	ErrHashMismatch     ErrorCode = "HASH_MISMATCH"
	ErrSignatureInvalid ErrorCode = "SIGNATURE_INVALID"
	ErrSignerNotAllowed ErrorCode = "SIGNER_NOT_ALLOWED"
	ErrCatalogMismatch  ErrorCode = "CATALOG_MISMATCH"

	// Pre-activation preflight / staging I/O failures.
	ErrCredentialPreflight ErrorCode = "CREDENTIAL_PREFLIGHT_FAILED"
	ErrStagingIO           ErrorCode = "STAGING_IO_FAILED"
	ErrActivationPlanWrite ErrorCode = "ACTIVATION_PLAN_WRITE_FAILED"
)

// allErrorCodes is the canonical ordered set used by the stability test and
// by IsKnownErrorCode. Keep in sync with the constants above.
var allErrorCodes = []ErrorCode{
	ErrUnsupportedPlatform,
	ErrLabTierRefused,
	ErrVersionDowngrade,
	ErrVersionReplay,
	ErrVersionUnparseable,
	ErrURLRejected,
	ErrDownloadFailed,
	ErrDownloadTooLarge,
	ErrHashMismatch,
	ErrSignatureInvalid,
	ErrSignerNotAllowed,
	ErrCatalogMismatch,
	ErrCredentialPreflight,
	ErrStagingIO,
	ErrActivationPlanWrite,
}

// AllErrorCodes returns a copy of the bounded taxonomy (stable order).
func AllErrorCodes() []ErrorCode {
	out := make([]ErrorCode, len(allErrorCodes))
	copy(out, allErrorCodes)
	return out
}

// IsKnownErrorCode reports whether code is in the bounded taxonomy. The
// backend strict-allowlist mirror can reject any code not in this set
// (defense-in-depth against future regressions).
func IsKnownErrorCode(code ErrorCode) bool {
	for _, c := range allErrorCodes {
		if c == code {
			return true
		}
	}
	return false
}
