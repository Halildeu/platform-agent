package security

import "regexp"

// PII redaction patterns for free-form strings that originate from
// untrusted sources — DisplayName / Publisher / InstallSource / probe
// error strings collected by the software inventory (AG-025) and the
// WinGet readiness probe (AG-026). These complement, but do not
// replace, RedactText (which targets structured key=value secrets):
// these patterns scan and replace inline PII fragments that show up in
// human-readable text, not assignment syntax.
//
// Replacement is a literal "[REDACTED]" sentinel rather than the
// <redacted> token used by RedactText so a caller (or a log scrubber)
// can tell the two paths apart when auditing.
//
// HIGH-3 background: registry data is operator-trusted but
// uninstall-string ergonomics make it easy to embed user paths,
// license keys, vendor JWT-style tokens, even unsalted email/UPN of
// the installer account. Treating registry text as untrusted is a
// cheap defence and stops accidental leakage if the agent ever
// surfaces full uninstall strings on a privileged code path.
const PIIRedactedValue = "[REDACTED]"

var piiPatterns = []*regexp.Regexp{
	// JWT-shaped tokens (three base64url chunks separated by dots).
	// Match conservatively (header ".") so we don't blow away dotted
	// version strings like "1.7.10861".
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`),
	// password=…  /  pwd=…  /  pass=…  in query-string or env style.
	// Captures both quoted and bare values up to whitespace or & ; ".
	regexp.MustCompile(`(?i)\b(password|pwd|pass)\s*[=:]\s*("[^"]*"|'[^']*'|[^\s&;"]+)`),
	// Email / UPN. Trailing TLD ≥2 letters keeps us off filenames like
	// "v1.2-rc.exe".
	regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`),
	// Full domain SIDs. The RID is *not* stripped — sub-authorities are
	// the sensitive part — but we keep the canonical "S-1-5-21-REDACTED"
	// shape so the value is still recognisable as a SID after redaction.
	regexp.MustCompile(`S-1-5-21-\d+-\d+-\d+-\d+`),
	// User profile path. Replaces only the username segment so the rest
	// of the path stays useful for debugging ("C:\Users\[REDACTED]\…").
	// Case-insensitive on the drive letter to cover %SystemDrive% drift.
	regexp.MustCompile(`(?i)([A-Z]:\\Users\\)[^\\/:*?"<>|]+`),
	// Product-key-shaped strings: five 5-char groups separated by
	// hyphens (Windows / Office style). Tightened to mixed
	// alphanumerics to avoid clobbering version triplets.
	regexp.MustCompile(`\b[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b`),
}

// "S-1-5-21-REDACTED" preserves the SID shape while still replacing
// every sub-authority. The Users-path pattern uses a back-reference so
// the drive prefix survives the substitution.
var piiReplacements = []string{
	PIIRedactedValue,
	`$1=` + PIIRedactedValue,
	PIIRedactedValue,
	`S-1-5-21-REDACTED`,
	`${1}` + PIIRedactedValue,
	PIIRedactedValue,
}

// RedactSoftwareString scrubs free-form text that may have been
// collected from the registry, an installer manifest, or a probe error
// message before it lands in a wire payload or a log line. Callers do
// not need to know the input shape: the function is a no-op on strings
// that don't match any pattern.
//
// Order matters — the JWT pattern runs first so it doesn't get
// shadowed by the password=… pattern when a Bearer token is embedded
// in a query string.
func RedactSoftwareString(input string) string {
	if input == "" {
		return input
	}
	out := input
	for i, pattern := range piiPatterns {
		out = pattern.ReplaceAllString(out, piiReplacements[i])
	}
	return out
}
