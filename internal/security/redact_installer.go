package security

import "regexp"

// AG-027L — Installer log/output redaction policy (Faz 22.5.4).
//
// RedactInstallerString extends RedactSoftwareString with patterns
// specific to silent-installer stdout/stderr capture. AG-027 wires its
// `sanitizeForWire` step here so the wire-safe StdoutTail / StderrTail
// in InstallResult cannot leak the additional credential/token shapes
// that WinGet / MSI / vendor installers commonly print to their logs.
//
// Patterns layered on top of RedactSoftwareString:
//
//   1. URL with embedded userinfo
//      ----------------------------
//      `https://user:pass@host/path` → `https://[REDACTED]@host/path`.
//      Installer logs occasionally echo download URLs verbatim; if the
//      vendor template includes a bearer-in-userinfo shape the secret
//      lands in the log tail.
//
//   2. MSI / installer property assignments with sensitive keys
//      ---------------------------------------------------------
//      Property assignments of the form `KEY=value` (or `KEY="value"`)
//      where KEY matches an allowlist of credential-shaped names —
//      LICENSE, LICENSEKEY, SERIAL, ACTIVATION, ACTIVATIONKEY, APIKEY,
//      APIKEYS, ACCESSTOKEN, REFRESHTOKEN, BEARER, OAUTHTOKEN — are
//      scrubbed to `KEY=[REDACTED]`. The pattern is anchored to a
//      word boundary so it does not match `LICENSES_VALIDATED=1` or
//      similar non-secret booleans that happen to contain `LICENSE`.
//
//   3. Token-bearing query string parameters
//      -------------------------------------
//      `?token=…`, `?api_key=…`, `?access_token=…`, `?refresh_token=…`,
//      `?secret=…`, `?bearer=…` — case-insensitive, both first
//      (`?key=`) and subsequent (`&key=`) parameter positions. The
//      value is captured up to the next `&`, whitespace, or end of
//      string and replaced with `[REDACTED]`.
//
// AG-027L deliberately does NOT scrub:
//
//   - Public-by-design paths like `C:\ProgramData\<vendor>\`,
//     `C:\Program Files\<vendor>\`, or temp dirs. RedactSoftwareString
//     already strips `C:\Users\<account>\` segments (the only path
//     class with intrinsic user identity).
//
//   - Hostnames / computer names that appear bare in installer output.
//     These are operational identifiers, not credentials. If a
//     hostname appears inside a UNC path adjacent to credential bytes
//     the URL-userinfo or property-assignment patterns above catch
//     them.
//
//   - Version strings, build numbers, package IDs. The version-string
//     guard in `piiPatterns` (license-key shape requires exactly five
//     5-char groups, so `1.2.3` is safe) remains the canonical
//     fence-line.

const InstallerRedactedValue = "[REDACTED]"

var installerPatterns = []*regexp.Regexp{
	// URL userinfo. The userinfo segment is whatever sits between
	// `://` and the next `@`, but it must NOT span a `/` because that
	// would let the pattern eat half of a normal URL path.
	regexp.MustCompile(`(?i)(https?://)[^/@\s]+@`),

	// MSI / installer property assignments with credential-shaped
	// names. The KEY allowlist is the union of common WinGet, MSI
	// (Wix / InstallShield) and vendor-specific property names.
	regexp.MustCompile(`(?i)\b(LICENSE(?:KEY)?|SERIAL|ACTIVATION(?:KEY)?|APIKEY|APIKEYS|ACCESSTOKEN|REFRESHTOKEN|BEARER|OAUTHTOKEN)\s*=\s*("[^"]*"|'[^']*'|[^\s&;"]+)`),

	// Token-bearing query parameters. Matches both first and follow-on
	// positions (`?key=` / `&key=`) and consumes the value up to the
	// next `&`, whitespace, or end of string.
	regexp.MustCompile(`(?i)([?&])(token|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|bearer)=([^&\s]+)`),
}

var installerReplacements = []string{
	// Userinfo: keep the scheme + restore the `@`.
	`${1}` + InstallerRedactedValue + `@`,
	// Property assignment: keep the KEY name verbatim.
	`$1=` + InstallerRedactedValue,
	// Query parameter: keep the leading `?`/`&` + the key name.
	`$1$2=` + InstallerRedactedValue,
}

// RedactInstallerString runs the AG-027L installer-specific patterns
// FIRST and then layers the AG-025/AG-026 RedactSoftwareString
// baseline on top.
//
// Order matters and is non-obvious. The baseline email pattern
// (`x@y.z`) would eagerly swallow the userinfo + host of a URL like
// `https://op:secret@cdn.example.com/...` (because `secret@cdn.example.com`
// looks like an email), erasing the hostname AND making it impossible
// for the URL-userinfo pattern to see the credentials at all. Running
// the installer patterns first means the URL-userinfo replacement
// happens while the structural `:` is still in place, the hostname
// survives for operator debuggability, and the secret is masked.
//
// JWT tokens inside a `BEARER=eyJ…` assignment are first scrubbed by
// the MSI-property pattern (which masks the whole RHS), so the
// baseline JWT pattern never sees a Bearer token in installer logs.
// That ordering is also handled by running installer first.
func RedactInstallerString(input string) string {
	if input == "" {
		return input
	}
	out := input
	for i, pattern := range installerPatterns {
		out = pattern.ReplaceAllString(out, installerReplacements[i])
	}
	return RedactSoftwareString(out)
}
