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
//      Authority parsing ends at `/`, `?`, or `#` so query/fragment
//      values containing `@` (e.g. `?email=user@example.com`) do
//      not get false-redacted as if they were userinfo. Installer
//      logs occasionally echo download URLs verbatim; if the vendor
//      template includes a bearer-in-userinfo shape the secret lands
//      in the log tail.
//
//   2. MSI / installer property assignments with sensitive keys
//      ---------------------------------------------------------
//      Property assignments of the form `KEY=value` (or `KEY="value"`)
//      where KEY belongs to the credential family — license / serial /
//      activation keys, API / access / refresh / OAuth / auth / ID
//      tokens, client / secret key variants — are scrubbed to
//      `KEY=[REDACTED]`. The allowlist covers bare (`LICENSEKEY`),
//      snake_case (`CLIENT_SECRET`), kebab-case (`client-secret`)
//      and camelCase (`clientSecret`) shapes via `(?:[_-])?` separator
//      variants. Case-insensitive on the KEY, bare + quoted values.
//      The pattern is anchored to a word boundary so it does not
//      match `LICENSES_VALIDATED=1` or similar non-secret booleans
//      that happen to contain a credential-family substring.
//
//   3. Token-bearing query string parameters
//      -------------------------------------
//      Same credential family as #2 — `?token=…`, `?client_secret=…`,
//      `?id_token=…`, `?api-key=…`, `?oauth_token=…`, `?auth-token=…`,
//      `?secret_key=…`, etc. — first (`?key=`) or follow-on (`&key=`)
//      parameter position, value captured up to next `&`, whitespace,
//      or end of string and replaced with `[REDACTED]`.
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
	// `://` and the next `@`, but it must NOT span a `/`, `?`, or
	// `#` — those delimiters end the authority component, so any `@`
	// after them is part of a query value or fragment (e.g.
	// `https://cdn.example.com?email=user@example.com`). Without the
	// `?` and `#` guards the pattern would eagerly redact the
	// hostname AND the value before the `@`, breaking the
	// "scheme + host preserved" invariant documented in
	// COMMAND-CONTRACT.md §11.3a. Codex 019e73de iter-1 must_fix #1.
	regexp.MustCompile(`(?i)(https?://)[^/@\s?#]+@`),

	// MSI / installer property assignments with credential-shaped
	// names. The KEY allowlist covers the common WinGet, MSI
	// (Wix / InstallShield), OAuth and vendor-specific property
	// shapes — bare (LICENSE), snake_case (CLIENT_SECRET), kebab-case
	// (client-secret) and camelCase (clientSecret) variants. KEY
	// allowlist tracks new vendor shapes via PR — silent widening is
	// not safe (false positives on non-credential property names with
	// "SECRET" or "KEY" substrings). Codex 019e73de iter-1 must_fix #2.
	regexp.MustCompile(`(?i)\b(LICENSE(?:KEY)?|SERIAL|ACTIVATION(?:KEY)?|APIKEY|API[_-]?KEY|APIKEYS|ACCESSTOKEN|ACCESS[_-]?TOKEN|REFRESHTOKEN|REFRESH[_-]?TOKEN|BEARER|OAUTHTOKEN|OAUTH[_-]?TOKEN|AUTHTOKEN|AUTH[_-]?TOKEN|CLIENTSECRET|CLIENT[_-]?SECRET|SECRETKEY|SECRET[_-]?KEY|IDTOKEN|ID[_-]?TOKEN)\s*=\s*("[^"]*"|'[^']*'|[^\s&;"]+)`),

	// Token-bearing query parameters. Matches both first and follow-on
	// positions (`?key=` / `&key=`) and consumes the value up to the
	// next `&`, whitespace, or end of string. KEY allowlist mirrors
	// the property-assignment list above (same credential class, same
	// snake/kebab/bare variants), plus the historical short forms
	// (`token`, `secret`, `bearer`). Codex 019e73de iter-1 must_fix #3.
	regexp.MustCompile(`(?i)([?&])(token|secret|bearer|api[_-]?key|access[_-]?token|refresh[_-]?token|oauth[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|id[_-]?token)=([^&\s]+)`),
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
