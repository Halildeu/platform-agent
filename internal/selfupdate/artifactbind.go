package selfupdate

import (
	"strconv"
	"strings"
)

// artifactbind.go — bind the backend-claimed targetVersion to the SIGNED
// artifact's own embedded version (Codex 019e9c36 must-fix #2).
//
// THREAT: a compromised backend cannot forge a signature (the local
// signer-allowlist is the authority), but it CAN take a genuinely
// allowlisted-signed OLDER binary and advertise it under a higher
// targetVersion (e.g. claim 9.9.9 for a 1.0.0 binary). That payload would
// pass the version policy (9.9.9 > current), Authenticode (the old binary is
// really signed), AND the signer allowlist (really our signer) — yet activate
// an old, known-vulnerable build. The no-downgrade / anti-replay gates key off
// payload.TargetVersion, which is backend-controlled, so they cannot close
// this on their own.
//
// FIX: after Authenticode verification, read the binary's OWN embedded version
// (PE ProductVersion/FileVersion — the bytes the publisher signed over) and
// require it to match the payload's targetVersion. The signed version is
// authoritative; the backend claim is only accepted when it agrees with what
// the publisher actually stamped + signed.

// EvaluateArtifactVersionBinding checks that the version stamped into (and
// signed within) the staged binary matches the payload's claimed targetVersion.
//
// peVersion is the raw value read from the binary's version resource (PR1b's
// PEVersionReader); targetVersion is the SemVer the backend payload claimed
// (already shape-validated upstream). Returns an empty ErrorCode on a clean
// bind; ErrCatalogMismatch otherwise (fail-closed — a missing/unreadable/
// divergent stamp is never trusted).
//
// Binding rules (fail-closed):
//   - empty peVersion              => CATALOG_MISMATCH (unsigned/unstamped art.)
//   - peVersion unparseable        => CATALOG_MISMATCH
//   - targetVersion unparseable    => CATALOG_MISMATCH (defense-in-depth; the
//     caller validated shape, but never assume)
//   - a Windows 4-field file version (a.b.c.REV) with a NON-ZERO 4th field
//     carries precision the SemVer target cannot express => CATALOG_MISMATCH
//     (we refuse rather than silently drop the revision)
//   - otherwise the normalized SemVer values must be EXACTLY equal (major,
//     minor, patch, and prerelease identifiers) — build metadata is ignored
//     per SemVer precedence, mirroring Compare().
func EvaluateArtifactVersionBinding(peVersion, targetVersion string) (ErrorCode, string) {
	pe := strings.TrimSpace(peVersion)
	if pe == "" {
		return ErrCatalogMismatch, "binary carries no version stamp to bind against"
	}

	norm, ok := normalizePEVersion(pe)
	if !ok {
		return ErrCatalogMismatch, "binary version stamp is not a bindable version"
	}

	peVer, err := ParseVersion(norm)
	if err != nil {
		return ErrCatalogMismatch, "binary version stamp is not parseable semver"
	}
	tgt, err := ParseVersion(targetVersion)
	if err != nil {
		// The shape gate already required a parseable target; reaching here
		// means a contract drift — fail closed, never bind on an unparseable.
		return ErrCatalogMismatch, "target version is not parseable semver"
	}
	if Compare(peVer, tgt) != 0 {
		return ErrCatalogMismatch, "binary version stamp does not match claimed target version"
	}
	return "", ""
}

// normalizePEVersion maps a Windows version stamp to a SemVer-3 core string,
// fail-closed. It accepts an OPTIONAL leading "v"/whitespace (delegated to
// ParseVersion), a SemVer string verbatim (returned as-is), or a Windows
// 1–4-field numeric "a.b.c[.rev]" file version. A 4th field is tolerated ONLY
// when it is exactly zero (the common "1.2.3.0" build stamp); a non-zero 4th
// field is rejected (ok=false) because the SemVer target cannot represent it
// and silently dropping it would let "1.2.3.7" bind to a "1.2.3" target.
//
// A 1- or 2-field stamp ("1" / "1.2") is zero-extended to 3 fields so a
// publisher that stamps "1.2" still binds to target "1.2.0".
func normalizePEVersion(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	// If it already parses as SemVer (optional leading "v", prerelease, build),
	// use it verbatim — covers a publisher that stamps a real SemVer string.
	if _, err := ParseVersion(s); err == nil {
		return s, true
	}
	// Otherwise handle a Windows 1–4-field numeric file version ("a.b.c[.rev]").
	// Each field is canonicalized through ParseUint so zero-padding ("01" ->
	// "1") binds correctly and an overflowing field fails closed.
	fields := strings.Split(s, ".")
	if len(fields) == 0 || len(fields) > 4 {
		return "", false
	}
	for i, f := range fields {
		n, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return "", false // non-numeric or overflow => not a bindable stamp
		}
		fields[i] = strconv.FormatUint(n, 10)
	}
	if len(fields) == 4 {
		// Tolerate only a zero revision; a real 4th field is precision the
		// SemVer target cannot express, so refuse rather than silently drop it.
		if fields[3] != "0" {
			return "", false
		}
		fields = fields[:3]
	}
	for len(fields) < 3 {
		fields = append(fields, "0")
	}
	candidate := strings.Join(fields, ".")
	if _, err := ParseVersion(candidate); err != nil {
		return "", false
	}
	return candidate, true
}
