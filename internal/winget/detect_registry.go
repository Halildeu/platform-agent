package winget

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// AG-027 REGISTRY_UNINSTALL detector (Session-0-reliable installed-state).
//
// LIVE evidence (AG-027 7-Zip pilot, PR #41) showed `winget list` cannot
// enumerate installed packages under the SYSTEM Session-0 service context,
// so WINGET_PACKAGE detection is only CONFIRM_ONLY there. The ARP
// (Add/Remove Programs) registry IS readable under Session-0, so a
// REGISTRY_UNINSTALL rule is AUTHORITATIVE: a post-verify miss is a real
// denial. The match/dedupe/ambiguity logic here is cross-platform; the
// only OS-specific seam is the ArpReader (Windows registry enumeration).

// ArpEntry is one sanitized Add/Remove Programs (Uninstall) registry
// entry. The raw UninstallString is intentionally NOT carried — it never
// reaches the wire (Codex 019e7d82 security).
type ArpEntry struct {
	// KeyName is the Uninstall subkey name — an MSI `{GUID}` (product
	// code) or a vendor key. Used for ProductCode matching + as the
	// matched identity surfaced to audit.
	KeyName        string
	DisplayName    string
	DisplayVersion string
	Publisher      string
}

// ArpReader reads machine-scope ARP entries. The Windows impl reads
// HKLM\…\Uninstall + HKLM\WOW6432Node\…\Uninstall; tests inject a fake.
//
// AUTHORITATIVE-detector contract (Codex 019e7d82): an incomplete or
// failed read must NOT look like a clean miss. Enumerate MUST return an
// error if the primary hive cannot be read or the enumeration cap
// truncates the inventory; only a genuinely-absent secondary hive
// (WOW6432Node on 32-bit OS) is skipped silently. Implementations sanitize
// + length-cap the strings they surface and never read UninstallString.
type ArpReader interface {
	// Enumerate returns all machine-scope ARP entries (capped). It errors
	// rather than silently truncating/skipping a failed primary hive.
	Enumerate(ctx context.Context) ([]ArpEntry, error)
	// Lookup resolves a single ARP entry by exact subkey name (the MSI
	// product code). found=false means the key is genuinely absent; a read
	// failure other than not-exist is an error. Cap-immune (direct open).
	Lookup(ctx context.Context, keyName string) (entry ArpEntry, found bool, err error)
}

// ErrRegistryAmbiguous is returned when a REGISTRY_UNINSTALL rule matches
// more than one DISTINCT ARP entry (after 32/64-bit dedupe). The caller
// maps it to INCONCLUSIVE (pre-detect) / FAILED_VERIFICATION (post-verify)
// — never a silent first-match (Codex 019e7d82).
var ErrRegistryAmbiguous = errors.New("registry_uninstall_ambiguous")

// ErrArpEnumTruncated is returned when ARP enumeration hits the cap before
// completing. For an AUTHORITATIVE detector a truncated inventory is unsafe
// (a match or a second distinct match could lie beyond the cap), so it is
// an error, not a partial result (Codex 019e7d82).
var ErrArpEnumTruncated = errors.New("registry_uninstall_enumeration_truncated")

// ProbeViaRegistry answers "is the REGISTRY_UNINSTALL rule satisfied?" by
// matching `rule` against the machine ARP entries.
//
// Match precedence:
//   - ProductCode (MSI `{GUID}`): exact, case-insensitive KeyName match.
//   - else DisplayName (+ Publisher) fallback with the configured modes.
//
// 32/64-bit duplicates of the same (DisplayName, Publisher, DisplayVersion)
// dedupe to one. Multiple DISTINCT matches → ErrRegistryAmbiguous.
func ProbeViaRegistry(ctx context.Context, reader ArpReader, rule DetectionRule) (PreDetectResult, error) {
	if reader == nil {
		return PreDetectResult{}, errors.New("AG-027 registry reader is nil")
	}
	if rule.Type != DetectionRuleTypeRegistryUninstall {
		return PreDetectResult{}, fmt.Errorf("AG-027 ProbeViaRegistry called with rule type %q", rule.Type)
	}
	// ProductCode primary: direct subkey lookup (cap-immune, precise,
	// cleaner errors — Codex 019e7d82). Validation guarantees GUID shape,
	// so the key name cannot inject a nested registry path.
	if pc := strings.TrimSpace(rule.ProductCode); pc != "" {
		entry, found, err := reader.Lookup(ctx, pc)
		if err != nil {
			return PreDetectResult{DetectionMethod: DetectionMethodRegistryUninstall}, err
		}
		if !found {
			return PreDetectResult{Satisfied: false, DetectionMethod: DetectionMethodRegistryUninstall}, nil
		}
		return PreDetectResult{
			Satisfied:        true,
			MatchedPackageID: strings.TrimSpace(entry.KeyName),
			MatchedVersion:   strings.TrimSpace(entry.DisplayVersion),
			DetectionMethod:  DetectionMethodRegistryUninstall,
		}, nil
	}

	// DisplayName(+Publisher) fallback: full enumeration. A failed/truncated
	// read surfaces as an error (never a clean miss for an authoritative
	// detector).
	entries, err := reader.Enumerate(ctx)
	if err != nil {
		return PreDetectResult{DetectionMethod: DetectionMethodRegistryUninstall}, err
	}

	var matches []ArpEntry
	for _, e := range entries {
		if registryEntryMatches(rule, e) {
			matches = append(matches, e)
		}
	}
	deduped := dedupeArp(matches)
	switch len(deduped) {
	case 0:
		return PreDetectResult{Satisfied: false, DetectionMethod: DetectionMethodRegistryUninstall}, nil
	case 1:
		m := deduped[0]
		return PreDetectResult{
			Satisfied:        true,
			MatchedPackageID: strings.TrimSpace(m.KeyName),
			MatchedVersion:   strings.TrimSpace(m.DisplayVersion),
			DetectionMethod:  DetectionMethodRegistryUninstall,
		}, nil
	default:
		return PreDetectResult{DetectionMethod: DetectionMethodRegistryUninstall}, ErrRegistryAmbiguous
	}
}

// registryEntryMatches applies the DisplayName(+Publisher) fallback.
// ProductCode is handled by a direct Lookup before enumeration, so it is
// not considered here.
func registryEntryMatches(rule DetectionRule, e ArpEntry) bool {
	if !matchString(rule.DisplayNameMatch, rule.DisplayName, e.DisplayName) {
		return false
	}
	if strings.TrimSpace(rule.Publisher) != "" {
		return matchString(rule.PublisherMatch, rule.Publisher, e.Publisher)
	}
	// Publisher omitted: validation only permits this with
	// AllowPublisherMissing + EXACT displayName, so the name match suffices.
	return true
}

// dedupeArp collapses identical (DisplayName, Publisher, DisplayVersion)
// entries — the common 32/64-bit double-registration case.
func dedupeArp(in []ArpEntry) []ArpEntry {
	seen := make(map[string]bool, len(in))
	out := make([]ArpEntry, 0, len(in))
	for _, e := range in {
		k := strings.ToLower(strings.TrimSpace(e.DisplayName)) + "\x00" +
			strings.ToLower(strings.TrimSpace(e.Publisher)) + "\x00" +
			strings.ToLower(strings.TrimSpace(e.DisplayVersion))
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	return out
}

// matchString applies a bounded, case-insensitive match. An empty pattern
// or unknown mode never matches. An empty mode defaults to EXACT. GLOB
// honours only `*` (any run) and `?` (any single char) — NO regex.
func matchString(mode, pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	p := strings.ToLower(pattern)
	v := strings.ToLower(strings.TrimSpace(value))
	switch strings.ToUpper(strings.TrimSpace(mode)) {
	case "", MatchModeExact:
		return v == p
	case MatchModePrefix:
		return strings.HasPrefix(v, p)
	case MatchModeContains:
		return strings.Contains(v, p)
	case MatchModeGlob:
		return globMatch(p, v)
	default:
		return false
	}
}

// globMatch matches `s` against `pat` supporting only `*` and `?`
// (linear-time iterative wildcard match; no backtracking blowup).
func globMatch(pat, s string) bool {
	px, sx := 0, 0
	nextPx, nextSx := -1, 0
	for sx < len(s) || px < len(pat) {
		if px < len(pat) {
			switch pat[px] {
			case '*':
				nextPx = px
				nextSx = sx + 1
				px++
				continue
			case '?':
				if sx < len(s) {
					px++
					sx++
					continue
				}
			default:
				if sx < len(s) && pat[px] == s[sx] {
					px++
					sx++
					continue
				}
			}
		}
		if nextPx != -1 && nextSx <= len(s) {
			px = nextPx + 1
			sx = nextSx
			nextSx++
			continue
		}
		return false
	}
	return true
}

// ────────────────────────────────────────────────────────────────
// Fail-closed validation (mirrors the backend DetectionRuleValidator).

// validateDetectionRule rejects a rule fail-closed BEFORE any mutation.
func validateDetectionRule(rule DetectionRule) error {
	switch rule.Type {
	case DetectionRuleTypeWingetPackage:
		if strings.TrimSpace(rule.PackageID) == "" {
			return errors.New("WINGET_PACKAGE requires packageId")
		}
		return nil
	case DetectionRuleTypeRegistryUninstall:
		return validateRegistryRule(rule)
	default:
		return fmt.Errorf("unsupported detection rule type %q", rule.Type)
	}
}

func validateRegistryRule(rule DetectionRule) error {
	pc := strings.TrimSpace(rule.ProductCode)
	dn := strings.TrimSpace(rule.DisplayName)
	if pc == "" && dn == "" {
		return errors.New("REGISTRY_UNINSTALL requires productCode or displayName")
	}
	if pc != "" {
		// productCode is used as a direct registry subkey name, so it must
		// be a real MSI GUID — this prevents a `\`/path-separator from
		// reaching a nested registry path (Codex 019e7d82).
		if !isMsiProductCode(pc) {
			return errors.New("productCode must be an MSI GUID of the form {8-4-4-4-12 hex}")
		}
		return nil
	}
	// DisplayName(+Publisher) fallback.
	if len(dn) > 256 {
		return errors.New("displayName too long")
	}
	mode := strings.ToUpper(strings.TrimSpace(rule.DisplayNameMatch))
	if mode == "" {
		mode = MatchModeExact
	}
	switch mode {
	case MatchModeExact, MatchModePrefix, MatchModeContains, MatchModeGlob:
	default:
		return fmt.Errorf("invalid displayNameMatch %q", rule.DisplayNameMatch)
	}
	if mode == MatchModeGlob {
		if strings.ContainsAny(dn, "[]\\") {
			return errors.New("glob displayName supports only * and ?")
		}
	}
	pub := strings.TrimSpace(rule.Publisher)
	if pub == "" {
		// Publisher omitted is only safe with an EXACT displayName + the
		// explicit AllowPublisherMissing escape hatch (Codex 019e7d82).
		if !rule.AllowPublisherMissing || mode != MatchModeExact {
			return errors.New("REGISTRY_UNINSTALL displayName fallback requires publisher (or allowPublisherMissing with an EXACT displayName)")
		}
		return nil
	}
	if len(pub) > 256 {
		return errors.New("publisher too long")
	}
	pm := strings.ToUpper(strings.TrimSpace(rule.PublisherMatch))
	if pm == "" {
		pm = MatchModeExact
	}
	switch pm {
	case MatchModeExact, MatchModeContains:
	default:
		return fmt.Errorf("invalid publisherMatch %q", rule.PublisherMatch)
	}
	return nil
}

// isMsiProductCode reports whether s is an MSI product-code GUID of the
// form {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} (38 chars, case-insensitive
// hex). Used to gate the direct registry subkey lookup so the key name
// cannot contain a path separator (Codex 019e7d82).
func isMsiProductCode(s string) bool {
	if len(s) != 38 || s[0] != '{' || s[37] != '}' {
		return false
	}
	for i := 1; i < 37; i++ {
		switch i {
		case 9, 14, 19, 24:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHexByte(s[i]) {
				return false
			}
		}
	}
	return true
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
