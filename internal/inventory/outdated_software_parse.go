package inventory

// AG-036 — WinGet `upgrade` table parsing.
//
// These functions are intentionally build-tag-agnostic (NO //go:build
// windows): they are pure string parsing with no exec/syscall surface,
// so they compile and are exercised by `go test` on every platform —
// including the linux CI host where the //go:build windows runner is
// skipped. Only the actual exec.CommandContext / winget locator bits
// live in outdated_software_windows.go. This guarantees CI catches a
// future parse regression instead of letting it hide behind a skipped
// Windows-only test.

import (
	"errors"
	"strings"
)

// parseUpgradeOutput parses the winget `upgrade` table into the
// PackageId + InstalledVersion + AvailableVersion triples.
//
// winget renders a fixed 3-row preamble:
//
//	Name          Id              Version   Available  Source   <- header
//	-----------   -------------   --------   ---------  ------   <- dashed separator
//	7-Zip         7zip.7zip       24.09      25.01      winget   <- FIRST data row
//
// The first DATA row is the line IMMEDIATELY after the dashed
// separator (headerIdx+1) — NOT headerIdx+2. The previous +2 dropped
// the first real package (single-package output -> PARSE_ERROR;
// multi-package -> silently omitted the first row).
//
// The dashed separator also encodes the column widths, which we use to
// slice the header/data rows into columns for a layout-aware id +
// version extraction (more robust than a pure whitespace-token
// heuristic when a display name contains a dot or dash).
func parseUpgradeOutput(output string) ([]OutdatedSoftwarePackage, error) {
	lines := strings.Split(output, "\n")
	headerIdx := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) > 20 && strings.Count(trimmed, "-") > 10 {
			headerIdx = i
			break
		}
	}
	// The first data row is the line immediately after the dashed
	// separator. headerIdx-1 is the column-header row.
	start := headerIdx + 1
	if headerIdx < 0 || start > len(lines) {
		return nil, errors.New("unparseable winget upgrade output: no header separator found")
	}

	// Derive column boundaries from the header row (headerIdx-1) using
	// the dashed separator (headerIdx) as the width oracle. When the
	// layout cannot be resolved (e.g. no preceding header row) we fall
	// back to the whitespace-token heuristic per line.
	cols := deriveUpgradeColumns(headerColumnsSource(lines, headerIdx))

	var classified []OutdatedSoftwarePackage
	for _, line := range lines[start:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Continuation / progress lines start with leading whitespace
		// (winget indents wrapped names and prints right-aligned
		// percentage / spinner artifacts). Real package rows start in
		// column 0 with a display-name glyph — which MAY be a digit
		// (e.g. "7-Zip", "1Password"), so we deliberately do NOT skip
		// digit-leading rows. Any non-row that slips through yields no
		// version pair / valid id below and is dropped naturally.
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		pkg := parseUpgradeRow(line, cols)
		if pkg.PackageID == "" {
			continue
		}
		classified = append(classified, pkg)
		if len(classified) >= MaxOutdatedPackages {
			break
		}
	}
	return classified, nil
}

// headerColumnsSource returns the column-header row text (the line
// directly above the dashed separator) or "" when unavailable.
func headerColumnsSource(lines []string, headerIdx int) string {
	if headerIdx-1 >= 0 {
		return lines[headerIdx-1]
	}
	return ""
}

// upgradeColumns holds the byte offset where the Id, Version, and
// Available columns begin within a fixed-width winget row. A zero/empty
// value signals "layout unresolved — use the token fallback".
type upgradeColumns struct {
	resolved     bool
	idStart      int
	versionStart int
	availStart   int
}

// deriveUpgradeColumns locates the Id / Version / Available column
// offsets from the winget header row. winget localizes the labels, so
// we match a small set of known localized header tokens for the three
// columns we keep; the unmatched Name/Source columns are irrelevant.
func deriveUpgradeColumns(header string) upgradeColumns {
	if strings.TrimSpace(header) == "" {
		return upgradeColumns{}
	}
	idStart := headerTokenOffset(header, []string{"Id"})
	versionStart := headerTokenOffset(header, []string{"Version"})
	availStart := headerTokenOffset(header, []string{"Available", "Verfügbar", "Disponible", "Disponibile"})
	if idStart < 0 || versionStart < 0 || availStart < 0 {
		return upgradeColumns{}
	}
	if !(idStart < versionStart && versionStart < availStart) {
		return upgradeColumns{}
	}
	return upgradeColumns{
		resolved:     true,
		idStart:      idStart,
		versionStart: versionStart,
		availStart:   availStart,
	}
}

// headerTokenOffset returns the byte index at which the first of the
// candidate header labels begins, or -1 when none is present as a
// whitespace-delimited token.
func headerTokenOffset(header string, candidates []string) int {
	for _, cand := range candidates {
		idx := 0
		for idx < len(header) {
			j := strings.Index(header[idx:], cand)
			if j < 0 {
				break
			}
			pos := idx + j
			beforeOK := pos == 0 || header[pos-1] == ' ' || header[pos-1] == '\t'
			afterPos := pos + len(cand)
			afterOK := afterPos >= len(header) || header[afterPos] == ' ' || header[afterPos] == '\t'
			if beforeOK && afterOK {
				return pos
			}
			idx = pos + len(cand)
		}
	}
	return -1
}

// parseUpgradeRow extracts the package triple from a single data row.
// When the column layout resolved, it slices by column offsets; the
// extracted id is then validated against the winget package-id charset.
// On any failure it falls back to the whitespace-token heuristic.
func parseUpgradeRow(line string, cols upgradeColumns) OutdatedSoftwarePackage {
	if cols.resolved {
		if pkg, ok := parseUpgradeRowByColumns(line, cols); ok {
			return pkg
		}
	}
	return parseUpgradeLine(strings.TrimSpace(line))
}

// parseUpgradeRowByColumns slices a fixed-width row by the derived
// column offsets. Returns ok=false when the row is shorter than the
// columns (e.g. a wrapped name) so the caller can fall back.
func parseUpgradeRowByColumns(line string, cols upgradeColumns) (OutdatedSoftwarePackage, bool) {
	if len(line) <= cols.idStart {
		return OutdatedSoftwarePackage{}, false
	}
	id := columnSlice(line, cols.idStart, cols.versionStart)
	installed := columnSlice(line, cols.versionStart, cols.availStart)
	available := columnSlice(line, cols.availStart, len(line))
	// Available column may include a trailing Source token; keep the
	// first whitespace field.
	if f := strings.Fields(available); len(f) > 0 {
		available = f[0]
	}
	if id == "" || installed == "" || available == "" {
		return OutdatedSoftwarePackage{}, false
	}
	if !isWinGetPackageID(id) {
		return OutdatedSoftwarePackage{}, false
	}
	if !looksLikeVersion(installed) || !looksLikeVersion(available) {
		return OutdatedSoftwarePackage{}, false
	}
	return OutdatedSoftwarePackage{
		PackageID:        id,
		InstalledVersion: installed,
		AvailableVersion: available,
	}, true
}

// columnSlice returns the trimmed substring [from,to) clamped to the
// line length.
func columnSlice(line string, from, to int) string {
	if from < 0 {
		from = 0
	}
	if from > len(line) {
		return ""
	}
	if to > len(line) {
		to = len(line)
	}
	if to < from {
		to = from
	}
	return strings.TrimSpace(line[from:to])
}

// isWinGetPackageID validates s against the winget package-identifier
// charset: alphanumeric plus '.', '-', '+', and must contain at least
// one '.' or '-' (publisher.package or publisher-package shape).
func isWinGetPackageID(s string) bool {
	if s == "" {
		return false
	}
	hasSep := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '.' || ch == '-':
			hasSep = true
		case ch == '+' || ch == '_':
		default:
			return false
		}
	}
	return hasSep
}

// parseUpgradeLine is the whitespace-token fallback used when the
// fixed-width column layout cannot be resolved. It locates the
// (installedVersion, availableVersion) adjacent version pair and takes
// the package id as the token immediately preceding that pair (falling
// back to the first id-shaped token), validated against the winget
// package-id charset.
func parseUpgradeLine(line string) OutdatedSoftwarePackage {
	tokens := strings.Fields(line)
	if len(tokens) < 4 {
		return OutdatedSoftwarePackage{}
	}

	// Find the adjacent (installed, available) version pair.
	installedIdx := -1
	availableIdx := -1
	for i := 0; i+1 < len(tokens); i++ {
		if looksLikeVersion(tokens[i]) && looksLikeVersion(tokens[i+1]) {
			installedIdx = i
			availableIdx = i + 1
			break
		}
	}

	idIdx := -1
	if installedIdx > 0 {
		// Prefer the token immediately preceding the version pair when
		// it is a valid package id.
		if isWinGetPackageID(tokens[installedIdx-1]) {
			idIdx = installedIdx - 1
		}
	}
	if idIdx < 0 {
		// Fall back to the first id-shaped token before the version
		// pair (or anywhere, if the pair wasn't found).
		limit := len(tokens)
		if installedIdx >= 0 {
			limit = installedIdx
		}
		for i := 0; i < limit; i++ {
			if isWinGetPackageID(tokens[i]) {
				idIdx = i
				break
			}
		}
	}

	if installedIdx < 0 {
		// No adjacent version pair — last-ditch positional fallback for
		// the canonical 4+ column layout (Name Id Version Available …).
		if len(tokens) >= 4 && isWinGetPackageID(tokens[1]) &&
			looksLikeVersion(tokens[2]) && looksLikeVersion(tokens[3]) {
			return OutdatedSoftwarePackage{
				PackageID:        tokens[1],
				InstalledVersion: tokens[2],
				AvailableVersion: tokens[3],
			}
		}
		return OutdatedSoftwarePackage{}
	}
	if idIdx < 0 {
		return OutdatedSoftwarePackage{}
	}

	return OutdatedSoftwarePackage{
		PackageID:        tokens[idIdx],
		InstalledVersion: tokens[installedIdx],
		AvailableVersion: tokens[availableIdx],
	}
}
