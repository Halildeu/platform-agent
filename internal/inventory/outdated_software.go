package inventory

import (
	"errors"
	"strings"
	"time"
)

// AG-036 — Outdated Software Inventory (Faz 22.5 Sprint B P1 visibility expansion).

const OutdatedSoftwareSchemaVersion = 1

const MaxOutdatedPackages = 512

type OutdatedSoftwareProbeSource string

const (
	OutdatedSoftwareSourceWinGet OutdatedSoftwareProbeSource = "winget"
	OutdatedSoftwareSourceNone   OutdatedSoftwareProbeSource = "none"
)

const (
	OutdatedSoftwareErrUnsupportedPlatform = "UNSUPPORTED_PLATFORM"
	OutdatedSoftwareErrWinGetNotFound      = "WINGET_NOT_FOUND"
	OutdatedSoftwareErrWinGetTimeout       = "WINGET_TIMEOUT"
	OutdatedSoftwareErrWinGetFailed        = "WINGET_FAILED"
	OutdatedSoftwareErrWinGetEmptyOutput   = "WINGET_EMPTY_OUTPUT"
	OutdatedSoftwareErrWinGetParseError    = "WINGET_PARSE_ERROR"
)

type OutdatedSoftwareProbeError struct {
	Source  OutdatedSoftwareProbeSource `json:"source,omitempty"`
	Code    string                      `json:"code"`
	Summary string                      `json:"summary,omitempty"`
}

// OutdatedSoftwarePackage is the per-package wire shape for the AG-036
// outdated-software probe.
//
// Wire fields: packageId + installedVersion + availableVersion. The two
// version strings are functionally REQUIRED for outdated-software /
// upgrade-eligibility detection (a "newer version is available" signal
// is meaningless without the from/to versions) and version strings are
// public, non-PII metadata.
//
// EXCLUDED PII (deliberately NEVER serialized): display name, publisher,
// install location, license, and download URL. The package id alone is
// the stable, non-PII correlation key; the human-facing name/publisher
// and the filesystem/license/URL surface stay off the wire. The
// JSON-keys regression test (TestOutdatedSoftwarePackage_JSONKeys)
// machine-enforces this exact key set so a future change cannot silently
// widen the PII surface.
type OutdatedSoftwarePackage struct {
	PackageID        string `json:"packageId"`
	InstalledVersion string `json:"installedVersion"`
	AvailableVersion string `json:"availableVersion"`
}

type OutdatedSoftwareResult struct {
	SchemaVersion    int                          `json:"schemaVersion"`
	Supported        bool                         `json:"supported"`
	ProbeComplete    bool                         `json:"probeComplete"`
	UpgradeCount     int                          `json:"upgradeCount"`
	Upgrade          []OutdatedSoftwarePackage    `json:"upgrade"`
	UpgradeTruncated bool                         `json:"upgradeTruncated"`
	MaxUpgrade       int                          `json:"maxUpgrade"`
	SourceUsed       OutdatedSoftwareProbeSource  `json:"sourceUsed"`
	ProbeErrors      []OutdatedSoftwareProbeError `json:"probeErrors,omitempty"`
	ProbeDurationMs  int                          `json:"probeDurationMs"`
}

func deriveOutdatedSoftwareSummary(result *OutdatedSoftwareResult) {
	if result.Upgrade == nil {
		result.Upgrade = make([]OutdatedSoftwarePackage, 0)
	}
	if result.MaxUpgrade == 0 {
		result.MaxUpgrade = MaxOutdatedPackages
	}
	result.ProbeComplete = len(result.ProbeErrors) == 0 && result.SourceUsed != OutdatedSoftwareSourceNone
}

func outdatedSoftwareElapsedMs(start time.Time, now func() time.Time) int {
	if now == nil {
		now = time.Now
	}
	return int(now().Sub(start) / time.Millisecond)
}

// isNotFoundErr reports whether err indicates the executable was not found.
// Exported for cross-platform test seam usage.
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errors.New("exec: not found")) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "not found") || strings.Contains(s, "executable file not found")
}

// looksLikeVersion reports whether token t looks like a (dotted)
// version string. It requires at least two dot-separated segments where
// each non-empty segment is a run of digits optionally followed by a
// '-'/'+' pre-release/build suffix (e.g. "1.91.0-preview", "24.09").
//
// Crucially it REJECTS tokens like "7zip.7zip" — a winget package id
// whose dot-segments begin with a digit but then contain letters with
// no separator. The earlier "segment must start with a digit" rule let
// such ids masquerade as versions, which broke the version-pair anchor
// in the token fallback parser.
func looksLikeVersion(t string) bool {
	if len(t) == 0 {
		return false
	}
	if t[0] == 'v' || t[0] == 'V' {
		t = t[1:]
	}
	if len(t) == 0 {
		return false
	}
	parts := strings.Split(t, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		if !versionSegment(p) {
			return false
		}
	}
	return true
}

// versionSegment reports whether p is a numeric version segment: a run
// of one or more digits, optionally followed by a '-' or '+' and an
// arbitrary pre-release/build suffix. "09" -> true, "0-preview" -> true,
// "7zip" -> false (digit immediately followed by a letter, no
// separator).
func versionSegment(p string) bool {
	if len(p) == 0 || p[0] < '0' || p[0] > '9' {
		return false
	}
	i := 0
	for i < len(p) && p[i] >= '0' && p[i] <= '9' {
		i++
	}
	if i == len(p) {
		return true
	}
	// First non-digit must be a recognized suffix separator.
	return p[i] == '-' || p[i] == '+'
}

// isNoUpgradeOutput reports whether output indicates there are no upgrades.
func isNoUpgradeOutput(output string) bool {
	l := strings.ToLower(output)
	return strings.Contains(l, "no applicable upgrade") ||
		strings.Contains(l, "no updates found") ||
		strings.Contains(l, "no upgrade packages")
}
