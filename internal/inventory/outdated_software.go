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

// looksLikeVersion reports whether token t looks like a semantic version.
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
		if p[0] < '0' || p[0] > '9' {
			return false
		}
	}
	return true
}

// isNoUpgradeOutput reports whether output indicates there are no upgrades.
func isNoUpgradeOutput(output string) bool {
	l := strings.ToLower(output)
	return strings.Contains(l, "no applicable upgrade") ||
		strings.Contains(l, "no updates found") ||
		strings.Contains(l, "no upgrade packages")
}
