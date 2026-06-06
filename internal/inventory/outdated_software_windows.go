//go:build windows

package inventory

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"platform-agent/internal/winget"
)

// NOTE: The pure WinGet `upgrade` table parsing (parseUpgradeOutput /
// parseUpgradeLine and helpers) lives in the build-tag-agnostic file
// outdated_software_parse.go so it compiles + is tested on every
// platform (incl. the linux CI host). Only the exec/syscall surface
// below is //go:build windows.

const outdatedSoftwareProbeTimeout = 60 * time.Second

var runOutdatedSoftwareProbe = runOutdatedSoftwareProbeReal

func runOutdatedSoftwareProbeReal(ctx context.Context) ([]byte, error) {
	path, err := outdatedSoftwareLocator()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, outdatedSoftwareArgs()...)
	return cmd.Output()
}

func outdatedSoftwareArgs() []string {
	return []string{
		"upgrade",
		"--source", "winget",
		"--accept-source-agreements",
		"--disable-interactivity",
	}
}

func ProbeOutdatedSoftware(ctx context.Context, now func() time.Time) OutdatedSoftwareResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if now == nil {
		now = time.Now
	}
	start := now()
	result := OutdatedSoftwareResult{
		SchemaVersion: OutdatedSoftwareSchemaVersion,
		Supported:     true,
		SourceUsed:    OutdatedSoftwareSourceNone,
		MaxUpgrade:    MaxOutdatedPackages,
	}

	probeCtx, cancel := context.WithTimeout(ctx, outdatedSoftwareProbeTimeout)
	defer cancel()

	raw, err := runOutdatedSoftwareProbe(probeCtx)
	if err != nil {
		code := OutdatedSoftwareErrWinGetFailed
		summary := "WinGet upgrade enumeration failed"
		switch {
		case isNotFoundErr(err):
			code = OutdatedSoftwareErrWinGetNotFound
			summary = "WinGet executable not found"
		case errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(probeCtx.Err(), context.DeadlineExceeded):
			// The 60s probe budget elapsed: classify as a distinct
			// timeout rather than a generic failure so the backend can
			// retry-vs-degrade differently. The exec error from a
			// deadline-killed process does not always wrap
			// DeadlineExceeded, so probeCtx.Err() is the reliable
			// signal.
			code = OutdatedSoftwareErrWinGetTimeout
			summary = "WinGet upgrade enumeration timed out"
		}
		result.ProbeErrors = append(result.ProbeErrors, OutdatedSoftwareProbeError{
			Source:  OutdatedSoftwareSourceWinGet,
			Code:    code,
			Summary: summary,
		})
		finalizeOutdatedSoftware(&result, start, now)
		return result
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		result.ProbeErrors = append(result.ProbeErrors, OutdatedSoftwareProbeError{
			Source:  OutdatedSoftwareSourceWinGet,
			Code:    OutdatedSoftwareErrWinGetEmptyOutput,
			Summary: "WinGet upgrade returned no output",
		})
		finalizeOutdatedSoftware(&result, start, now)
		return result
	}

	if isNoUpgradeOutput(trimmed) {
		result.SourceUsed = OutdatedSoftwareSourceWinGet
		finalizeOutdatedSoftware(&result, start, now)
		return result
	}

	classified, truncated, parseErr := parseUpgradeOutput(trimmed)
	if parseErr != nil {
		result.ProbeErrors = append(result.ProbeErrors, OutdatedSoftwareProbeError{
			Source:  OutdatedSoftwareSourceWinGet,
			Code:    OutdatedSoftwareErrWinGetParseError,
			Summary: "WinGet upgrade output parse failed",
		})
		finalizeOutdatedSoftware(&result, start, now)
		return result
	}

	result.SourceUsed = OutdatedSoftwareSourceWinGet
	// parseUpgradeOutput already enforced the MaxOutdatedPackages hard
	// upper bound and reports whether more classifiable upgrade rows than
	// the cap were present. The previous `len(classified) >
	// MaxOutdatedPackages` check here was dead code — the in-parser cap
	// made it impossible — so truncation went unreported (AG-036).
	//
	// NOTE: when truncated, Upgrade (and the derived UpgradeCount below)
	// reflect the capped list length (MaxOutdatedPackages), NOT the true
	// pending total; UpgradeTruncated is the authoritative "list is
	// incomplete" signal consumers must read.
	result.Upgrade = classified
	result.UpgradeTruncated = truncated
	finalizeOutdatedSoftware(&result, start, now)
	return result
}

// Use the same production WinGet locator as AG-026/AG-026A and install
// execution. HALILKOOLUB735 live evidence showed LocalSystem can miss
// winget on PATH while App Installer's system-wide WindowsApps package
// contains a working winget.exe.
var outdatedSoftwareLocator = winget.LocateExecutable

func finalizeOutdatedSoftware(result *OutdatedSoftwareResult, start time.Time, now func() time.Time) {
	deriveOutdatedSoftwareSummary(result)
	if result.UpgradeCount == 0 {
		result.UpgradeCount = len(result.Upgrade)
	}
	result.ProbeDurationMs = outdatedSoftwareElapsedMs(start, now)
}
