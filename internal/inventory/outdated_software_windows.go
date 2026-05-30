//go:build windows

package inventory

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

const outdatedSoftwareProbeTimeout = 60 * time.Second

var runOutdatedSoftwareProbe = runOutdatedSoftwareProbeReal

func runOutdatedSoftwareProbeReal(ctx context.Context) ([]byte, error) {
	path, err := outdatedSoftwareLocator()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, "upgrade", "--include-returning-apps", "--source", "winget")
	return cmd.Output()
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
		if isNotFoundErr(err) {
			code = OutdatedSoftwareErrWinGetNotFound
		}
		result.ProbeErrors = append(result.ProbeErrors, OutdatedSoftwareProbeError{
			Source:  OutdatedSoftwareSourceWinGet,
			Code:    code,
			Summary: "WinGet upgrade enumeration failed",
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

	classified, parseErr := parseUpgradeOutput(trimmed)
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
	if len(classified) > MaxOutdatedPackages {
		result.Upgrade = classified[:MaxOutdatedPackages]
		result.UpgradeTruncated = true
	} else {
		result.Upgrade = classified
	}
	finalizeOutdatedSoftware(&result, start, now)
	return result
}

var outdatedSoftwareLocator = func() (string, error) {
	path, err := exec.LookPath("winget")
	if err == nil {
		return path, nil
	}
	locAppData := os.Getenv("LOCALAPPDATA")
	if locAppData != "" {
		winApps := locAppData + `\Microsoft\WindowsApps`
		cmd := exec.Command("cmd", "/c", "dir", "/b", winApps+`\winget.exe`)
		out, _ := cmd.Output()
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" && !strings.Contains(trimmed, "File Not Found") {
			return winApps + `\` + trimmed, nil
		}
	}
	return "", err
}

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
	start := headerIdx + 2
	if headerIdx < 0 || start >= len(lines) {
		return nil, errors.New("unparseable winGet upgrade output: no header separator found")
	}

	var classified []OutdatedSoftwarePackage
	for _, line := range lines[start:] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		c := trimmed[0]
		if c == ' ' || c == '\t' || (c >= '0' && c <= '9') {
			continue
		}
		pkg := parseUpgradeLine(trimmed)
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

func parseUpgradeLine(line string) OutdatedSoftwarePackage {
	tokens := strings.Fields(line)
	if len(tokens) < 4 {
		return OutdatedSoftwarePackage{}
	}

	idIdx := -1
	installedIdx := -1
	availableIdx := -1

	for i, t := range tokens {
		if idIdx < 0 && (strings.Contains(t, ".") || strings.Contains(t, "-")) {
			idIdx = i
			continue
		}
		if installedIdx < 0 && looksLikeVersion(t) {
			installedIdx = i
			if i+1 < len(tokens) && looksLikeVersion(tokens[i+1]) {
				availableIdx = i + 1
			}
		}
		if idIdx > 0 && installedIdx > 0 {
			break
		}
	}

	if idIdx < 0 || installedIdx < 0 {
		if len(tokens) >= 4 {
			idIdx = 1
			installedIdx = 2
			availableIdx = 3
		} else {
			return OutdatedSoftwarePackage{}
		}
	}
	if availableIdx < 0 {
		availableIdx = installedIdx + 1
	}
	pkgID := tokens[idIdx]
	if !strings.Contains(pkgID, ".") && !strings.Contains(pkgID, "-") {
		return OutdatedSoftwarePackage{}
	}
	if availableIdx >= len(tokens) {
		availableIdx = installedIdx
	}
	return OutdatedSoftwarePackage{
		PackageID:        pkgID,
		InstalledVersion: tokens[installedIdx],
		AvailableVersion: tokens[availableIdx],
	}
}

func finalizeOutdatedSoftware(result *OutdatedSoftwareResult, start time.Time, now func() time.Time) {
	deriveOutdatedSoftwareSummary(result)
	if result.UpgradeCount == 0 {
		result.UpgradeCount = len(result.Upgrade)
	}
	result.ProbeDurationMs = outdatedSoftwareElapsedMs(start, now)
}
