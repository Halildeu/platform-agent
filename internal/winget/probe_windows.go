//go:build windows

package winget

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Detect wires the default production locator + executor into Probe.
// It is the only function callers outside this package should ever
// invoke; the lower-level Probe / Locator / Executor primitives exist
// for testability.
//
// The `now` parameter is kept on the signature for caller-side audit
// stamping (the inventory snapshot uses it as CollectedAt), but the
// probe's internal duration measurement uses the real wall clock — a
// fixed-clock stub would collapse ProbeDurationMs to zero and lose the
// telemetry signal even though context.WithTimeout still works (Codex
// peer review iter-1, thread 019e691c).
func Detect(now time.Time) Readiness {
	_ = now
	return Probe(ProbeOptions{
		Locator: defaultLocator,
		Execute: defaultExecutor,
		Timeout: DefaultProbeTimeout * time.Second,
		Now:     time.Now,
	})
}

// defaultLocator tries PATH first, then the per-user WindowsApps
// reparse point (where Microsoft Store installs the AppX alias), then
// the system-wide WindowsApps directory. These are the three places
// WinGet App Installer actually lives on Windows 10/11 IT pilot
// builds; we don't search the registry because the registry entry is
// not reliably present under LocalSystem.
func defaultLocator() (string, error) {
	if path, err := exec.LookPath("winget"); err == nil {
		return path, nil
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		candidate := filepath.Join(local, "Microsoft", "WindowsApps", "winget.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
		// Microsoft.DesktopAppInstaller_8wekyb3d8bbwe is the AppX
		// family name. We glob it so the version segment doesn't
		// pin us to one specific store release.
		pattern := filepath.Join(programFiles, "WindowsApps", "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe", "winget.exe")
		if matches, err := filepath.Glob(pattern); err == nil && len(matches) > 0 {
			return matches[0], nil
		}
	}
	return "", fmt.Errorf("%w", ErrWinGetNotFound)
}

// defaultExecutor uses exec.CommandContext so the deadline supplied
// by Probe cancels the child process if winget hangs (msstore source
// reset prompt is a recurring offender under LocalSystem).
func defaultExecutor(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	return cmd.CombinedOutput()
}
