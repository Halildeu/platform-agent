package winget

import (
	"path/filepath"
	"testing"
)

// TestDesktopAppInstallerGlobMatchesAllArches locks the AG-026A
// arch-agnostic winget-locator fix: the WindowsApps package-folder
// glob must match x64, arm64, arm and x86 alike. The prior `_x64__`
// glob missed ARM64 Windows endpoints, breaking winget location
// under LocalSystem (wingetReady=false → BE-021A preflight BLOCK).
func TestDesktopAppInstallerGlobMatchesAllArches(t *testing.T) {
	match := []string{
		"Microsoft.DesktopAppInstaller_1.28.239.0_arm64__8wekyb3d8bbwe", // HALILKOOLUB735 (regression case)
		"Microsoft.DesktopAppInstaller_1.22.10661.0_x64__8wekyb3d8bbwe",
		"Microsoft.DesktopAppInstaller_1.0.0.0_arm__8wekyb3d8bbwe",
		"Microsoft.DesktopAppInstaller_1.0.0.0_x86__8wekyb3d8bbwe",
		"Microsoft.DesktopAppInstaller_2.0.0.0_neutral__8wekyb3d8bbwe",
	}
	for _, folder := range match {
		ok, err := filepath.Match(DesktopAppInstallerGlob, folder)
		if err != nil {
			t.Fatalf("filepath.Match error for %q: %v", folder, err)
		}
		if !ok {
			t.Errorf("glob %q did NOT match arch folder %q (regression)", DesktopAppInstallerGlob, folder)
		}
	}

	noMatch := []string{
		"Microsoft.SomethingElse_1.0.0.0_x64__8wekyb3d8bbwe",  // wrong package name
		"Foo.DesktopAppInstaller_1.0.0.0_arm64__8wekyb3d8bbwe", // wrong prefix
		"Microsoft.DesktopAppInstaller_1.0.0.0_arm64__abcdef",  // wrong publisher hash
		"Microsoft.DesktopAppInstaller",                        // no version/arch/hash
	}
	for _, folder := range noMatch {
		ok, _ := filepath.Match(DesktopAppInstallerGlob, folder)
		if ok {
			t.Errorf("glob %q unexpectedly matched non-AppInstaller folder %q", DesktopAppInstallerGlob, folder)
		}
	}
}
