//go:build windows

package inventory

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProbeOutdatedSoftwareWinGetNotFound(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return nil, errors.New("exec: not found")
	}

	result := ProbeOutdatedSoftware(context.Background(), time.Now)
	if len(result.ProbeErrors) == 0 {
		t.Fatal("Should have probe errors when winget not found")
	}
	if result.ProbeErrors[0].Code != OutdatedSoftwareErrWinGetNotFound {
		t.Errorf("Code = %q; want %q", result.ProbeErrors[0].Code, OutdatedSoftwareErrWinGetNotFound)
	}
}

func TestProbeOutdatedSoftwareEmptyOutput(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return []byte("   "), nil
	}

	result := ProbeOutdatedSoftware(context.Background(), time.Now)
	if len(result.ProbeErrors) == 0 {
		t.Fatal("Should have probe errors on empty output")
	}
	if result.ProbeErrors[0].Code != OutdatedSoftwareErrWinGetEmptyOutput {
		t.Errorf("Code = %q; want %q", result.ProbeErrors[0].Code, OutdatedSoftwareErrWinGetEmptyOutput)
	}
}

func TestProbeOutdatedSoftwareNoUpgrades(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return []byte("No applicable upgrade packages found."), nil
	}

	result := ProbeOutdatedSoftware(context.Background(), time.Now)
	if result.SourceUsed != OutdatedSoftwareSourceWinGet {
		t.Errorf("SourceUsed = %v; want winget", result.SourceUsed)
	}
	if len(result.Upgrade) != 0 {
		t.Errorf("len(Upgrade) = %d; want 0", len(result.Upgrade))
	}
}

func TestProbeOutdatedSoftwareWithPackages(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	output := `
Name                      Id                              Version   Available  Source
----                      --                              -------   ---------  ------
7-Zip                     7zip.7zip                       24.09     25.01     winget
`
	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return []byte(output), nil
	}

	result := ProbeOutdatedSoftware(context.Background(), time.Now)
	if result.SourceUsed != OutdatedSoftwareSourceWinGet {
		t.Errorf("SourceUsed = %v; want winget", result.SourceUsed)
	}
	if len(result.Upgrade) != 1 {
		t.Errorf("len(Upgrade) = %d; want 1", len(result.Upgrade))
	}
	if result.Upgrade[0].PackageID != "7zip.7zip" {
		t.Errorf("PackageID = %q; want %q", result.Upgrade[0].PackageID, "7zip.7zip")
	}
}

func TestProbeOutdatedSoftwareParseFailure(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return []byte("some random text without table markers"), nil
	}

	result := ProbeOutdatedSoftware(context.Background(), time.Now)
	if len(result.ProbeErrors) == 0 {
		t.Fatal("Should have probe errors on parse failure")
	}
	if result.ProbeErrors[0].Code != OutdatedSoftwareErrWinGetParseError {
		t.Errorf("Code = %q; want %q", result.ProbeErrors[0].Code, OutdatedSoftwareErrWinGetParseError)
	}
}

func TestProbeOutdatedSoftwareDuration(t *testing.T) {
	orig := runOutdatedSoftwareProbe
	t.Cleanup(func() { runOutdatedSoftwareProbe = orig })

	runOutdatedSoftwareProbe = func(ctx context.Context) ([]byte, error) {
		return []byte("No applicable upgrade packages found."), nil
	}

	result := ProbeOutdatedSoftware(context.Background(), time.Now)
	if result.ProbeDurationMs <= 0 {
		t.Errorf("ProbeDurationMs = %d; want > 0", result.ProbeDurationMs)
	}
}

func TestProbeOutdatedSoftwareNilCtx(t *testing.T) {
	result := ProbeOutdatedSoftware(nil, time.Now)
	if result.SchemaVersion == 0 {
		t.Errorf("SchemaVersion should be set; got %d", result.SchemaVersion)
	}
}
