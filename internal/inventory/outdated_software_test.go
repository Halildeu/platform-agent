package inventory

import (
	"testing"
	"time"
)

func TestOutdatedSoftwareSchemaVersion(t *testing.T) {
	if OutdatedSoftwareSchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d; want 1", OutdatedSoftwareSchemaVersion)
	}
}

func TestMaxOutdatedPackages(t *testing.T) {
	if MaxOutdatedPackages != 512 {
		t.Errorf("MaxOutdatedPackages = %d; want 512", MaxOutdatedPackages)
	}
}

func TestLooksLikeVersion(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1.0.0", true},
		{"v1.0.0", true},
		{"24.09", true},
		{"1.91.0-preview", true},
		{"x1.0", false},
		{"", false},
	}
	for _, c := range cases {
		got := looksLikeVersion(c.in)
		if got != c.want {
			t.Errorf("looksLikeVersion(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

func TestIsNoUpgradeOutput(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"No applicable upgrade packages found.", true},
		{"No updates found.", true},
		{"NO APPLICABLE UPGRADE", true},
		{"7-Zip  7zip.7zip  24.09  25.01", false},
		{"", false},
	}
	for _, c := range cases {
		got := isNoUpgradeOutput(c.in)
		if got != c.want {
			t.Errorf("isNoUpgradeOutput(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

func TestProbeOutdatedSoftwareUnsupported(t *testing.T) {
	result := ProbeOutdatedSoftware(nil, time.Now)
	if result.Supported {
		t.Error("Supported should be false on non-Windows")
	}
	if result.SourceUsed != OutdatedSoftwareSourceNone {
		t.Errorf("SourceUsed = %v; want none", result.SourceUsed)
	}
	if len(result.ProbeErrors) == 0 {
		t.Error("Should have probe error on non-Windows")
	}
}

func TestDeriveUpgradeNeverNil(t *testing.T) {
	result := &OutdatedSoftwareResult{}
	deriveOutdatedSoftwareSummary(result)
	if result.Upgrade == nil {
		t.Error("Upgrade should not be nil after derive")
	}
	if result.MaxUpgrade != MaxOutdatedPackages {
		t.Errorf("MaxUpgrade = %d; want %d", result.MaxUpgrade, MaxOutdatedPackages)
	}
}

func TestIsNotFoundErr(t *testing.T) {
	if isNotFoundErr(nil) {
		t.Error("isNotFoundErr(nil) should be false")
	}
}

func TestProbeOutdatedSoftwareNilCtx(t *testing.T) {
	result := ProbeOutdatedSoftware(nil, time.Now)
	if result.SchemaVersion == 0 {
		t.Errorf("SchemaVersion = %d; should be 1", result.SchemaVersion)
	}
}
