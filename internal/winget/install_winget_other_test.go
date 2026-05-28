//go:build !windows

package winget

import (
	"context"
	"testing"
)

func TestInstallWinGet_OnNonWindowsReturnsUnsupportedPlatform(t *testing.T) {
	req := InstallRequest{
		PackageID:        "7zip.7zip",
		ArgsPolicyPreset: ArgsPresetDefault,
		DetectionRule: DetectionRule{
			Type:      DetectionRuleTypeWingetPackage,
			PackageID: "7zip.7zip",
		},
		VersionPredicate: VersionPredicate{Type: VersionPredicateLatest},
	}
	res := InstallWinGet(context.Background(), req)
	if res.FinalStatus != FinalStatusFailedUnsupportedPlatform {
		t.Fatalf("expected FAILED_UNSUPPORTED_PLATFORM, got %s", res.FinalStatus)
	}
	if res.FailedReasonCode != "platform_not_windows" {
		t.Fatalf("expected failedReasonCode=platform_not_windows, got %q", res.FailedReasonCode)
	}
	if res.Supported {
		t.Fatal("Supported must be false on non-Windows builds")
	}
	if res.SchemaVersion != InstallSchemaVersion {
		t.Fatalf("schemaVersion=%d, want %d", res.SchemaVersion, InstallSchemaVersion)
	}
}
