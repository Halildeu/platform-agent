//go:build !windows

package winget

import (
	"testing"
	"time"
)

// AG-026A — non-Windows stub contract.
//
// DetectSourceEgress on non-Windows returns an unsupported
// SourceEgressReadiness with Supported=false and the rest trivially
// false / zero so the wire shape stays uniform across platforms.
// The PackageQuery sub-struct still echoes the canonical
// FixedPackageQueryID so backend-side parsers do not have to handle
// a missing field.
func TestDetectSourceEgressOnNonWindowsIsUnsupported(t *testing.T) {
	r := DetectSourceEgress(time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))
	if r.Supported {
		t.Fatalf("non-Windows DetectSourceEgress should report Supported=false, got %#v", r)
	}
	if r.SchemaVersion != SourceEgressSchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", r.SchemaVersion, SourceEgressSchemaVersion)
	}
	if r.PackageQuery.PackageID != FixedPackageQueryID {
		t.Fatalf("PackageQuery.PackageID = %q, want %q", r.PackageQuery.PackageID, FixedPackageQueryID)
	}
	if r.PackageQuery.Found {
		t.Fatalf("PackageQuery.Found must be false on unsupported platform")
	}
	if len(r.Sources) != 0 {
		t.Fatalf("Sources must be empty on unsupported platform, got %#v", r.Sources)
	}
	if len(r.Egress.DNS) != 0 || len(r.Egress.TCP) != 0 || len(r.Egress.HTTPS) != 0 {
		t.Fatalf("egress probes must not run on unsupported platform, got %#v", r.Egress)
	}
}
