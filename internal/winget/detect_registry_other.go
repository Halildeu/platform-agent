//go:build !windows

package winget

import (
	"context"
	"errors"
)

// stubArpReader is the non-Windows ArpReader. REGISTRY_UNINSTALL detection
// is Windows-only; on other platforms the reader errors so the pipeline
// fails closed (it never assumes not-installed from an unavailable
// detector).
type stubArpReader struct{}

func defaultArpReader() ArpReader { return stubArpReader{} }

func (stubArpReader) Enumerate(_ context.Context) ([]ArpEntry, error) {
	return nil, errors.New("AG-027 REGISTRY_UNINSTALL detection is only supported on Windows")
}

func (stubArpReader) Lookup(_ context.Context, _ string) (ArpEntry, bool, error) {
	return ArpEntry{}, false, errors.New("AG-027 REGISTRY_UNINSTALL detection is only supported on Windows")
}
