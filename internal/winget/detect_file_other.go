//go:build !windows

package winget

import (
	"context"
	"errors"
)

// detect_file_other.go — cross-platform stub for FILE_VERSION on
// non-Windows builds. FILE_VERSION reads PE VersionInfo, which is a
// Windows-only resource format. Catalog rules pinned to FILE_VERSION
// hitting a non-Windows agent return a typed error so the executor
// maps to FinalStatusFailedUnsupportedPlatform (mirrors the AG-027
// install_winget_other.go pattern).
//
// FILE_EXISTS / FILE_SHA256 do work cross-platform — both probes live
// in detect_file.go and use os.Stat / os.Open which are portable.

var errFileVersionUnsupported = errors.New(
	"path C1: FILE_VERSION is not implemented on non-Windows platforms")

func probeFileVersionPlatform(_ context.Context, _ DetectionRule) (PreDetectResult, error) {
	return PreDetectResult{DetectionMethod: DetectionMethodFileVersion},
		errFileVersionUnsupported
}
