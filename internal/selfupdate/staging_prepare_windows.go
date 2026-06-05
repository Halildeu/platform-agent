//go:build windows

package selfupdate

import (
	"fmt"
	"os"

	"platform-agent/internal/platform/windows/dpapi"
)

// PrepareProtectedStagingDir creates the per-request staging directory and
// replaces its DACL with the hardened SYSTEM + Administrators-only policy used
// by the DPAPI credential store. No binary is written here; PR1's downloader
// writes only after policy, hash, and Authenticode gates are clean.
func PrepareProtectedStagingDir(root, stagingID string) (StagingPaths, ErrorCode, string) {
	paths, code, reason := BuildStagingPaths(root, stagingID)
	if code != "" {
		return StagingPaths{}, code, reason
	}
	if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
		return StagingPaths{}, ErrStagingIO, "create protected staging directory failed"
	}
	if err := dpapi.SetHardenedACL(paths.Directory); err != nil {
		return StagingPaths{}, ErrStagingIO, fmt.Sprintf("harden protected staging directory acl failed: %v", err)
	}
	return paths, "", ""
}
