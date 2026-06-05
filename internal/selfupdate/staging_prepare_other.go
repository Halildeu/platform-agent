//go:build !windows

package selfupdate

// PrepareProtectedStagingDir is Windows-only in AG-029 v1. Non-Windows agents
// must not create partial staging state or advertise UPDATE_AGENT capability.
func PrepareProtectedStagingDir(root, stagingID string) (StagingPaths, ErrorCode, string) {
	if _, code, reason := BuildStagingPaths(root, stagingID); code != "" {
		return StagingPaths{}, code, reason
	}
	return StagingPaths{}, ErrUnsupportedPlatform, "self-update staging is windows-only in v1"
}
