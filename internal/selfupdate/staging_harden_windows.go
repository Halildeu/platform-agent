//go:build windows

package selfupdate

import "platform-agent/internal/platform/windows/acl"

func hardenStagedFile(path string) error {
	return acl.SetHardenedACL(path)
}
