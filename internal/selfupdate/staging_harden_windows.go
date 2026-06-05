//go:build windows

package selfupdate

import "platform-agent/internal/platform/windows/dpapi"

func hardenStagedFile(path string) error {
	return dpapi.SetHardenedACL(path)
}
