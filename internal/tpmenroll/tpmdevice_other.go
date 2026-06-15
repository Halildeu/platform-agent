//go:build !windows

package tpmenroll

import "fmt"

// NewWindowsTPMDevice is unavailable off Windows — the hardware path needs
// Windows TBS. Tests + non-Windows builds use MockTPMDevice. Keeping the same
// signature on every platform lets cmd/endpoint-agent reference it unconditionally
// (it only invokes it on Windows).
func NewWindowsTPMDevice() (TPMDevice, error) {
	return nil, fmt.Errorf("tpmenroll: hardware TPM enrollment requires Windows (TBS); use MockTPMDevice elsewhere")
}
