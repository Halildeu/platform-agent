//go:build windows

package acl

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// HardenedSystemAdministratorsSDDL pins writable access to LocalSystem and
// BUILTIN\Administrators, with inheritance disabled. It is intentionally kept
// dependency-light so callers that already sit below higher-level packages do
// not introduce import cycles.
//
// Decoded:
//
//	O:SY                Owner = LocalSystem
//	G:SY                Group = LocalSystem
//	D:P                 DACL is protected (no inheritance)
//	(A;;FA;;;SY)        Allow Full Access — SY = LocalSystem
//	(A;;FA;;;BA)        Allow Full Access — BA = BUILTIN\Administrators
const HardenedSystemAdministratorsSDDL = "O:SY G:SY D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// SetHardenedACL applies HardenedSystemAdministratorsSDDL to path using
// SetNamedSecurityInfo. The DACL replaces any existing one; ownership is
// forced to SYSTEM so a tampered owner cannot regrant access to itself.
func SetHardenedACL(path string) error {
	sd, err := windows.SecurityDescriptorFromString(HardenedSystemAdministratorsSDDL)
	if err != nil {
		return fmt.Errorf("parse sddl: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read owner from sddl: %w", err)
	}
	group, _, err := sd.Group()
	if err != nil {
		return fmt.Errorf("read group from sddl: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read dacl from sddl: %w", err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION |
		windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION |
		windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil); err != nil {
		return fmt.Errorf("set named security info: %w", err)
	}
	return nil
}
