//go:build windows

package dataprotection

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// longPathBuf is the GetFinalPathNameByHandle scratch size (chars). Windows
// long paths cap at 32767; we start here and grow if the API asks for more.
const longPathBuf = 32768

// volumeNameDOS is the GetFinalPathNameByHandle flags value requesting a
// normalized DOS-volume path (FILE_NAME_NORMALIZED | VOLUME_NAME_DOS). Both
// constituent flags are 0x0; x/sys/windows v0.43.0 does not export
// VOLUME_NAME_DOS, so it is pinned here.
const volumeNameDOS uint32 = 0x0

// windowsCanonicalizer resolves a path to its canonical DOS form using a
// METADATA-ONLY file handle. It is the production canonicalizer for the
// disabled-by-default 22.8A capability.
type windowsCanonicalizer struct{}

// NewCanonicalizer returns the platform canonicalizer.
func NewCanonicalizer() Canonicalizer { return windowsCanonicalizer{} }

// Canonicalize opens localPath with FILE_READ_ATTRIBUTES only — NO read
// access, NO GENERIC_READ — so the handle can never read content (invariant
// #1; asserted by backupmanifest_guard_test.go). FILE_FLAG_BACKUP_SEMANTICS
// allows opening a directory handle. FILE_FLAG_OPEN_REPARSE_POINT is
// deliberately NOT set so GetFinalPathNameByHandle resolves a junction/symlink
// to its real target (the walker then containment-checks that target and
// drops escapes). The reparse attribute is read separately so the walker can
// refuse to descend reparse-point directories.
func (windowsCanonicalizer) Canonicalize(localPath string) (string, bool, bool, error) {
	rawADS := strings.Contains(filepath.Base(localPath), ":")

	ptr, err := windows.UTF16PtrFromString(localPath)
	if err != nil {
		return "", false, rawADS, ErrManifestFailed
	}

	// Reparse attribute (read BEFORE resolution so the walker can skip descent).
	attrs, aerr := windows.GetFileAttributes(ptr)
	isReparse := aerr == nil && attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0

	h, err := windows.CreateFile(
		ptr,
		windows.FILE_READ_ATTRIBUTES, // metadata only — never GENERIC_READ
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, // open dirs; NOT OPEN_REPARSE_POINT
		0,
	)
	if err != nil {
		return "", isReparse, rawADS, ErrManifestFailed
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, longPathBuf)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), volumeNameDOS)
	if err != nil {
		return "", isReparse, rawADS, ErrManifestFailed
	}
	if int(n) > len(buf) {
		buf = make([]uint16, n)
		n, err = windows.GetFinalPathNameByHandle(h, &buf[0], n, volumeNameDOS)
		if err != nil {
			return "", isReparse, rawADS, ErrManifestFailed
		}
	}
	final := stripExtendedPrefix(windows.UTF16ToString(buf[:n]))

	hasADS := rawADS || adsBeyondDrive(final)
	return final, isReparse, hasADS, nil
}

// stripExtendedPrefix normalizes the `\\?\` extended-length forms that
// GetFinalPathNameByHandle returns into the conventional canonical path the
// containment check + denylist segment matcher expect:
//
//	\\?\C:\Users\x      -> C:\Users\x
//	\\?\UNC\srv\share\x -> \\srv\share\x
func stripExtendedPrefix(p string) string {
	switch {
	case strings.HasPrefix(p, `\\?\UNC\`):
		return `\\` + p[len(`\\?\UNC\`):]
	case strings.HasPrefix(p, `\\?\`):
		return p[len(`\\?\`):]
	default:
		return p
	}
}

// adsBeyondDrive reports an NTFS alternate-data-stream designator that appears
// after the `<DRIVE>:` prefix (e.g. `C:\foo.docx:secret`). The single legit
// colon is the drive designator at index 1.
func adsBeyondDrive(p string) bool {
	if len(p) >= 2 && p[1] == ':' {
		return strings.Contains(p[2:], ":")
	}
	return strings.Contains(p, ":")
}
