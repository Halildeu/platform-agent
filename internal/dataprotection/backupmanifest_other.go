//go:build !windows

package dataprotection

import (
	"os"
	"path/filepath"
	"strings"
)

// otherCanonicalizer is the non-Windows canonicalizer. The 22.8A capability is
// only advertised on Windows; this implementation exists so the package
// compiles, the OS-agnostic walker/denylist logic is unit-testable on
// developer/CI machines (symlink-escape, reparse, containment), and a
// non-Windows agent fails closed rather than panicking.
type otherCanonicalizer struct{}

// NewCanonicalizer returns the platform canonicalizer.
func NewCanonicalizer() Canonicalizer { return otherCanonicalizer{} }

// Canonicalize resolves symlinks (so an escaping symlink's target is checked
// against the managed root by the walker) and reports whether localPath is
// itself a symlink (treated as a reparse point — never descended). It opens
// nothing for reading; os.Lstat + filepath.EvalSymlinks are metadata/path
// operations only.
func (otherCanonicalizer) Canonicalize(localPath string) (string, bool, bool, error) {
	hasADS := strings.Contains(filepath.Base(localPath), ":")

	li, err := os.Lstat(localPath)
	if err != nil {
		return "", false, hasADS, ErrManifestFailed
	}
	isReparse := li.Mode()&os.ModeSymlink != 0

	resolved, rerr := filepath.EvalSymlinks(localPath)
	if rerr != nil {
		resolved = localPath
	}
	abs, aerr := filepath.Abs(resolved)
	if aerr != nil {
		return "", isReparse, hasADS, ErrManifestFailed
	}
	return filepath.Clean(abs), isReparse, hasADS, nil
}
