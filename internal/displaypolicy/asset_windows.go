//go:build windows

package displaypolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// The desktop renders the wallpaper with the signed-in user's token, so Users
// need read access; nobody but SYSTEM and Administrators may write. The DACL
// is protected (P) so nothing is inherited from ProgramData, where Users may
// create files, and the owner is SYSTEM so a user who pre-created the
// directory keeps no owner rights over it.
const (
	wallpaperDirSDDL  = "O:SY G:SY D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	wallpaperFileSDDL = "O:SY G:SY D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
)

// DefaultWallpaperRoot is where managed wallpapers are stored.
func DefaultWallpaperRoot() string {
	root := os.Getenv("ProgramData")
	if root == "" {
		root = `C:\ProgramData`
	}
	return filepath.Join(root, "EndpointAgent", "wallpaper")
}

// DefaultAssetStore returns the hardened per-machine wallpaper store.
func DefaultAssetStore() AssetStore {
	return WindowsAssetStore{Root: DefaultWallpaperRoot()}
}

// WindowsAssetStore commits verified wallpaper bytes into a hardened directory.
// It refuses reparse points on the directory, its parent and the target, and
// writes through an exclusive temp file plus an atomic replace, so a planted
// link or file is never written through or reused.
type WindowsAssetStore struct {
	Root string
	// DirSDDL / FileSDDL override the security descriptors (tests that do not
	// run as SYSTEM cannot assign SYSTEM as owner). Empty means the defaults.
	DirSDDL  string
	FileSDDL string
}

// Commit implements AssetStore.
func (s WindowsAssetStore) Commit(name string, content []byte) (string, error) {
	if s.Root == "" {
		return "", errors.New("wallpaper store root is empty")
	}
	if name == "" || filepath.Base(name) != name {
		return "", fmt.Errorf("invalid wallpaper file name %q", name)
	}
	if err := s.ensureDirectory(); err != nil {
		return "", err
	}
	target := filepath.Join(s.Root, name)

	tmp, err := os.CreateTemp(s.Root, ".wallpaper-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	moved := false
	defer func() {
		if !moved {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("flush temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp file: %w", err)
	}
	if err := rejectReparsePoint(tmpPath); err != nil {
		return "", err
	}

	from, err := windows.UTF16PtrFromString(tmpPath)
	if err != nil {
		return "", err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return "", err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return "", fmt.Errorf("replace wallpaper file: %w", err)
	}
	moved = true
	if err := rejectReparsePoint(target); err != nil {
		return "", err
	}
	if err := applySDDL(target, s.fileSDDL()); err != nil {
		return "", fmt.Errorf("harden wallpaper file: %w", err)
	}
	return target, nil
}

func (s WindowsAssetStore) ensureDirectory() error {
	parent := filepath.Dir(s.Root)
	if err := rejectReparsePoint(parent); err != nil {
		return fmt.Errorf("wallpaper store parent: %w", err)
	}
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return fmt.Errorf("create wallpaper store: %w", err)
	}
	fi, err := os.Lstat(s.Root)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return errors.New("wallpaper store is not a plain directory")
	}
	if err := rejectReparsePoint(s.Root); err != nil {
		return fmt.Errorf("wallpaper store: %w", err)
	}
	if err := applySDDL(s.Root, s.dirSDDL()); err != nil {
		return fmt.Errorf("harden wallpaper store: %w", err)
	}
	return nil
}

func (s WindowsAssetStore) dirSDDL() string {
	if s.DirSDDL != "" {
		return s.DirSDDL
	}
	return wallpaperDirSDDL
}

func (s WindowsAssetStore) fileSDDL() string {
	if s.FileSDDL != "" {
		return s.FileSDDL
	}
	return wallpaperFileSDDL
}

func rejectReparsePoint(path string) error {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a reparse point", path)
	}
	return nil
}

// applySDDL sets the DACL (protected) and, when the descriptor names them, the
// owner and group.
func applySDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse sddl: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read dacl: %w", err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read owner: %w", err)
	}
	if owner != nil {
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	group, _, err := sd.Group()
	if err != nil {
		return fmt.Errorf("read group: %w", err)
	}
	if group != nil {
		info |= windows.GROUP_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil)
}
