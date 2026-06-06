//go:build windows

package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const selfUpdateHardenedSDDL = "O:SY G:SY D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// WindowsStagingStore commits verified update bytes into a protected
// per-machine staging directory. It refuses reparse points and pre-existing
// targets; the returned path is local-only and never sent to the backend.
type WindowsStagingStore struct {
	Root string
}

// DefaultWindowsStagingRoot returns the AG-029 staging root under ProgramData.
func DefaultWindowsStagingRoot() string {
	root := os.Getenv("ProgramData")
	if root == "" {
		root = `C:\ProgramData`
	}
	return filepath.Join(root, "EndpointAgent", "self-update", "staging")
}

// DefaultWindowsHighWaterPath returns the local activated-version high-water
// path used by PR3. PR1b reads it when present and treats absence as first
// install.
func DefaultWindowsHighWaterPath() string {
	root := os.Getenv("ProgramData")
	if root == "" {
		root = `C:\ProgramData`
	}
	return filepath.Join(root, "EndpointAgent", "self-update", "max-activated-version.txt")
}

// Commit implements StagingStore.
func (s WindowsStagingStore) Commit(ctx context.Context, tempPath, stagingID string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	root := s.Root
	if root == "" {
		root = DefaultWindowsStagingRoot()
	}
	if stagingID == "" {
		return "", errors.New("staging id is empty")
	}
	if err := ensureHardenedDirectory(root); err != nil {
		return "", err
	}
	if err := rejectReparsePoint(root); err != nil {
		return "", err
	}

	staged := stagedNameFor(root, stagingID)
	if filepath.Dir(staged) != filepath.Clean(root) {
		return "", errors.New("staged path escapes the staging root")
	}
	if err := rejectReparsePoint(tempPath); err != nil {
		return "", err
	}
	if _, err := os.Lstat(staged); err == nil {
		return "", errors.New("staged target already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	from, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return "", fmt.Errorf("staging: utf16 source: %w", err)
	}
	to, err := windows.UTF16PtrFromString(staged)
	if err != nil {
		return "", fmt.Errorf("staging: utf16 target: %w", err)
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return "", fmt.Errorf("staging: atomic move: %w", err)
	}
	if err := rejectReparsePoint(staged); err != nil {
		return "", fmt.Errorf("staging: staged file reparse check: %w", err)
	}
	if err := setSelfUpdateHardenedACL(staged); err != nil {
		return "", fmt.Errorf("staging: harden staged file: %w", err)
	}
	return staged, nil
}

// PrepareTempDir implements the optional hardened temp-dir hook used by the
// stager before download. The verified bytes are downloaded inside the same
// protected root that Commit later uses for the no-overwrite atomic move.
func (s WindowsStagingStore) PrepareTempDir(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	root := s.Root
	if root == "" {
		root = DefaultWindowsStagingRoot()
	}
	if err := ensureHardenedDirectory(root); err != nil {
		return "", err
	}
	if err := rejectReparsePoint(root); err != nil {
		return "", err
	}
	return root, nil
}

func ensureHardenedDirectory(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("staging: mkdir root: %w", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("staging root is a symlink")
	}
	if !fi.IsDir() {
		return errors.New("staging root is not a directory")
	}
	if err := setSelfUpdateHardenedACL(path); err != nil {
		return fmt.Errorf("staging: harden root acl: %w", err)
	}
	return nil
}

func rejectReparsePoint(path string) error {
	if path == "" {
		return errors.New("path is empty")
	}
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("path is a reparse point")
	}
	return nil
}

func setSelfUpdateHardenedACL(path string) error {
	sd, err := windows.SecurityDescriptorFromString(selfUpdateHardenedSDDL)
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
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, group, dacl, nil)
}
