//go:build !windows

package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

// staging_portable.go — non-windows StagingStore for tests and dev only. The
// PRODUCTION staging store is the DACL-hardened windows implementation (PR1b);
// self-update itself is windows-only (the preflight platform gate refuses other
// OSes), so this portable store never runs in production. It still enforces the
// platform-independent safety invariants — no overwrite, no symlinked root, the
// staged path stays inside the root — so the orchestration tests exercise them.

// PortableStagingStore commits verified bytes into Root via an atomic rename.
type PortableStagingStore struct {
	Root string
}

// Commit implements StagingStore for non-windows test/dev use.
func (p PortableStagingStore) Commit(_ context.Context, tempPath, stagingID string) (string, error) {
	if p.Root == "" {
		return "", errors.New("staging root is empty")
	}
	if stagingID == "" {
		return "", errors.New("staging id is empty")
	}
	// The staging root must be a real directory, not a symlink/reparse point
	// (defense-in-depth; the windows store additionally checks junctions).
	fi, err := os.Lstat(p.Root)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("staging root is a symlink")
	}
	if !fi.IsDir() {
		return "", errors.New("staging root is not a directory")
	}

	staged := stagedNameFor(p.Root, stagingID)
	// Confine the resolved staged path to the root (no traversal via a crafted id).
	if filepath.Dir(staged) != filepath.Clean(p.Root) {
		return "", errors.New("staged path escapes the staging root")
	}
	// No overwrite: a pre-existing target is a collision / tamper signal.
	if _, err := os.Lstat(staged); err == nil {
		return "", errors.New("staged target already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	if err := os.Rename(tempPath, staged); err != nil {
		return "", err
	}
	return staged, nil
}
