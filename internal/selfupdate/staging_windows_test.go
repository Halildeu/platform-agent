//go:build windows

package selfupdate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsStagingStoreCommitNoOverwrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "staging")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	skipIfCannotHardenACL(t, root)
	store := WindowsStagingStore{Root: root}
	stagingID := "0123456789abcdef0123456789abcdef"
	target := stagedNameFor(root, stagingID)
	if err := os.WriteFile(target, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(root, "candidate.tmp")
	if err := os.WriteFile(tmp, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), tmp, stagingID); err == nil {
		t.Fatal("expected no-overwrite staging refusal")
	}
}

func TestWindowsStagingStoreCommitMovesIntoHardenedRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "staging")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	skipIfCannotHardenACL(t, root)
	tmp := filepath.Join(root, "candidate.tmp")
	if err := os.WriteFile(tmp, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	staged, err := (WindowsStagingStore{Root: root}).Commit(context.Background(), tmp, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if filepath.Dir(staged) != filepath.Clean(root) {
		t.Fatalf("staged path escaped root: %s", staged)
	}
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("staged file missing: %v", err)
	}
}

func skipIfCannotHardenACL(t *testing.T, path string) {
	t.Helper()
	if err := setSelfUpdateHardenedACL(path); err != nil {
		t.Skipf("Windows self-update staging ACL hardening requires an elevated/SYSTEM context: %v", err)
	}
}
