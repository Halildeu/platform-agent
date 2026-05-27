// Package dpapi persists the auto-enroll PersistedConfig as a
// DPAPI-protected machine-scope blob on disk, with a hardened DACL that
// restricts read/write to SYSTEM + Administrators. Non-Windows builds
// expose the same Store type but always return ErrUnsupportedOS so the
// auto-enroll runner can compile and unit-test on darwin/linux.
//
// Atomic write semantics: writes go to a "<path>.tmp" first, are
// fsync'd, ACL-hardened, then os.Rename'd onto <path>. The final path's
// ACL is re-applied after rename to defend against edge cases where
// rename does not carry the temp file's DACL (Codex iter-3 guardrail).
package dpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"platform-agent/internal/autoenroll"
)

// DefaultPath returns the production location for the persisted config on
// Windows: %ProgramData%\EndpointAgent\config\auto-enroll.dpapi. On
// non-Windows the function is still callable (it does not touch the OS)
// but the returned path is informational only — the non-Windows Store
// rejects all reads/writes.
func DefaultPath() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "EndpointAgent", "config", "auto-enroll.dpapi")
	}
	return filepath.Join("C:", "ProgramData", "EndpointAgent", "config", "auto-enroll.dpapi")
}

// Store implements autoenroll.ConfigStore. On Windows it encrypts/decrypts
// via CryptProtectData with CRYPTPROTECT_LOCAL_MACHINE and hardens the
// file DACL; on non-Windows it always returns autoenroll.ErrUnsupportedOS.
type Store struct {
	// Path is the on-disk location of the encrypted blob.
	Path string
	// Entropy, when non-empty, is mixed into the DPAPI ciphertext to bind
	// the blob to this specific application. Production deployments
	// should pin this to a constant so a rogue process on the same
	// machine cannot decrypt the blob even with LOCAL_MACHINE scope.
	Entropy []byte
}

// New returns a Store rooted at path. Empty path falls back to
// DefaultPath().
func New(path string, entropy []byte) *Store {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	return &Store{Path: path, Entropy: append([]byte(nil), entropy...)}
}

// readBlob is the shared decode path used by both the Windows
// implementation (after Unprotect) and the non-Windows tests-via-stub.
// It is unexported because the Windows backend embeds the encryption
// step before calling it.
func decodeConfig(plaintext []byte) (autoenroll.PersistedConfig, error) {
	var cfg autoenroll.PersistedConfig
	if len(plaintext) == 0 {
		return cfg, fmt.Errorf("empty plaintext")
	}
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		return autoenroll.PersistedConfig{}, fmt.Errorf("decode persisted config: %w", err)
	}
	return cfg, nil
}

// encodeConfig is the inverse of decodeConfig.
func encodeConfig(cfg autoenroll.PersistedConfig) ([]byte, error) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode persisted config: %w", err)
	}
	return data, nil
}

// isNotExist normalises the OS not-exist error so callers can map it
// onto autoenroll.ErrEmptyStore without depending on os.IsNotExist
// quirks on weird VFSes.
func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || os.IsNotExist(err)
}

// Compile-time guard: Store satisfies autoenroll.ConfigStore on every
// build. The interface methods themselves live in the build-tagged files
// so darwin/linux builds get the stub and Windows builds get the real
// implementation; this line catches accidental drift.
var _ autoenroll.ConfigStore = (*Store)(nil)

// Read implements autoenroll.ConfigStore. The platform-specific files
// override this method; this default returns ErrUnsupportedOS so
// accidentally instantiating the struct without a platform build leaves
// no doubt about the missing functionality.
func (s *Store) read(ctx context.Context) (autoenroll.PersistedConfig, error) {
	return autoenroll.PersistedConfig{}, autoenroll.ErrUnsupportedOS
}

func (s *Store) write(ctx context.Context, cfg autoenroll.PersistedConfig) error {
	return autoenroll.ErrUnsupportedOS
}
