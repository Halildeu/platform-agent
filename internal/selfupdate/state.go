package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// state.go — cross-platform persistence of the ACTIVATED-version high-water
// mark (must-fix #3). The file lives in a protected per-machine directory
// (ProgramData on Windows; the DACL hardening of that directory is applied by
// the installer / PR1b). This layer is the portable read/write skeleton:
//
//   - PR1 READS the high-water mark and gates the version policy on it; it
//     NEVER advances it (a binary that is merely STAGED has not been ACTIVATED).
//   - PR3 advances it via WriteMaxSeen AFTER a successful activation.
//
// Fail-closed semantics:
//   - file absent            => ("", nil)   first install / no record yet
//   - file present but empty  => error       corrupt/truncated, treat as suspect
//   - read I/O error          => error       fail closed (do not assume "0")
//
// A present-but-empty file is treated as corruption rather than "first install"
// so that truncating the high-water file cannot silently re-open the anti-replay
// window — writing/truncating it already requires access to the protected dir,
// but defense-in-depth refuses the ambiguous state.

// FileHighWaterStore persists the high-water mark as a single trimmed version
// string in Path.
type FileHighWaterStore struct {
	Path string
}

// ReadMaxSeen implements HighWaterStore.
func (s FileHighWaterStore) ReadMaxSeen(_ context.Context) (string, error) {
	if strings.TrimSpace(s.Path) == "" {
		return "", errors.New("high-water store path is empty")
	}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil // first install / no record yet
		}
		return "", err // fail closed on any other read error
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", errors.New("high-water file present but empty (corrupt)")
	}
	// SemVer validity is enforced by EvaluateVersionPolicy (single authority);
	// returning the raw value keeps one validation point and yields a precise
	// POLICY_VERSION_UNPARSEABLE if it is malformed.
	return v, nil
}

// WriteMaxSeen atomically persists v as the new high-water mark (temp file in
// the same directory + rename). Intended for PR3 (post-activation); the Stager
// never calls it. v must be a parseable SemVer (validated here so a caller
// cannot persist garbage that would later fail-close every update).
//
// The containing directory is assumed to already exist with a hardened ACL
// (installer / PR1b); this function does not create or re-permission it.
func (s FileHighWaterStore) WriteMaxSeen(_ context.Context, v string) error {
	if strings.TrimSpace(s.Path) == "" {
		return errors.New("high-water store path is empty")
	}
	if _, err := ParseVersion(v); err != nil {
		return errors.New("refusing to persist unparseable high-water version")
	}
	dir := filepath.Dir(s.Path)
	tmp, err := os.CreateTemp(dir, ".highwater-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename

	if _, err := tmp.WriteString(strings.TrimSpace(v) + "\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.Path)
}
