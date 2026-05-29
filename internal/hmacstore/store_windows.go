//go:build windows

package hmacstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"platform-agent/internal/platform/windows/dpapi"
)

// Read decrypts the persisted blob with DPAPI machine-scope and decodes
// the JSON payload. Returns ErrEmpty when the file does not exist or has
// zero length (first-run / clean install). Returns ErrInvalid (wrapped)
// when the blob decrypts and decodes but fails Validate — the runner
// must NOT auto-delete in that case (Codex 019e7314 constraint #4); the
// caller should use Invalidate to quarantine if it wants to force
// re-enrollment.
func (s *Store) Read(ctx context.Context) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		if isNotExist(err) {
			return Credential{}, ErrEmpty
		}
		return Credential{}, fmt.Errorf("read hmac credential blob: %w", err)
	}
	if len(raw) == 0 {
		return Credential{}, ErrEmpty
	}
	plain, err := dpapi.Unprotect(raw, s.Entropy)
	if err != nil {
		return Credential{}, fmt.Errorf("dpapi unprotect hmac credential: %w", err)
	}
	cred, err := decodeCredential(plain)
	if err != nil {
		return Credential{}, err
	}
	if err := cred.Validate(); err != nil {
		return cred, err
	}
	return cred, nil
}

// Write encrypts the credential with DPAPI machine-scope and writes it
// atomically (temp + fsync + ACL harden + rename + ACL re-harden) so a
// crash mid-write cannot leave a half-written / world-readable blob on
// disk. The file DACL is restricted to SYSTEM + Administrators only
// (matches the autoenroll DPAPI store).
//
// Validate is called BEFORE encrypt so we never persist a structurally
// invalid credential; the call returns a clear error to the caller
// instead of writing an unreadable blob that Read would later treat as
// ErrInvalid.
func (s *Store) Write(ctx context.Context, cred Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cred.Validate(); err != nil {
		return fmt.Errorf("refuse to persist invalid hmac credential: %w", err)
	}

	plain, err := encodeCredential(cred)
	if err != nil {
		return err
	}
	cipher, err := dpapi.Protect(plain, s.Entropy)
	if err != nil {
		return fmt.Errorf("dpapi protect hmac credential: %w", err)
	}

	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := dpapi.SetHardenedACL(dir); err != nil {
		return fmt.Errorf("harden hmac config dir acl: %w", err)
	}

	tmp := s.Path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open hmac credential temp %s: %w", tmp, err)
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.Write(cipher); err != nil {
		f.Close()
		cleanup()
		return fmt.Errorf("write hmac credential temp %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return fmt.Errorf("fsync hmac credential temp %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close hmac credential temp %s: %w", tmp, err)
	}
	if err := dpapi.SetHardenedACL(tmp); err != nil {
		cleanup()
		return fmt.Errorf("harden hmac credential temp acl: %w", err)
	}
	if err := os.Rename(tmp, s.Path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmp, s.Path, err)
	}
	// Re-apply DACL on the final path in case rename did not carry it
	// (parity with the autoenroll DPAPI store, Codex iter-3 guardrail).
	if err := dpapi.SetHardenedACL(s.Path); err != nil {
		return fmt.Errorf("harden hmac credential final acl: %w", err)
	}
	return nil
}
