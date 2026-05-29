//go:build windows

package dpapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"platform-agent/internal/autoenroll"
)

// hardenedSDDL pins the DACL applied to the persisted config file. It
// gives full access to LocalSystem and to BUILTIN\Administrators, and
// denies everyone else by default (`D:P` makes the DACL protected — no
// inheritance from the parent directory).
//
// Decoded:
//   O:SY                Owner = LocalSystem
//   G:SY                Group = LocalSystem
//   D:P                 DACL is protected (no inheritance)
//   (A;;FA;;;SY)        Allow Full Access — SY = LocalSystem
//   (A;;FA;;;BA)        Allow Full Access — BA = BUILTIN\Administrators
const hardenedSDDL = "O:SY G:SY D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// Read implements autoenroll.ConfigStore. ENOENT is translated into
// autoenroll.ErrEmptyStore so the runner can distinguish first-run from
// real I/O failure.
func (s *Store) Read(ctx context.Context) (autoenroll.PersistedConfig, error) {
	if err := ctx.Err(); err != nil {
		return autoenroll.PersistedConfig{}, err
	}
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		if isNotExist(err) {
			return autoenroll.PersistedConfig{}, autoenroll.ErrEmptyStore
		}
		return autoenroll.PersistedConfig{}, fmt.Errorf("read persisted blob: %w", err)
	}
	if len(raw) == 0 {
		return autoenroll.PersistedConfig{}, autoenroll.ErrEmptyStore
	}
	plain, err := Unprotect(raw, s.Entropy)
	if err != nil {
		return autoenroll.PersistedConfig{}, fmt.Errorf("dpapi unprotect: %w", err)
	}
	return decodeConfig(plain)
}

// Write implements autoenroll.ConfigStore with atomic semantics and DACL
// hardening on both the temp file and (after rename) the final path.
func (s *Store) Write(ctx context.Context, cfg autoenroll.PersistedConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	plain, err := encodeConfig(cfg)
	if err != nil {
		return err
	}
	cipher, err := Protect(plain, s.Entropy)
	if err != nil {
		return fmt.Errorf("dpapi protect: %w", err)
	}

	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := SetHardenedACL(dir); err != nil {
		return fmt.Errorf("harden dir acl: %w", err)
	}

	tmp := s.Path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open temp %s: %w", tmp, err)
	}
	cleanup := func() {
		_ = os.Remove(tmp)
	}
	if _, err := f.Write(cipher); err != nil {
		f.Close()
		cleanup()
		return fmt.Errorf("write temp %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return fmt.Errorf("fsync temp %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp %s: %w", tmp, err)
	}
	if err := SetHardenedACL(tmp); err != nil {
		cleanup()
		return fmt.Errorf("harden temp acl: %w", err)
	}
	if err := os.Rename(tmp, s.Path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmp, s.Path, err)
	}
	// Re-apply DACL on the final path in case rename did not carry it.
	if err := SetHardenedACL(s.Path); err != nil {
		return fmt.Errorf("harden final acl: %w", err)
	}
	return nil
}

// protect encrypts plain with CryptProtectData under
// CRYPTPROTECT_LOCAL_MACHINE so any process running as SYSTEM or as a
// member of Administrators on this machine can decrypt — but no
// other machine can. Entropy, when non-empty, binds the blob to this
// application.
func Protect(plain, entropy []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("dpapi: empty plaintext")
	}
	in := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var ent *windows.DataBlob
	if len(entropy) > 0 {
		ent = &windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, ent, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) //nolint:govet // OS-owned buffer release
	if out.Size == 0 || out.Data == nil {
		return nil, errors.New("dpapi: empty ciphertext")
	}
	buf := make([]byte, out.Size)
	copy(buf, unsafe.Slice(out.Data, out.Size))
	return buf, nil
}

// unprotect reverses protect. Codex F2 absorb: the flags argument to
// CryptUnprotectData must NOT carry CRYPTPROTECT_LOCAL_MACHINE — that flag
// is only meaningful on the protect side (scope selection). On the
// unprotect side it is rejected as ERROR_INVALID_PARAMETER on some
// Windows builds. We pass CRYPTPROTECT_UI_FORBIDDEN to make sure no UI
// prompt can ever appear from a SYSTEM service context.
func Unprotect(cipher, entropy []byte) ([]byte, error) {
	if len(cipher) == 0 {
		return nil, errors.New("dpapi: empty ciphertext")
	}
	in := windows.DataBlob{Size: uint32(len(cipher)), Data: &cipher[0]}
	var ent *windows.DataBlob
	if len(entropy) > 0 {
		ent = &windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) //nolint:govet // OS-owned buffer release
	if out.Size == 0 || out.Data == nil {
		return nil, errors.New("dpapi: empty plaintext")
	}
	buf := make([]byte, out.Size)
	copy(buf, unsafe.Slice(out.Data, out.Size))
	return buf, nil
}

// setHardenedACL applies hardenedSDDL to path using
// SetNamedSecurityInfo. The DACL replaces any existing one; ownership is
// forced to SYSTEM so a tampered owner cannot regrant access to itself.
func SetHardenedACL(path string) error {
	sd, err := windows.SecurityDescriptorFromString(hardenedSDDL)
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
