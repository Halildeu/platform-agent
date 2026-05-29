// Package hmacstore persists the HMAC device credential that the agent
// receives from the backend's POST /enrollments/consume response. The
// credential is the (CredentialKeyID, Secret, DeviceID) tuple the agent
// signs every subsequent /heartbeat, /commands/next and /commands/.../result
// request with.
//
// Why a separate package from internal/platform/windows/dpapi?
//
// dpapi is tightly bound to autoenroll.PersistedConfig (the AD CS cert
// thumbprint + service-token model). The HMAC manual-enrollment path
// stores a different credential shape, has a different invalidation
// lifecycle (no cert thumbprint changes — only backend-issued 401
// triggers re-enroll), and must NOT pull the autoenroll type into its
// surface (Codex 019e7314 constraint #1, "auto-enroll tipini HMAC içine
// taşımak kabul değil"). Keeping the two stores siblings avoids the
// auto-enroll <-> manual-enroll coupling that breaking changes would
// otherwise propagate across.
//
// Wire model:
//   - Windows: DPAPI machine-scope (CRYPTPROTECT_LOCAL_MACHINE) encrypted
//     JSON blob, atomic temp-then-rename write, file DACL hardened to
//     SYSTEM + Administrators only. Default path
//     %ProgramData%\EndpointAgent\config\hmac-credential.dpapi.
//   - Non-Windows: ErrUnsupportedOS for both Read and Write so darwin
//     and linux builds compile and unit-test without pulling DPAPI but
//     the runner does not silently get a no-op store. Codex 019e7314
//     constraint #2 — "Windows'ta DPAPI store, non-Windows'ta explicit
//     no-op/memory/dev store seçilmeli". The runner is expected to skip
//     persistence wiring entirely on non-Windows; persistence is a
//     Windows-only invariant of the production agent.
//
// Tamper protection: per Codex 019e7314 constraint #4, Read returning a
// decryption / decode error MUST NOT trigger automatic Delete in the
// runner. The store exposes Invalidate (rename to ".invalid") as the
// explicit destructive operation; callers may also call Delete when the
// credential has been replaced by a successful Write.
package hmacstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Errors exported for callers that need to branch on store state.
var (
	// ErrEmpty is returned by Read when no credential has been persisted
	// yet (file does not exist or has zero length). Distinguishes
	// first-run from a real I/O failure.
	ErrEmpty = errors.New("hmac credential store is empty")

	// ErrUnsupportedOS is returned by Read and Write on non-Windows
	// builds. Callers must not treat this as a transient error — the
	// agent runtime is expected to skip persistence entirely on
	// non-Windows.
	ErrUnsupportedOS = errors.New("hmac credential persistence is Windows-only")

	// ErrInvalid is returned by Read when the persisted blob decodes
	// but fails Validate (zero fields, expired ServerTime). The runner
	// must NOT silently re-enroll on this — Codex 019e7314 constraint
	// #4. Callers should quarantine via Invalidate.
	ErrInvalid = errors.New("persisted hmac credential is invalid")
)

// Credential is the persisted device credential.
//
// All four fields are required for Validate to pass. ServerTime is the
// backend's clock at enrollment (so post-restart skew detection is
// possible); Issued is the agent's wall clock (for staleness telemetry).
type Credential struct {
	DeviceID        string    `json:"device_id"`
	CredentialKeyID string    `json:"credential_key_id"`
	Secret          string    `json:"secret"`
	ServerTime      time.Time `json:"server_time"`
	Issued          time.Time `json:"issued"`
}

// IsZero reports whether the credential has not been populated.
func (c Credential) IsZero() bool {
	return c.DeviceID == "" && c.CredentialKeyID == "" && c.Secret == ""
}

// Validate enforces the persisted-credential invariants the runner relies
// on after a successful Read. All three identity fields must be non-empty
// (an empty Secret would silently produce broken signatures on every
// signed request) and Issued must be non-zero (so the runner can
// distinguish a legitimate-but-old credential from a corrupt blob).
//
// ServerTime is allowed to be zero on Validate — older persisted blobs
// from agents that predate this field still parse, but a fresh Write
// always sets ServerTime from the backend response. This avoids
// gratuitously invalidating credentials on first upgrade.
func (c Credential) Validate() error {
	if c.IsZero() {
		return ErrEmpty
	}
	if strings.TrimSpace(c.DeviceID) == "" {
		return fmt.Errorf("%w: device_id empty", ErrInvalid)
	}
	if strings.TrimSpace(c.CredentialKeyID) == "" {
		return fmt.Errorf("%w: credential_key_id empty", ErrInvalid)
	}
	if strings.TrimSpace(c.Secret) == "" {
		return fmt.Errorf("%w: secret empty", ErrInvalid)
	}
	if c.Issued.IsZero() {
		return fmt.Errorf("%w: issued timestamp zero", ErrInvalid)
	}
	return nil
}

// Store reads, writes, and quarantines the persisted credential. The
// platform-specific Read and Write are in store_windows.go and
// store_other.go; this file holds only the shared decode/encode and the
// platform-agnostic Invalidate / Delete operations.
type Store struct {
	// Path is the on-disk location of the encrypted blob. Empty falls
	// back to DefaultPath().
	Path string
	// Entropy, when non-empty, is mixed into the DPAPI ciphertext to
	// bind the blob to this specific application. Production deployments
	// should pin this to a constant so a rogue process on the same
	// machine cannot decrypt the blob even with LOCAL_MACHINE scope.
	Entropy []byte
}

// New returns a Store rooted at path. Empty path falls back to
// DefaultPath(). The entropy is defensively copied so a caller mutating
// its byte slice after construction does not invalidate the blob.
func New(path string, entropy []byte) *Store {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	return &Store{Path: path, Entropy: append([]byte(nil), entropy...)}
}

// DefaultPath returns the production location for the persisted
// credential on Windows: %ProgramData%\EndpointAgent\config\hmac-credential.dpapi.
// On non-Windows the function is still callable (it does not touch the
// OS) but the returned path is informational only — the non-Windows
// Store rejects all reads and writes.
func DefaultPath() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "EndpointAgent", "config", "hmac-credential.dpapi")
	}
	return filepath.Join("C:", "ProgramData", "EndpointAgent", "config", "hmac-credential.dpapi")
}

// decodeCredential is the shared decode path. Exposed at package level so
// the platform-specific Read methods can share the same JSON contract.
func decodeCredential(plaintext []byte) (Credential, error) {
	var cred Credential
	if len(plaintext) == 0 {
		return cred, fmt.Errorf("empty plaintext")
	}
	if err := json.Unmarshal(plaintext, &cred); err != nil {
		return Credential{}, fmt.Errorf("decode hmac credential: %w", err)
	}
	return cred, nil
}

// encodeCredential is the inverse of decodeCredential.
func encodeCredential(cred Credential) ([]byte, error) {
	data, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode hmac credential: %w", err)
	}
	return data, nil
}

// Delete removes the persisted blob. Used by the installer when
// uninstalling the agent or by callers that have a fresher credential
// from a successful Write (which already does atomic replace via
// rename). Non-existence is not an error.
func (s *Store) Delete(_ context.Context) error {
	if err := os.Remove(s.Path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete hmac credential: %w", err)
	}
	return nil
}

// Invalidate quarantines the persisted blob by renaming it to
// "<path>.invalid". Used by the runner when Validate fails on Read so
// operators can inspect the corrupt blob without the agent silently
// re-enrolling on every iteration. Codex 019e7314 constraint #4.
//
// If the path does not exist, Invalidate returns nil (idempotent).
func (s *Store) Invalidate(_ context.Context) error {
	target := s.Path + ".invalid"
	if err := os.Rename(s.Path, target); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("invalidate hmac credential: %w", err)
	}
	return nil
}

// isNotExist normalises the OS not-exist error so callers can map it
// onto ErrEmpty without depending on os.IsNotExist quirks on weird VFSes.
func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || os.IsNotExist(err)
}
