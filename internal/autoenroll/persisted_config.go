package autoenroll

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// (errors used by Validate are declared at the bottom of the file.)

// PersistedConfig is the on-disk state the agent owns between runs. It is
// stored DPAPI-encrypted with machine scope and a hardened DACL on Windows;
// on non-Windows builds a plaintext file store is available behind an
// explicit opt-in for dev/test only.
//
// The persisted state is deliberately MINIMAL — no secrets that the backend
// can re-derive, no env-overridable fields. Token storage lives only here;
// it must never be written to env or logged (Codex F3 absorb).
type PersistedConfig struct {
	DeviceID             string    `json:"device_id"`
	ServiceToken         string    `json:"service_token"`
	TokenExpiresAt       time.Time `json:"token_expires_at"`
	CertThumbprintSHA256 string    `json:"cert_thumbprint_sha256"`
	CertThumbprintSHA1   string    `json:"cert_thumbprint_sha1,omitempty"`
	Issued               time.Time `json:"issued"`
}

// IsZero reports whether the config has not yet been populated (no
// successful enrollment has run). Used by Runner to decide between the
// first-run auto-enroll path and the heartbeat/command loop.
func (p PersistedConfig) IsZero() bool {
	return p.DeviceID == "" && p.ServiceToken == ""
}

// Validate enforces the persisted-config invariants the runner relies on
// after a successful enroll or refresh. A response missing any of the
// mandatory fields means the backend contract drifted (or a corrupted
// blob was decoded) and the runner must NOT silently continue — Codex
// F4 absorb. Validate is called both after Wire decode and before the
// runner uses a snapshot loaded from disk.
func (p PersistedConfig) Validate() error {
	if p.IsZero() {
		return ErrEmptyStore
	}
	if p.DeviceID == "" {
		return fmt.Errorf("%w: device_id empty", ErrInvalidPersistedConfig)
	}
	if p.ServiceToken == "" {
		return fmt.Errorf("%w: service_token empty", ErrInvalidPersistedConfig)
	}
	if p.TokenExpiresAt.IsZero() {
		return fmt.Errorf("%w: token_expires_at zero", ErrInvalidPersistedConfig)
	}
	if p.CertThumbprintSHA256 == "" {
		return fmt.Errorf("%w: cert_thumbprint_sha256 empty", ErrInvalidPersistedConfig)
	}
	return nil
}

// ErrInvalidPersistedConfig is returned by Validate when the snapshot
// fails its required-field check. The runner treats this as fatal —
// silently continuing with a half-populated config risks heartbeat
// loops with an empty bearer token, which the backend cannot
// distinguish from "no token" and which would mask a real config drift.
var ErrInvalidPersistedConfig = errors.New("persisted config is invalid")

// TokenExpired reports whether the persisted token's TTL has elapsed. The
// agent must then take the idempotent auto-enroll reissue path rather than
// /service-token/refresh — refresh requires a non-expired bearer (Codex F11
// absorb).
func (p PersistedConfig) TokenExpired(now time.Time) bool {
	return !p.TokenExpiresAt.IsZero() && !now.Before(p.TokenExpiresAt)
}

// TokenExpiringWithin reports whether the persisted token will expire within
// d. Triggers the standard refresh path.
func (p PersistedConfig) TokenExpiringWithin(now time.Time, d time.Duration) bool {
	if p.TokenExpiresAt.IsZero() {
		return false
	}
	return p.TokenExpiresAt.Sub(now) < d
}

// CertThumbprintChanged reports whether the freshly loaded cert thumbprint
// differs from the persisted one. A change indicates AD CS renewal has minted
// a new cert and the agent must reissue (idempotent /endpoint-enrollments/auto)
// to rebind the service token to the new cert identity (Codex F2 absorb).
func (p PersistedConfig) CertThumbprintChanged(currentSHA256 string) bool {
	return p.CertThumbprintSHA256 != "" && p.CertThumbprintSHA256 != currentSHA256
}

// ConfigStore reads and writes PersistedConfig. Implementations must ensure
// Write is atomic — Codex F5 absorb (temp file + fsync + rename, plus DACL
// hardening on Windows). Read returns a zero PersistedConfig and nil error
// when the store is empty (no enrollment yet) — distinguishing "empty store"
// from "store error" matters for the first-run branch.
type ConfigStore interface {
	Read(ctx context.Context) (PersistedConfig, error)
	Write(ctx context.Context, cfg PersistedConfig) error
}

// ErrEmptyStore is returned by Read when the underlying file does not
// exist. Wrapping it lets callers distinguish first-run from real I/O
// errors. Production stores translate ENOENT into this sentinel.
var ErrEmptyStore = errors.New("persisted config store is empty")

// IsEmptyStore reports whether an error is the empty-store sentinel.
func IsEmptyStore(err error) bool {
	return errors.Is(err, ErrEmptyStore)
}

// MemoryStore is an in-memory ConfigStore for tests. Concurrent access is
// safe; Write replaces the entire snapshot atomically.
type MemoryStore struct {
	mu  sync.RWMutex
	cfg PersistedConfig
	set bool
	// FailNextRead, when non-nil, is returned by the next Read call and then
	// cleared. Lets tests exercise the I/O error branch.
	FailNextRead error
	// FailNextWrite, when non-nil, is returned by the next Write call and
	// then cleared.
	FailNextWrite error
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

// Read implements ConfigStore.
func (s *MemoryStore) Read(ctx context.Context) (PersistedConfig, error) {
	s.mu.Lock()
	if s.FailNextRead != nil {
		err := s.FailNextRead
		s.FailNextRead = nil
		s.mu.Unlock()
		return PersistedConfig{}, err
	}
	s.mu.Unlock()

	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.set {
		return PersistedConfig{}, ErrEmptyStore
	}
	// Defensive deep copy via JSON to keep the caller from mutating the
	// internal snapshot.
	data, err := json.Marshal(s.cfg)
	if err != nil {
		return PersistedConfig{}, fmt.Errorf("memory store: marshal copy: %w", err)
	}
	var out PersistedConfig
	if err := json.Unmarshal(data, &out); err != nil {
		return PersistedConfig{}, fmt.Errorf("memory store: unmarshal copy: %w", err)
	}
	return out, nil
}

// Write implements ConfigStore.
func (s *MemoryStore) Write(ctx context.Context, cfg PersistedConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FailNextWrite != nil {
		err := s.FailNextWrite
		s.FailNextWrite = nil
		return err
	}
	s.cfg = cfg
	s.set = true
	return nil
}

// Snapshot returns the current stored config without flagging consumption
// errors. Helper for assertions in tests.
func (s *MemoryStore) Snapshot() (PersistedConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg, s.set
}
