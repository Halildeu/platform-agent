package autoenroll

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPersistedConfig_IsZero(t *testing.T) {
	if !(PersistedConfig{}).IsZero() {
		t.Fatal("zero value should be IsZero")
	}
	if (PersistedConfig{DeviceID: "x", ServiceToken: "y"}).IsZero() {
		t.Fatal("populated config should not be IsZero")
	}
}

func TestPersistedConfig_TokenExpired(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	cfg := PersistedConfig{TokenExpiresAt: now.Add(-time.Minute)}
	if !cfg.TokenExpired(now) {
		t.Fatal("expected token to be expired")
	}
	cfg.TokenExpiresAt = now.Add(time.Hour)
	if cfg.TokenExpired(now) {
		t.Fatal("expected token to be unexpired")
	}
	cfg.TokenExpiresAt = time.Time{}
	if cfg.TokenExpired(now) {
		t.Fatal("zero expiry should be treated as not-expired (no token yet)")
	}
}

func TestPersistedConfig_TokenExpiringWithin(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	cfg := PersistedConfig{TokenExpiresAt: now.Add(90 * time.Minute)}
	if !cfg.TokenExpiringWithin(now, 2*time.Hour) {
		t.Fatal("expected expiring within 2h to be true")
	}
	if cfg.TokenExpiringWithin(now, 30*time.Minute) {
		t.Fatal("expected expiring within 30m to be false")
	}
}

func TestPersistedConfig_CertThumbprintChanged(t *testing.T) {
	cfg := PersistedConfig{CertThumbprintSHA256: "abc"}
	if !cfg.CertThumbprintChanged("def") {
		t.Fatal("different thumbprints should report changed")
	}
	if cfg.CertThumbprintChanged("abc") {
		t.Fatal("same thumbprint should not report changed")
	}
	zero := PersistedConfig{}
	if zero.CertThumbprintChanged("anything") {
		t.Fatal("empty persisted thumbprint should not report changed")
	}
}

func TestMemoryStore_EmptyReadReturnsSentinel(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.Read(context.Background())
	if !IsEmptyStore(err) {
		t.Fatalf("expected ErrEmptyStore, got %v", err)
	}
}

func TestMemoryStore_RoundTrip(t *testing.T) {
	s := NewMemoryStore()
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	in := PersistedConfig{
		DeviceID:             "dev-1",
		ServiceToken:         "tok-1",
		TokenExpiresAt:       now.Add(24 * time.Hour),
		CertThumbprintSHA256: "thumb",
		Issued:               now,
	}
	if err := s.Write(context.Background(), in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, err := s.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if out.DeviceID != in.DeviceID || out.ServiceToken != in.ServiceToken {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", out, in)
	}
}

func TestMemoryStore_FailNextRead(t *testing.T) {
	s := NewMemoryStore()
	s.FailNextRead = errors.New("simulated io error")
	if _, err := s.Read(context.Background()); err == nil {
		t.Fatal("expected simulated error from FailNextRead")
	}
	if s.FailNextRead != nil {
		t.Fatal("FailNextRead should be consumed after one read")
	}
}

func TestMemoryStore_FailNextWrite(t *testing.T) {
	s := NewMemoryStore()
	s.FailNextWrite = errors.New("simulated io error")
	if err := s.Write(context.Background(), PersistedConfig{DeviceID: "x"}); err == nil {
		t.Fatal("expected simulated error from FailNextWrite")
	}
	if s.FailNextWrite != nil {
		t.Fatal("FailNextWrite should be consumed after one write")
	}
}
