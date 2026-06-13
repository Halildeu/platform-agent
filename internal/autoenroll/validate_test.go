package autoenroll

import (
	"errors"
	"testing"
	"time"
)

// TestPersistedConfig_Validate_TokenlessHappyPath is the #149 canonical case:
// a device + bound cert thumbprint with NO service token is valid.
func TestPersistedConfig_Validate_TokenlessHappyPath(t *testing.T) {
	cfg := PersistedConfig{
		DeviceID:             "dev-1",
		CertThumbprintSHA256: "abc",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("tokenless Validate happy path: %v", err)
	}
	if !cfg.IsTokenlessEnrollment() {
		t.Fatal("expected IsTokenlessEnrollment to be true")
	}
}

// TestPersistedConfig_Validate_LegacyTokenHappyPath keeps the legacy
// token-backed shape valid (retained for the #151 lifecycle).
func TestPersistedConfig_Validate_LegacyTokenHappyPath(t *testing.T) {
	cfg := PersistedConfig{
		DeviceID:             "dev-1",
		ServiceToken:         "tok-1",
		TokenExpiresAt:       time.Now().Add(24 * time.Hour),
		CertThumbprintSHA256: "abc",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("legacy token Validate happy path: %v", err)
	}
	if cfg.IsTokenlessEnrollment() {
		t.Fatal("token-backed record must not report IsTokenlessEnrollment")
	}
}

func TestPersistedConfig_Validate_EmptyStoreSentinel(t *testing.T) {
	if err := (PersistedConfig{}).Validate(); !errors.Is(err, ErrEmptyStore) {
		t.Fatalf("expected ErrEmptyStore, got %v", err)
	}
}

func TestPersistedConfig_Validate_MissingFields(t *testing.T) {
	t.Run("device_id_empty", func(t *testing.T) {
		// Token fields set so the record is not IsZero — must hit the
		// device_id branch rather than the empty-store sentinel.
		c := PersistedConfig{
			ServiceToken:         "tok-1",
			TokenExpiresAt:       time.Now().Add(time.Hour),
			CertThumbprintSHA256: "abc",
		}
		if err := c.Validate(); err == nil || errors.Is(err, ErrEmptyStore) || !errors.Is(err, ErrInvalidPersistedConfig) {
			t.Fatalf("expected ErrInvalidPersistedConfig (device_id), got %v", err)
		}
	})
	t.Run("cert_thumbprint_empty", func(t *testing.T) {
		c := PersistedConfig{DeviceID: "dev-1"}
		if err := c.Validate(); err == nil || errors.Is(err, ErrEmptyStore) || !errors.Is(err, ErrInvalidPersistedConfig) {
			t.Fatalf("expected ErrInvalidPersistedConfig (cert_thumbprint), got %v", err)
		}
	})
	t.Run("token_without_expiry_inconsistent", func(t *testing.T) {
		c := PersistedConfig{DeviceID: "dev-1", CertThumbprintSHA256: "abc", ServiceToken: "tok-1"}
		if err := c.Validate(); !errors.Is(err, ErrInvalidPersistedConfig) {
			t.Fatalf("expected ErrInvalidPersistedConfig (token without expiry), got %v", err)
		}
	})
	t.Run("expiry_without_token_inconsistent", func(t *testing.T) {
		c := PersistedConfig{DeviceID: "dev-1", CertThumbprintSHA256: "abc", TokenExpiresAt: time.Now().Add(time.Hour)}
		if err := c.Validate(); !errors.Is(err, ErrInvalidPersistedConfig) {
			t.Fatalf("expected ErrInvalidPersistedConfig (expiry without token), got %v", err)
		}
	})
}
