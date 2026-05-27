package autoenroll

import (
	"errors"
	"testing"
	"time"
)

func TestPersistedConfig_Validate_HappyPath(t *testing.T) {
	cfg := PersistedConfig{
		DeviceID:             "dev-1",
		ServiceToken:         "tok-1",
		TokenExpiresAt:       time.Now().Add(24 * time.Hour),
		CertThumbprintSHA256: "abc",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate happy path: %v", err)
	}
}

func TestPersistedConfig_Validate_EmptyStoreSentinel(t *testing.T) {
	if err := (PersistedConfig{}).Validate(); !errors.Is(err, ErrEmptyStore) {
		t.Fatalf("expected ErrEmptyStore, got %v", err)
	}
}

func TestPersistedConfig_Validate_MissingFields(t *testing.T) {
	base := PersistedConfig{
		DeviceID:             "dev-1",
		ServiceToken:         "tok-1",
		TokenExpiresAt:       time.Now().Add(24 * time.Hour),
		CertThumbprintSHA256: "abc",
	}
	t.Run("device_id_empty", func(t *testing.T) {
		c := base
		c.DeviceID = ""
		// DeviceID empty alone is not "zero" (token still set) — should
		// hit the device_id branch in Validate.
		if err := c.Validate(); err == nil || errors.Is(err, ErrEmptyStore) {
			t.Fatalf("expected ErrInvalidPersistedConfig: %v", err)
		}
	})
	t.Run("service_token_empty", func(t *testing.T) {
		c := base
		c.ServiceToken = ""
		if err := c.Validate(); err == nil || errors.Is(err, ErrEmptyStore) {
			t.Fatalf("expected ErrInvalidPersistedConfig: %v", err)
		}
	})
	t.Run("token_expires_at_zero", func(t *testing.T) {
		c := base
		c.TokenExpiresAt = time.Time{}
		if err := c.Validate(); err == nil || !errors.Is(err, ErrInvalidPersistedConfig) {
			t.Fatalf("expected ErrInvalidPersistedConfig, got %v", err)
		}
	})
	t.Run("cert_thumbprint_empty", func(t *testing.T) {
		c := base
		c.CertThumbprintSHA256 = ""
		if err := c.Validate(); err == nil || !errors.Is(err, ErrInvalidPersistedConfig) {
			t.Fatalf("expected ErrInvalidPersistedConfig, got %v", err)
		}
	})
}
