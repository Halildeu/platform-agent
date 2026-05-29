package hmacstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestCredentialValidate(t *testing.T) {
	now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	t.Run("valid", func(t *testing.T) {
		c := Credential{
			DeviceID:        "device-1",
			CredentialKeyID: "edc_abc",
			Secret:          "secret",
			Issued:          now,
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	t.Run("zero is ErrEmpty", func(t *testing.T) {
		if err := (Credential{}).Validate(); !errors.Is(err, ErrEmpty) {
			t.Fatalf("expected ErrEmpty, got %v", err)
		}
	})

	t.Run("missing device_id", func(t *testing.T) {
		c := Credential{
			CredentialKeyID: "edc_abc",
			Secret:          "secret",
			Issued:          now,
		}
		if err := c.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected ErrInvalid, got %v", err)
		}
	})

	t.Run("missing credential_key_id", func(t *testing.T) {
		c := Credential{
			DeviceID: "device-1",
			Secret:   "secret",
			Issued:   now,
		}
		if err := c.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected ErrInvalid, got %v", err)
		}
	})

	t.Run("missing secret", func(t *testing.T) {
		c := Credential{
			DeviceID:        "device-1",
			CredentialKeyID: "edc_abc",
			Issued:          now,
		}
		if err := c.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected ErrInvalid, got %v", err)
		}
	})

	t.Run("missing issued", func(t *testing.T) {
		c := Credential{
			DeviceID:        "device-1",
			CredentialKeyID: "edc_abc",
			Secret:          "secret",
		}
		if err := c.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected ErrInvalid, got %v", err)
		}
	})
}

func TestStoreInvalidateIdempotent(t *testing.T) {
	dir := t.TempDir()
	store := New(filepath.Join(dir, "missing.dpapi"), nil)
	// Invalidate on a non-existent path is a no-op (idempotent for
	// installer/runner safety).
	if err := store.Invalidate(context.Background()); err != nil {
		t.Fatalf("Invalidate on non-existent: %v", err)
	}
	if err := store.Delete(context.Background()); err != nil {
		t.Fatalf("Delete on non-existent: %v", err)
	}
}

func TestDecodeEncodeRoundTrip(t *testing.T) {
	now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	original := Credential{
		DeviceID:        "423b6fc3-7497-4083-bd2f-5e2fe543bfe9",
		CredentialKeyID: "edc_022a7111-c4ce-4a39-bfc7-858bae74af53",
		Secret:          "4MuT4y8HQsTkYoC9BMG_gfSUVd1uxxFN9IlIdJhzKEU",
		ServerTime:      now,
		Issued:          now,
	}
	plain, err := encodeCredential(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodeCredential(plain)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.DeviceID != original.DeviceID {
		t.Errorf("DeviceID: got %q want %q", decoded.DeviceID, original.DeviceID)
	}
	if decoded.CredentialKeyID != original.CredentialKeyID {
		t.Errorf("CredentialKeyID: got %q want %q", decoded.CredentialKeyID, original.CredentialKeyID)
	}
	if decoded.Secret != original.Secret {
		t.Errorf("Secret mismatch (redacted)")
	}
	if !decoded.ServerTime.Equal(original.ServerTime) {
		t.Errorf("ServerTime: got %v want %v", decoded.ServerTime, original.ServerTime)
	}
	if !decoded.Issued.Equal(original.Issued) {
		t.Errorf("Issued: got %v want %v", decoded.Issued, original.Issued)
	}
}

func TestDecodeEmptyPlaintext(t *testing.T) {
	if _, err := decodeCredential(nil); err == nil {
		t.Fatal("expected error decoding nil plaintext, got nil")
	}
	if _, err := decodeCredential([]byte{}); err == nil {
		t.Fatal("expected error decoding empty plaintext, got nil")
	}
}
