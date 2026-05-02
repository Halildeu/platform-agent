package security

import "testing"

func TestVerifyMaintenanceToken(t *testing.T) {
	hash := MaintenanceTokenHash("token-123")
	if !VerifyMaintenanceToken("token-123", hash) {
		t.Fatal("expected token to verify")
	}
	if VerifyMaintenanceToken("wrong", hash) {
		t.Fatal("expected wrong token to fail")
	}
	if VerifyMaintenanceToken("", hash) {
		t.Fatal("expected empty token to fail when hash is configured")
	}
	if !VerifyMaintenanceToken("", "") {
		t.Fatal("expected empty hash to disable token requirement")
	}
}

func TestRequireMaintenanceToken(t *testing.T) {
	hash := MaintenanceTokenHash("token-123")
	if err := RequireMaintenanceToken("token-123", hash); err != nil {
		t.Fatalf("expected nil error: %v", err)
	}
	if err := RequireMaintenanceToken("wrong", hash); err != ErrMaintenanceTokenRequired {
		t.Fatalf("expected ErrMaintenanceTokenRequired, got %v", err)
	}
}
