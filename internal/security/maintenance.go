package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

var ErrMaintenanceTokenRequired = errors.New("valid maintenance token is required")

func MaintenanceTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func VerifyMaintenanceToken(token string, expectedHash string) bool {
	expectedHash = strings.TrimSpace(strings.ToLower(expectedHash))
	if expectedHash == "" {
		return true
	}
	if strings.TrimSpace(token) == "" {
		return false
	}
	actualHash := MaintenanceTokenHash(token)
	if len(actualHash) != len(expectedHash) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actualHash), []byte(expectedHash)) == 1
}

func RequireMaintenanceToken(token string, expectedHash string) error {
	if VerifyMaintenanceToken(token, expectedHash) {
		return nil
	}
	return ErrMaintenanceTokenRequired
}
