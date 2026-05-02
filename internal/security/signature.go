package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func SignatureBase(method string, path string, timestampMillis int64, nonce string, bodyHash string) string {
	parts := []string{
		strings.ToUpper(strings.TrimSpace(method)),
		strings.TrimSpace(path),
		strconv.FormatInt(timestampMillis, 10),
		strings.TrimSpace(nonce),
		strings.TrimSpace(bodyHash),
	}
	return strings.Join(parts, "\n")
}

func SignRequest(secret string, method string, path string, timestampMillis int64, nonce string, body []byte) string {
	base := SignatureBase(method, path, timestampMillis, nonce, BodyHash(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(base))
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyRequestSignature(secret string, method string, path string, timestampMillis int64, nonce string, body []byte, signature string) bool {
	if strings.TrimSpace(secret) == "" || strings.TrimSpace(signature) == "" {
		return false
	}
	expected := SignRequest(secret, method, path, timestampMillis, nonce, body)
	return hmac.Equal([]byte(expected), []byte(strings.TrimSpace(signature)))
}
