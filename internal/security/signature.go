// Package security implements the agent-side HMAC request signing that the
// endpoint-admin-service device-credential auth filter verifies.
//
// BE-011: the scheme MUST byte-match the backend's
// com.example.endpointadmin.security.HmacSignatureSupport:
//
//	canonical  = METHOD\npath\nquery\ntimestamp\nnonce\nsha256hex(body)
//	signature  = base64url-no-padding( HMAC-SHA256(secret, canonical) )
//
// where METHOD is upper-cased, sha256hex(body) is lower-case hex, and an
// absent query is the empty string. The backend reads the request headers
// X-Device-Credential-Id / X-Request-Timestamp / X-Request-Nonce /
// X-Signature; the timestamp is an ISO-8601 instant (parsed with
// java.time.Instant.parse) and is used verbatim in the canonical string.
package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// BodyHashHex returns the lower-case hex SHA-256 of the request body. An empty
// body hashes to the SHA-256 of the empty byte string, matching the backend
// which hashes the cached (possibly empty) body bytes.
func BodyHashHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// CanonicalRequest builds the six-line canonical string the backend's
// HmacSignatureSupport.canonicalPayload produces. path is the backend-visible
// request path (after any api-gateway rewrite); query is the raw query string
// or "" when absent; bodyHashHex is the BodyHashHex of the request body.
func CanonicalRequest(method, path, query, timestamp, nonce, bodyHashHex string) string {
	return strings.Join([]string{
		strings.ToUpper(method),
		path,
		query,
		timestamp,
		nonce,
		strings.ToLower(bodyHashHex),
	}, "\n")
}

// Sign returns the base64url (no padding) HMAC-SHA256 of the canonical string,
// matching the backend's HmacSignatureSupport.hmacSha256Base64Url.
func Sign(secret, canonical string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify reports whether signature equals the expected Sign(secret, canonical).
// Comparison is constant-time.
func Verify(secret, canonical, signature string) bool {
	if strings.TrimSpace(signature) == "" {
		return false
	}
	expected := Sign(secret, canonical)
	return hmac.Equal([]byte(expected), []byte(strings.TrimSpace(signature)))
}
