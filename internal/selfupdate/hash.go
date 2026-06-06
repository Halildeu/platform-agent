package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

// DefaultMaxUpdateBytes is deliberately conservative for an endpoint-agent
// binary. Backend payloads may lower this cap, but local policy must never let
// a payload raise it.
const DefaultMaxUpdateBytes int64 = 250 * 1024 * 1024

// HashResult is bounded local evidence for a candidate / staged binary.
type HashResult struct {
	ActualSha256 string
	Bytes        int64
}

// HashReaderWithLimit streams r through SHA256 while enforcing maxBytes. It
// reads at most maxBytes+1 bytes, so oversize input is detected rather than
// silently truncated.
func HashReaderWithLimit(r io.Reader, maxBytes int64) (HashResult, ErrorCode, string) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxUpdateBytes
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, maxBytes+1))
	if err != nil {
		return HashResult{}, ErrDownloadFailed, "read candidate binary failed"
	}
	if n > maxBytes {
		return HashResult{Bytes: n}, ErrDownloadTooLarge, "candidate binary exceeded maxBytes"
	}
	return HashResult{ActualSha256: hex.EncodeToString(h.Sum(nil)), Bytes: n}, "", ""
}

// HashFileWithLimit hashes an already-staged file with the same bounded byte
// budget used for downloads.
func HashFileWithLimit(path string, maxBytes int64) (HashResult, ErrorCode, string) {
	f, err := os.Open(path)
	if err != nil {
		return HashResult{}, ErrStagingIO, "open binary for verification failed"
	}
	defer f.Close()
	return HashReaderWithLimit(f, maxBytes)
}

// VerifySHA256Equal compares two local evidence hashes. Both sides must be
// 64-character lowercase hex after trimming and lower-casing.
func VerifySHA256Equal(actual, expected string) (ErrorCode, string) {
	actual = strings.ToLower(strings.TrimSpace(actual))
	expected = strings.ToLower(strings.TrimSpace(expected))
	if !isSHA256Hex(actual) || !isSHA256Hex(expected) {
		return ErrHashMismatch, "sha256 must be 64 hex characters"
	}
	if actual != expected {
		return ErrHashMismatch, "sha256 mismatch"
	}
	return "", ""
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}
