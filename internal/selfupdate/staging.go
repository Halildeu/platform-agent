package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path/filepath"
	"strings"
)

const (
	// DefaultMaxUpdateBytes is deliberately conservative for an endpoint-agent
	// binary. The backend may set a lower cap in the release catalog payload.
	DefaultMaxUpdateBytes int64 = 250 * 1024 * 1024

	stagedBinaryName        = "endpoint-agent.exe"
	activationPlanFileName  = "activation-plan.json"
	maxStagingIdentifierLen = 128
)

// HashResult is the bounded evidence produced by streaming a candidate binary.
type HashResult struct {
	ActualSha256 string
	Bytes        int64
}

// HashReaderWithLimit streams r through SHA256 while enforcing maxBytes. It
// reads at most maxBytes+1 bytes, so an oversized download is rejected without
// buffering the full payload in memory.
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

// VerifyClaimedSHA256 compares the locally-computed hash to the backend's
// catalog-derived claim. The claim is evidence only, but a mismatch still
// blocks staging because the release catalog and payload no longer describe
// the bytes the agent received.
func VerifyClaimedSHA256(actual, claimed string) (ErrorCode, string) {
	actual = strings.ToLower(strings.TrimSpace(actual))
	claimed = strings.ToLower(strings.TrimSpace(claimed))
	if !isLowerHexSHA256(actual) || !isLowerHexSHA256(claimed) {
		return ErrHashMismatch, "sha256 must be 64 lowercase hex characters"
	}
	if actual != claimed {
		return ErrHashMismatch, "candidate sha256 does not match release catalog claim"
	}
	return "", ""
}

func isLowerHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

// StagingPaths are local-only filesystem paths. They must never be copied into
// StageResult; the wire result carries only StagingID / ActivationPlanID.
type StagingPaths struct {
	Root               string
	StagingID          string
	Directory          string
	BinaryPath         string
	ActivationPlanPath string
}

// BuildStagingPaths constructs the protected staging directory paths from a
// bounded opaque staging identifier. The identifier rejects path separators,
// drive prefixes, traversal tokens, and empty/dot values.
func BuildStagingPaths(root, stagingID string) (StagingPaths, ErrorCode, string) {
	root = strings.TrimSpace(root)
	stagingID = strings.TrimSpace(stagingID)
	if root == "" || !validStagingID(stagingID) {
		return StagingPaths{}, ErrStagingIO, "invalid staging root or identifier"
	}
	cleanRoot := filepath.Clean(root)
	dir := filepath.Join(cleanRoot, stagingID)
	if !pathWithinRoot(cleanRoot, dir) {
		return StagingPaths{}, ErrStagingIO, "staging directory escaped root"
	}
	return StagingPaths{
		Root:               cleanRoot,
		StagingID:          stagingID,
		Directory:          dir,
		BinaryPath:         filepath.Join(dir, stagedBinaryName),
		ActivationPlanPath: filepath.Join(dir, activationPlanFileName),
	}, "", ""
}

func validStagingID(id string) bool {
	if id == "" || len(id) > maxStagingIdentifierLen {
		return false
	}
	if id == "." || id == ".." || strings.Contains(id, "..") {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

func pathWithinRoot(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel))
}
