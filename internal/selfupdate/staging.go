package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultMaxUpdateBytes is deliberately conservative for an endpoint-agent
	// binary. The backend may set a lower cap in the release catalog payload.
	DefaultMaxUpdateBytes int64 = 250 * 1024 * 1024

	stagedBinaryName          = "endpoint-agent.exe"
	activationPlanFileName    = "activation-plan.json"
	activationOutcomeFileName = "activation-outcome.json"
	rollbackBackupFileName    = "endpoint-agent.rollback.exe"
	rollbackPlanFileName      = "rollback-plan.json"
	maxStagingIdentifierLen   = 128
)

// HashResult is the bounded evidence produced by streaming a candidate binary.
type HashResult struct {
	ActualSha256 string
	Bytes        int64
}

var stagedFileHardener = hardenStagedFile
var protectedStagingDirPreparer = PrepareProtectedStagingDir

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

// HashFileWithLimit hashes an already-staged file with the same size cap used
// for downloads. PR1 uses this after rename as a final byte-for-byte guard.
func HashFileWithLimit(path string, maxBytes int64) (HashResult, ErrorCode, string) {
	f, err := os.Open(path)
	if err != nil {
		return HashResult{}, ErrStagingIO, "open staged binary for verification failed"
	}
	defer f.Close()
	return HashReaderWithLimit(f, maxBytes)
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

// WriteStagedBinaryFromReader atomically writes a verified candidate binary to
// paths.BinaryPath. The caller supplies the bytes (future PR1 downloader can
// pass an HTTP body); this helper performs no network work and is not wired to
// command execution in PR1a.
//
// Sequence: exclusive temp create -> stream hash+write under maxBytes -> claim
// check -> fsync+close -> harden temp -> rename -> harden final -> re-hash
// final. Any failure removes the temp file and returns a bounded, path-free
// reason.
func WriteStagedBinaryFromReader(paths StagingPaths, r io.Reader, claimedSha256 string, maxBytes int64) (HashResult, ErrorCode, string) {
	if code, reason := validateStagingPaths(paths); code != "" {
		return HashResult{}, code, reason
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxUpdateBytes
	}

	tmp := paths.BinaryPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return HashResult{}, ErrStagingIO, "create staged binary temp failed"
	}
	cleanup := func() { _ = os.Remove(tmp) }

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, maxBytes+1))
	if err != nil {
		_ = f.Close()
		cleanup()
		return HashResult{}, ErrDownloadFailed, "read candidate binary failed"
	}
	if n > maxBytes {
		_ = f.Close()
		cleanup()
		return HashResult{Bytes: n}, ErrDownloadTooLarge, "candidate binary exceeded maxBytes"
	}

	result := HashResult{ActualSha256: hex.EncodeToString(h.Sum(nil)), Bytes: n}
	if code, reason := VerifyClaimedSHA256(result.ActualSha256, claimedSha256); code != "" {
		_ = f.Close()
		cleanup()
		return result, code, reason
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return HashResult{}, ErrStagingIO, "fsync staged binary temp failed"
	}
	if err := f.Close(); err != nil {
		cleanup()
		return HashResult{}, ErrStagingIO, "close staged binary temp failed"
	}
	if err := stagedFileHardener(tmp); err != nil {
		cleanup()
		return HashResult{}, ErrStagingIO, "harden staged binary temp failed"
	}
	if err := os.Rename(tmp, paths.BinaryPath); err != nil {
		cleanup()
		return HashResult{}, ErrStagingIO, "promote staged binary failed"
	}
	if err := stagedFileHardener(paths.BinaryPath); err != nil {
		return HashResult{}, ErrStagingIO, "harden staged binary final failed"
	}
	finalHash, code, reason := HashFileWithLimit(paths.BinaryPath, maxBytes)
	if code != "" {
		return HashResult{}, code, reason
	}
	if finalHash.ActualSha256 != result.ActualSha256 || finalHash.Bytes != result.Bytes {
		return HashResult{}, ErrHashMismatch, "final staged binary verification mismatch"
	}
	return result, "", ""
}

func validateStagingPaths(paths StagingPaths) (ErrorCode, string) {
	if !validStagingID(paths.StagingID) {
		return ErrStagingIO, "invalid staging identifier"
	}
	if strings.TrimSpace(paths.Directory) == "" || strings.TrimSpace(paths.BinaryPath) == "" || strings.TrimSpace(paths.ActivationPlanPath) == "" {
		return ErrStagingIO, "staging paths are incomplete"
	}
	if filepath.Base(paths.BinaryPath) != stagedBinaryName || filepath.Base(paths.ActivationPlanPath) != activationPlanFileName {
		return ErrStagingIO, "staging paths have unexpected filenames"
	}
	if !pathWithinRoot(paths.Directory, paths.BinaryPath) || !pathWithinRoot(paths.Directory, paths.ActivationPlanPath) {
		return ErrStagingIO, "staging paths escaped directory"
	}
	return "", ""
}

func removeStagedArtifacts(paths StagingPaths) {
	if code, _ := validateStagingPaths(paths); code != "" {
		return
	}
	_ = os.Remove(paths.BinaryPath + ".tmp")
	_ = os.Remove(paths.BinaryPath)
	_ = os.Remove(paths.ActivationPlanPath + ".tmp")
	_ = os.Remove(paths.ActivationPlanPath)
	_ = os.Remove(activationOutcomePath(paths) + ".tmp")
	_ = os.Remove(activationOutcomePath(paths))
	_ = os.Remove(rollbackBackupPath(paths) + ".tmp")
	_ = os.Remove(rollbackBackupPath(paths))
	_ = os.Remove(rollbackPlanPath(paths) + ".tmp")
	_ = os.Remove(rollbackPlanPath(paths))
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

func rollbackBackupPath(paths StagingPaths) string {
	return filepath.Join(paths.Directory, rollbackBackupFileName)
}

func activationOutcomePath(paths StagingPaths) string {
	return filepath.Join(paths.Directory, activationOutcomeFileName)
}

func rollbackPlanPath(paths StagingPaths) string {
	return filepath.Join(paths.Directory, rollbackPlanFileName)
}
