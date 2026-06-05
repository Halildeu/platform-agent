package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHashReaderWithLimit(t *testing.T) {
	input := "endpoint-agent"
	want := sha256.Sum256([]byte(input))
	got, code, reason := HashReaderWithLimit(strings.NewReader(input), 1024)
	if code != "" || reason != "" {
		t.Fatalf("HashReaderWithLimit rejected small input: code=%q reason=%q", code, reason)
	}
	if got.ActualSha256 != hex.EncodeToString(want[:]) || got.Bytes != int64(len(input)) {
		t.Fatalf("hash result = %+v", got)
	}
}

func TestHashFileWithLimit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.exe")
	if err := os.WriteFile(p, []byte("agent"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, code, reason := HashFileWithLimit(p, 1024)
	if code != "" || reason != "" {
		t.Fatalf("HashFileWithLimit rejected file: code=%q reason=%q", code, reason)
	}
	want := sha256.Sum256([]byte("agent"))
	if got.ActualSha256 != hex.EncodeToString(want[:]) || got.Bytes != 5 {
		t.Fatalf("hash result = %+v", got)
	}
}

func TestHashReaderWithLimitRejectsOversizeWithoutFullBuffer(t *testing.T) {
	got, code, reason := HashReaderWithLimit(strings.NewReader("abcdef"), 5)
	if code != ErrDownloadTooLarge {
		t.Fatalf("oversize code=%q reason=%q result=%+v", code, reason, got)
	}
	if got.Bytes != 6 {
		t.Fatalf("bytes read = %d, want maxBytes+1", got.Bytes)
	}
}

func TestVerifyClaimedSHA256(t *testing.T) {
	sha := strings.Repeat("a", 64)
	if code, reason := VerifyClaimedSHA256(sha, sha); code != "" || reason != "" {
		t.Fatalf("matching sha rejected: code=%q reason=%q", code, reason)
	}
	for _, tc := range []struct {
		name    string
		actual  string
		claimed string
	}{
		{"bad actual shape", "abc", sha},
		{"bad claimed shape", sha, strings.Repeat("g", 64)},
		{"mismatch", sha, strings.Repeat("b", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := VerifyClaimedSHA256(tc.actual, tc.claimed); code != ErrHashMismatch {
				t.Fatalf("code=%q, want HASH_MISMATCH", code)
			}
		})
	}
}

func TestBuildStagingPaths(t *testing.T) {
	paths, code, reason := BuildStagingPaths("/ProgramData/EndpointAgent/updates", "req-123_OK.4")
	if code != "" || reason != "" {
		t.Fatalf("BuildStagingPaths rejected clean id: code=%q reason=%q", code, reason)
	}
	if !strings.HasSuffix(paths.BinaryPath, "endpoint-agent.exe") {
		t.Fatalf("binary path = %q", paths.BinaryPath)
	}
	if !strings.HasSuffix(paths.ActivationPlanPath, "activation-plan.json") {
		t.Fatalf("activation plan path = %q", paths.ActivationPlanPath)
	}
}

func TestBuildStagingPathsRejectsTraversalAndSeparators(t *testing.T) {
	for _, id := range []string{"", ".", "..", "../x", `..\x`, "a/b", `a\b`, "C:evil", strings.Repeat("a", maxStagingIdentifierLen+1)} {
		t.Run(id, func(t *testing.T) {
			if _, code, _ := BuildStagingPaths("/root", id); code != ErrStagingIO {
				t.Fatalf("id %q code=%q, want STAGING_IO_FAILED", id, code)
			}
		})
	}
}

func TestWriteStagedBinaryFromReader(t *testing.T) {
	withNoopStagedFileHardener(t)
	root := t.TempDir()
	paths, code, reason := BuildStagingPaths(root, "req-write")
	if code != "" || reason != "" {
		t.Fatalf("BuildStagingPaths: code=%q reason=%q", code, reason)
	}
	if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("new endpoint-agent bytes")
	sum := sha256.Sum256(payload)
	result, code, reason := WriteStagedBinaryFromReader(paths, strings.NewReader(string(payload)), hex.EncodeToString(sum[:]), 1024)
	if code != "" || reason != "" {
		t.Fatalf("WriteStagedBinaryFromReader: code=%q reason=%q", code, reason)
	}
	if result.ActualSha256 != hex.EncodeToString(sum[:]) || result.Bytes != int64(len(payload)) {
		t.Fatalf("result = %+v", result)
	}
	got, err := os.ReadFile(paths.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("staged payload = %q", got)
	}
	if _, err := os.Stat(paths.BinaryPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file still present or unexpected stat err: %v", err)
	}
}

func TestWriteStagedBinaryFromReaderMismatchCleansTemp(t *testing.T) {
	withNoopStagedFileHardener(t)
	paths := testWritableStagingPaths(t, "req-mismatch")
	if _, code, _ := WriteStagedBinaryFromReader(paths, strings.NewReader("payload"), strings.Repeat("a", 64), 1024); code != ErrHashMismatch {
		t.Fatalf("code=%q, want HASH_MISMATCH", code)
	}
	assertNoStagingFiles(t, paths)
}

func TestWriteStagedBinaryFromReaderOversizeCleansTemp(t *testing.T) {
	withNoopStagedFileHardener(t)
	paths := testWritableStagingPaths(t, "req-oversize")
	if _, code, _ := WriteStagedBinaryFromReader(paths, strings.NewReader("abcdef"), strings.Repeat("a", 64), 5); code != ErrDownloadTooLarge {
		t.Fatalf("code=%q, want DOWNLOAD_TOO_LARGE", code)
	}
	assertNoStagingFiles(t, paths)
}

func TestWriteStagedBinaryFromReaderRejectsStaleTemp(t *testing.T) {
	withNoopStagedFileHardener(t)
	paths := testWritableStagingPaths(t, "req-stale")
	if err := os.WriteFile(paths.BinaryPath+".tmp", []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("payload"))
	if _, code, _ := WriteStagedBinaryFromReader(paths, strings.NewReader("payload"), hex.EncodeToString(sum[:]), 1024); code != ErrStagingIO {
		t.Fatalf("code=%q, want STAGING_IO_FAILED", code)
	}
}

func withNoopStagedFileHardener(t *testing.T) {
	t.Helper()
	previous := stagedFileHardener
	stagedFileHardener = func(string) error { return nil }
	t.Cleanup(func() { stagedFileHardener = previous })
}

func testWritableStagingPaths(t *testing.T, id string) StagingPaths {
	t.Helper()
	paths, code, reason := BuildStagingPaths(t.TempDir(), id)
	if code != "" || reason != "" {
		t.Fatalf("BuildStagingPaths: code=%q reason=%q", code, reason)
	}
	if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return paths
}

func assertNoStagingFiles(t *testing.T, paths StagingPaths) {
	t.Helper()
	for _, p := range []string{paths.BinaryPath, paths.BinaryPath + ".tmp"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s exists or stat err=%v", filepath.Base(p), err)
		}
	}
}

func TestPrepareProtectedStagingDirNonWindowsUnsupported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows unsupported contract")
	}
	if _, code, _ := PrepareProtectedStagingDir("/root", "req-1"); code != ErrUnsupportedPlatform {
		t.Fatalf("code=%q, want POLICY_UNSUPPORTED_PLATFORM", code)
	}
}
