package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
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

func TestPrepareProtectedStagingDirNonWindowsUnsupported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows unsupported contract")
	}
	if _, code, _ := PrepareProtectedStagingDir("/root", "req-1"); code != ErrUnsupportedPlatform {
		t.Fatalf("code=%q, want POLICY_UNSUPPORTED_PLATFORM", code)
	}
}
