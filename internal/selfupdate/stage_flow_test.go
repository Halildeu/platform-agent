package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestStageCandidateFromReaderReady(t *testing.T) {
	root := t.TempDir()
	withTestStagingHooks(t)

	payload := []byte("signed endpoint agent candidate")
	sum := sha256.Sum256(payload)
	result, plan := StageCandidateFromReader(testStageCandidateInput(root, payload, hex.EncodeToString(sum[:]), AuthenticodeEvidence{
		ChainValid:        true,
		HasCodeSigningEKU: true,
		SignerThumbprint:  "AA:BB CC",
		Timestamped:       true,
		SigningTimeValid:  true,
	}))

	if result.StageStatus != StageReady {
		t.Fatalf("stage status=%q result=%+v", result.StageStatus, result)
	}
	if result.ActualSha256 != hex.EncodeToString(sum[:]) || result.ActualSignerThumbprint != "AABBCC" {
		t.Fatalf("result evidence mismatch: %+v", result)
	}
	if plan.StagedBinaryPath == "" || plan.ActivationPlanPath == "" || plan.ActivationPlanID != result.ActivationPlanID {
		t.Fatalf("activation plan mismatch: %+v", plan)
	}
	got, err := os.ReadFile(plan.StagedBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("staged bytes=%q", got)
	}
	stageJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(stageJSON)), "program") || strings.Contains(string(stageJSON), `\`) {
		t.Fatalf("StageResult leaked local path: %s", stageJSON)
	}
}

func TestStageCandidateFromReaderNoopDoesNotPrepare(t *testing.T) {
	calledPrepare := false
	withTestStagingHooks(t)
	previous := protectedStagingDirPreparer
	protectedStagingDirPreparer = func(root, id string) (StagingPaths, ErrorCode, string) {
		calledPrepare = true
		return previous(root, id)
	}
	t.Cleanup(func() { protectedStagingDirPreparer = previous })

	payload := []byte("unused")
	sum := sha256.Sum256(payload)
	in := testStageCandidateInput(t.TempDir(), payload, hex.EncodeToString(sum[:]), AuthenticodeEvidence{})
	in.Preflight.Payload.TargetVersion = in.Preflight.CurrentVersion
	in.Preflight.MaxSeenVersion = ""

	result, plan := StageCandidateFromReader(in)
	if result.StageStatus != StageNoopCurrent {
		t.Fatalf("stage status=%q result=%+v", result.StageStatus, result)
	}
	if calledPrepare {
		t.Fatal("noop preflight must not prepare staging")
	}
	if plan.StagedBinaryPath != "" {
		t.Fatalf("noop produced activation plan: %+v", plan)
	}
}

func TestStageCandidateFromReaderHashMismatchCleansTemp(t *testing.T) {
	root := t.TempDir()
	withTestStagingHooks(t)

	result, plan := StageCandidateFromReader(testStageCandidateInput(root, []byte("payload"), strings.Repeat("a", 64), AuthenticodeEvidence{
		ChainValid:        true,
		HasCodeSigningEKU: true,
		SignerThumbprint:  "AABBCC",
		Timestamped:       true,
		SigningTimeValid:  true,
	}))

	if result.StageStatus != StageFailed || result.ErrorCode != ErrHashMismatch {
		t.Fatalf("result=%+v, want HASH_MISMATCH failure", result)
	}
	if plan.StagedBinaryPath != "" {
		t.Fatalf("failure produced activation plan: %+v", plan)
	}
	paths, _, _ := BuildStagingPaths(root, "req-stage")
	assertNoStagingFiles(t, paths)
}

func TestStageCandidateFromReaderSignatureFailureRemovesFinalBinary(t *testing.T) {
	root := t.TempDir()
	withTestStagingHooks(t)

	payload := []byte("payload")
	sum := sha256.Sum256(payload)
	result, _ := StageCandidateFromReader(testStageCandidateInput(root, payload, hex.EncodeToString(sum[:]), AuthenticodeEvidence{
		ChainValid:        true,
		HasCodeSigningEKU: false,
		SignerThumbprint:  "AABBCC",
		Timestamped:       true,
		SigningTimeValid:  true,
	}))

	if result.StageStatus != StageFailed || result.ErrorCode != ErrSignatureInvalid {
		t.Fatalf("result=%+v, want SIGNATURE_INVALID failure", result)
	}
	paths, _, _ := BuildStagingPaths(root, "req-stage")
	assertNoStagingFiles(t, paths)
}

func TestStageCandidateFromReaderSignerFailureRemovesFinalBinary(t *testing.T) {
	root := t.TempDir()
	withTestStagingHooks(t)

	payload := []byte("payload")
	sum := sha256.Sum256(payload)
	in := testStageCandidateInput(root, payload, hex.EncodeToString(sum[:]), AuthenticodeEvidence{
		ChainValid:        true,
		HasCodeSigningEKU: true,
		SignerThumbprint:  "DD:EE FF",
		Timestamped:       true,
		SigningTimeValid:  true,
	})
	result, _ := StageCandidateFromReader(in)

	if result.StageStatus != StageFailed || result.ErrorCode != ErrSignerNotAllowed {
		t.Fatalf("result=%+v, want SIGNER_NOT_ALLOWED failure", result)
	}
	paths, _, _ := BuildStagingPaths(root, "req-stage")
	assertNoStagingFiles(t, paths)
}

func withTestStagingHooks(t *testing.T) {
	t.Helper()
	withNoopStagedFileHardener(t)
	previous := protectedStagingDirPreparer
	protectedStagingDirPreparer = func(root, id string) (StagingPaths, ErrorCode, string) {
		paths, code, reason := BuildStagingPaths(root, id)
		if code != "" {
			return StagingPaths{}, code, reason
		}
		if err := os.MkdirAll(paths.Directory, 0o700); err != nil {
			return StagingPaths{}, ErrStagingIO, "create protected staging directory failed"
		}
		return paths, "", ""
	}
	t.Cleanup(func() { protectedStagingDirPreparer = previous })
}

func testStageCandidateInput(root string, candidate []byte, claimedSHA string, ev AuthenticodeEvidence) StageCandidateInput {
	return StageCandidateInput{
		Preflight: PreflightInput{
			Platform:       "windows",
			CurrentVersion: "1.0.0",
			MaxSeenVersion: "1.0.0",
			Payload: UpdateAgentPayload{
				ReleaseID:               "rel-1",
				TargetVersion:           "1.1.0",
				BinaryURL:               "https://github.com/Halildeu/platform-agent/releases/download/v1.1.0/endpoint-agent.exe",
				ClaimedSha256:           claimedSHA,
				ClaimedSignerThumbprint: "AABBCC",
				SigningTier:             TierTrusted,
				MaxBytes:                1024,
			},
			URLPolicy:  URLPolicy{AllowedHosts: []string{"github.com"}, MaxRedirects: 0},
			TierPolicy: TierPolicy{},
		},
		StagingRoot:       root,
		StagingID:         "req-stage",
		CurrentBinaryPath: `C:\Program Files\EndpointAgent\endpoint-agent.exe`,
		ServiceName:       "EndpointAgent",
		Candidate:         strings.NewReader(string(candidate)),
		Authenticode:      ev,
		SignerAllowlist:   SignerAllowlist{Thumbprints: []string{"AABBCC"}},
	}
}
