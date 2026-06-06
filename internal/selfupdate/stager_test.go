package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

// ---- fakes -----------------------------------------------------------------

type fakeVerifier struct {
	ev  AuthenticodeEvidence
	err error
}

func (f fakeVerifier) Verify(_ context.Context, _ string) (AuthenticodeEvidence, error) {
	return f.ev, f.err
}

type fakeVersionReader struct {
	version string
	err     error
}

func (f fakeVersionReader) ReadVersion(_ context.Context, _ string) (string, error) {
	return f.version, f.err
}

type fakeDownloader struct {
	body    []byte
	code    ErrorCode
	reason  string
	gotMax  int64 // records the maxBytes the stager passed
	gotURL  string
	gotPol  URLPolicy
	written int64
}

func (f *fakeDownloader) Download(_ context.Context, rawURL string, pol URLPolicy, maxBytes int64, dst io.Writer) (int64, ErrorCode, string) {
	f.gotMax = maxBytes
	f.gotURL = rawURL
	f.gotPol = pol
	if f.code != "" {
		return 0, f.code, f.reason
	}
	n, _ := dst.Write(f.body)
	f.written = int64(n)
	return int64(n), "", ""
}

type fakeHighWater struct {
	maxSeen string
	err     error
}

func (f fakeHighWater) ReadMaxSeen(_ context.Context) (string, error) {
	return f.maxSeen, f.err
}

type fakeStaging struct {
	committed bool
	gotTemp   string
	gotID     string
	path      string
	err       error
}

func (f *fakeStaging) Commit(_ context.Context, tempPath, stagingID string) (string, error) {
	f.gotTemp, f.gotID = tempPath, stagingID
	if f.err != nil {
		return "", f.err
	}
	f.committed = true
	if f.path == "" {
		return "C:/ProgramData/agent/staged-x.bin", nil
	}
	return f.path, nil
}

// ---- harness ---------------------------------------------------------------

const goodThumb = "AABBCCDDEEFF00112233445566778899AABBCCDD"

var goodBody = []byte("this-is-a-fake-signed-agent-binary")

func goodSha() string {
	sum := sha256.Sum256(goodBody)
	return hex.EncodeToString(sum[:])
}

// newHappyStager wires every collaborator for a successful STAGED_ACTIVATION_READY
// run (target 2.0.0 over current 1.0.0). Individual tests mutate one field.
func newHappyStager(t *testing.T) (*Stager, *fakeDownloader, *fakeStaging) {
	t.Helper()
	dl := &fakeDownloader{body: goodBody}
	st := &fakeStaging{}
	s := &Stager{
		GOOS:          "windows",
		Verifier:      fakeVerifier{ev: AuthenticodeEvidence{ChainValid: true, HasCodeSigningEKU: true, SignerThumbprint: goodThumb, CurrentTimeValid: true}},
		VersionReader: fakeVersionReader{version: "2.0.0"},
		Downloader:    dl,
		HighWater:     fakeHighWater{maxSeen: "1.0.0"},
		Staging:       st,
		Allowlist:     SignerAllowlist{Thumbprints: []string{goodThumb}},
		TierPolicy:    TierPolicy{},
		URLPolicy:     URLPolicy{AllowedHosts: []string{"github.com"}, MaxRedirects: 5},
		HardMaxBytes:  10 << 20,
		TempDir:       t.TempDir(),
		NewStagingID:  func() string { return fixedStagingID },
	}
	return s, dl, st
}

// fixedStagingID is a valid 32-hex opaque handle for deterministic tests.
const fixedStagingID = "0123456789abcdef0123456789abcdef"

func happyPayload() UpdateAgentPayload {
	return UpdateAgentPayload{
		ReleaseID:     "rel-1",
		TargetVersion: "2.0.0",
		BinaryURL:     "https://github.com/org/agent/releases/download/v2.0.0/agent.exe",
		ClaimedSha256: goodSha(),
		SigningTier:   TierTrusted,
	}
}

// ---- happy path ------------------------------------------------------------

func TestStage_HappyPath(t *testing.T) {
	s, _, st := newHappyStager(t)
	r := s.Stage(context.Background(), happyPayload(), "1.0.0")
	if r.StageStatus != StageReady {
		t.Fatalf("want STAGED_ACTIVATION_READY, got %q (code=%q reason=%q)", r.StageStatus, r.ErrorCode, r.Reason)
	}
	if !st.committed {
		t.Error("staging.Commit was not called")
	}
	if r.ActualSha256 != goodSha() {
		t.Errorf("ActualSha256 = %q, want recomputed %q", r.ActualSha256, goodSha())
	}
	if r.ActualSignerThumbprint != goodThumb {
		t.Errorf("ActualSignerThumbprint = %q, want %q", r.ActualSignerThumbprint, goodThumb)
	}
	if r.StagingID != fixedStagingID || r.ActivationPlanID != fixedStagingID {
		t.Errorf("staging handles = %q/%q", r.StagingID, r.ActivationPlanID)
	}
	if r.OldVersion != "1.0.0" || r.TargetVersion != "2.0.0" {
		t.Errorf("version echo = %q -> %q", r.OldVersion, r.TargetVersion)
	}
}

// TestStage_ClaimedHashIsNeverAuthority is the must-fix #1 proof: a payload
// whose claimedSha256 is GARBAGE still stages successfully when ExpectedHash
// (the trusted-local source) is empty — the backend claim is audit-only and is
// never an integrity gate.
func TestStage_ClaimedHashIsNeverAuthority(t *testing.T) {
	s, _, _ := newHappyStager(t)
	p := happyPayload()
	p.ClaimedSha256 = "deadbeef" // wildly wrong; must NOT cause a failure
	r := s.Stage(context.Background(), p, "1.0.0")
	if r.StageStatus != StageReady {
		t.Fatalf("claimed-hash mismatch must not block (it is audit-only); got %q/%q", r.StageStatus, r.ErrorCode)
	}
	if r.ActualSha256 != goodSha() {
		t.Errorf("ActualSha256 should be the recomputed value, got %q", r.ActualSha256)
	}
}

// TestStage_ExpectedHashGate proves the durable path: when a TRUSTED LOCAL
// expected hash IS configured, a mismatch fails closed and a match passes.
func TestStage_ExpectedHashGate(t *testing.T) {
	t.Run("mismatch fails closed", func(t *testing.T) {
		s, _, _ := newHappyStager(t)
		s.ExpectedHash = "00" + goodSha()[2:] // flip first byte
		r := s.Stage(context.Background(), happyPayload(), "1.0.0")
		if r.ErrorCode != ErrHashMismatch {
			t.Fatalf("want HASH_MISMATCH, got %q/%q", r.StageStatus, r.ErrorCode)
		}
	})
	t.Run("match passes", func(t *testing.T) {
		s, _, _ := newHappyStager(t)
		s.ExpectedHash = goodSha()
		if r := s.Stage(context.Background(), happyPayload(), "1.0.0"); r.StageStatus != StageReady {
			t.Fatalf("matching expected hash should pass, got %q/%q", r.StageStatus, r.ErrorCode)
		}
	})
}

// ---- gate-by-gate refusals -------------------------------------------------

func TestStage_GateRefusals(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(s *Stager, p *UpdateAgentPayload)
		current string
		want    StageStatus
		code    ErrorCode
	}{
		{"non-windows platform", func(s *Stager, _ *UpdateAgentPayload) { s.GOOS = "linux" }, "1.0.0", StageFailed, ErrUnsupportedPlatform},
		{"missing url (shape)", func(_ *Stager, p *UpdateAgentPayload) { p.BinaryURL = "" }, "1.0.0", StageFailed, ErrURLRejected},
		{"lab tier without opt-in", func(_ *Stager, p *UpdateAgentPayload) { p.SigningTier = TierLabOnlyEvidence }, "1.0.0", StageFailed, ErrLabTierRefused},
		// downgrade/noop isolate the version gate from anti-replay by clearing
		// the high-water mark (first-install state), since EvaluateVersionPolicy
		// checks maxSeen BEFORE the downgrade/noop branches — a target below or
		// equal to a non-empty maxSeen is (correctly) a REPLAY, covered below.
		{"downgrade", func(s *Stager, p *UpdateAgentPayload) {
			s.HighWater = fakeHighWater{maxSeen: ""}
			p.TargetVersion = "0.9.0"
		}, "1.0.0", StageFailed, ErrVersionDowngrade},
		{"noop already current", func(s *Stager, p *UpdateAgentPayload) {
			s.HighWater = fakeHighWater{maxSeen: ""}
			p.TargetVersion = "1.0.0"
		}, "1.0.0", StageNoopCurrent, ""},
		{"replay (<= maxSeen)", func(s *Stager, p *UpdateAgentPayload) {
			s.HighWater = fakeHighWater{maxSeen: "3.0.0"}
		}, "1.0.0", StageFailed, ErrVersionReplay},
		{"corrupt high-water fails closed", func(s *Stager, _ *UpdateAgentPayload) {
			s.HighWater = fakeHighWater{err: errors.New("corrupt")}
		}, "1.0.0", StageFailed, ErrVersionUnparseable},
		{"url not allowlisted", func(_ *Stager, p *UpdateAgentPayload) {
			p.BinaryURL = "https://evil.example.com/agent.exe"
		}, "1.0.0", StageFailed, ErrURLRejected},
		{"download too large", func(s *Stager, _ *UpdateAgentPayload) {
			s.Downloader = &fakeDownloader{code: ErrDownloadTooLarge, reason: "too big"}
		}, "1.0.0", StageFailed, ErrDownloadTooLarge},
		{"download failed", func(s *Stager, _ *UpdateAgentPayload) {
			s.Downloader = &fakeDownloader{code: ErrDownloadFailed, reason: "io"}
		}, "1.0.0", StageFailed, ErrDownloadFailed},
		{"verifier error", func(s *Stager, _ *UpdateAgentPayload) {
			s.Verifier = fakeVerifier{err: errors.New("winverifytrust failed")}
		}, "1.0.0", StageFailed, ErrSignatureInvalid},
		{"authenticode no EKU", func(s *Stager, _ *UpdateAgentPayload) {
			s.Verifier = fakeVerifier{ev: AuthenticodeEvidence{ChainValid: true, HasCodeSigningEKU: false, SignerThumbprint: goodThumb, CurrentTimeValid: true}}
		}, "1.0.0", StageFailed, ErrSignatureInvalid},
		{"signer not allowlisted", func(s *Stager, _ *UpdateAgentPayload) {
			s.Verifier = fakeVerifier{ev: AuthenticodeEvidence{ChainValid: true, HasCodeSigningEKU: true, SignerThumbprint: "FFFF", CurrentTimeValid: true}}
		}, "1.0.0", StageFailed, ErrSignerNotAllowed},
		{"version-bind mismatch", func(s *Stager, _ *UpdateAgentPayload) {
			s.VersionReader = fakeVersionReader{version: "1.5.0"} // != target 2.0.0
		}, "1.0.0", StageFailed, ErrCatalogMismatch},
		{"version stamp missing", func(s *Stager, _ *UpdateAgentPayload) {
			s.VersionReader = fakeVersionReader{version: ""}
		}, "1.0.0", StageFailed, ErrCatalogMismatch},
		{"version reader error", func(s *Stager, _ *UpdateAgentPayload) {
			s.VersionReader = fakeVersionReader{err: errors.New("io")}
		}, "1.0.0", StageFailed, ErrCatalogMismatch},
		{"staging io error", func(s *Stager, _ *UpdateAgentPayload) {
			s.Staging = &fakeStaging{err: errors.New("rename failed")}
		}, "1.0.0", StageFailed, ErrStagingIO},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := newHappyStager(t)
			p := happyPayload()
			tc.mutate(s, &p)
			r := s.Stage(context.Background(), p, tc.current)
			if r.StageStatus != tc.want {
				t.Fatalf("status = %q, want %q (code=%q)", r.StageStatus, tc.want, r.ErrorCode)
			}
			if r.ErrorCode != tc.code {
				t.Fatalf("code = %q, want %q (reason=%q)", r.ErrorCode, tc.code, r.Reason)
			}
			if r.StageStatus == StageFailed && !IsKnownErrorCode(r.ErrorCode) {
				t.Errorf("failed result carries an unknown error code %q", r.ErrorCode)
			}
		})
	}
}

// ---- gate ORDERING: a refusal never advances to a later collaborator -------

// TestStage_RefusalSkipsDownload proves a non-I/O preflight refusal never calls
// the downloader (cheap+restrictive first; no network on a policy refusal).
func TestStage_RefusalSkipsDownload(t *testing.T) {
	s, dl, st := newHappyStager(t)
	p := happyPayload()
	p.TargetVersion = "0.1.0" // downgrade => refused at preflight
	_ = s.Stage(context.Background(), p, "1.0.0")
	if dl.gotURL != "" {
		t.Error("downloader was called despite a preflight refusal")
	}
	if st.committed {
		t.Error("staging happened despite a preflight refusal")
	}
}

// ---- must-fix #4: payload MaxBytes can only LOWER the cap ------------------

func TestStage_EffectiveMaxBytes(t *testing.T) {
	s, dl, _ := newHappyStager(t)
	s.HardMaxBytes = 1000
	p := happyPayload()

	p.MaxBytes = 500 // lower than hard cap => used
	_ = s.Stage(context.Background(), p, "1.0.0")
	if dl.gotMax != 500 {
		t.Errorf("payload MaxBytes 500 should lower the cap to 500, got %d", dl.gotMax)
	}

	s, dl, _ = newHappyStager(t)
	s.HardMaxBytes = 1000
	p.MaxBytes = 5000 // higher than hard cap => must NOT raise it
	_ = s.Stage(context.Background(), p, "1.0.0")
	if dl.gotMax != 1000 {
		t.Errorf("payload MaxBytes 5000 must not raise the cap above 1000, got %d", dl.gotMax)
	}
}

// ---- misconfiguration fails closed ----------------------------------------

func TestStage_MisconfigFailsClosed(t *testing.T) {
	t.Run("no cap", func(t *testing.T) {
		s, _, _ := newHappyStager(t)
		s.HardMaxBytes = 0
		if r := s.Stage(context.Background(), happyPayload(), "1.0.0"); r.ErrorCode != ErrStagingIO {
			t.Fatalf("missing cap should fail closed STAGING_IO, got %q/%q", r.StageStatus, r.ErrorCode)
		}
	})
	t.Run("nil collaborator", func(t *testing.T) {
		s, _, _ := newHappyStager(t)
		s.Verifier = nil
		if r := s.Stage(context.Background(), happyPayload(), "1.0.0"); r.ErrorCode != ErrStagingIO {
			t.Fatalf("nil verifier should fail closed STAGING_IO, got %q/%q", r.StageStatus, r.ErrorCode)
		}
	})
}

// ---- stub collaborators fail closed ---------------------------------------

func TestStubCollaboratorsFailClosed(t *testing.T) {
	if _, err := (StubVerifier{}).Verify(context.Background(), "x"); err == nil {
		t.Error("StubVerifier must fail closed")
	}
	if _, err := (StubVersionReader{}).ReadVersion(context.Background(), "x"); err == nil {
		t.Error("StubVersionReader must fail closed")
	}
}

// ---- staging-id opacity (Codex 019e9d35) ----------------------------------

func TestValidStagingID(t *testing.T) {
	good := []string{
		"0123456789abcdef0123456789abcdef",
		"AABBCCDDEEFF00112233445566778899",
	}
	bad := []string{
		"",                                  // empty
		"rng-unavailable",                   // the old fail-open sentinel
		"../x",                              // path traversal
		"short",                             // too short
		"0123456789abcdef0123456789abcde",   // 31 chars
		"0123456789abcdef0123456789abcdef0", // 33 chars
		"0123456789abcdef0123456789abcdeZ",  // non-hex char
		"req-123",                           // illustrative-but-non-opaque
	}
	for _, g := range good {
		if !validStagingID(g) {
			t.Errorf("valid id rejected: %q", g)
		}
	}
	for _, b := range bad {
		if validStagingID(b) {
			t.Errorf("invalid id accepted: %q", b)
		}
	}
}

// TestStage_BadStagingIDFailsClosed proves a non-opaque/path-ish minted id
// (e.g. a bad NewStagingID injection or an RNG sentinel) fails closed with
// STAGING_IO_FAILED and NEVER reaches the staging store.
func TestStage_BadStagingIDFailsClosed(t *testing.T) {
	for _, badID := range []string{"", "rng-unavailable", "../escape", "not-hex-at-all-xxxxxxxxxxxxxxxxxx"} {
		t.Run(badID, func(t *testing.T) {
			s, _, st := newHappyStager(t)
			s.NewStagingID = func() string { return badID }
			r := s.Stage(context.Background(), happyPayload(), "1.0.0")
			if r.ErrorCode != ErrStagingIO {
				t.Fatalf("bad staging id must fail STAGING_IO, got %q/%q", r.StageStatus, r.ErrorCode)
			}
			if st.committed {
				t.Error("staging store was called with a non-opaque id")
			}
		})
	}
}

// TestStage_DefaultStagingIDIsValidHex proves the default generator (no
// injection) produces a valid 32-hex opaque handle that stages cleanly.
func TestStage_DefaultStagingIDIsValidHex(t *testing.T) {
	s, _, _ := newHappyStager(t)
	s.NewStagingID = nil // use the real crypto/rand generator
	r := s.Stage(context.Background(), happyPayload(), "1.0.0")
	if r.StageStatus != StageReady {
		t.Fatalf("default staging id should stage, got %q/%q", r.StageStatus, r.ErrorCode)
	}
	if !validStagingID(r.StagingID) {
		t.Errorf("default staging id is not a valid opaque handle: %q", r.StagingID)
	}
}

// TestStage_NegativeRedirectCapFailsClosed proves a misconfigured negative
// redirect cap (which would disable the hop limit) fails closed before download.
func TestStage_NegativeRedirectCapFailsClosed(t *testing.T) {
	s, dl, _ := newHappyStager(t)
	s.URLPolicy.MaxRedirects = -1
	r := s.Stage(context.Background(), happyPayload(), "1.0.0")
	if r.ErrorCode != ErrStagingIO {
		t.Fatalf("negative redirect cap must fail closed STAGING_IO, got %q/%q", r.StageStatus, r.ErrorCode)
	}
	if dl.gotURL != "" {
		t.Error("download happened despite a misconfigured redirect cap")
	}
}
