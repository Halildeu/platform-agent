package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// stager.go — AG-029 PR1 verifier/stager ORCHESTRATION (cross-platform).
//
// PR0 delivered the I/O-free policy core (EvaluatePreflight + the Evaluate*
// gates). PR1a wires those gates to real I/O THROUGH INTERFACES, so the entire
// security ordering is unit-testable with fakes on any OS. The Windows syscall
// implementations of the interfaces (Authenticode verify, PE-version read,
// DACL-hardened staging) land in PR1b and are verified on the Windows VM; this
// file references only the interfaces and never a windows-only symbol.
//
// Gate order (fail-closed, each step gated on the previous):
//
//	preflight(platform/shape/tier/version/url)  [PR0, non-I/O]
//	 -> download (url+redirect policy + hard size cap)   DOWNLOAD_*
//	 -> recompute SHA-256 (evidence; NOT a backend-claim gate — must-fix #1)
//	 -> Authenticode verify -> EvaluateAuthenticodePolicy SIGNATURE_INVALID
//	 -> EvaluateSignerPolicy (LOCAL allowlist authority)  SIGNER_NOT_ALLOWED
//	 -> artifact-version bind (signed stamp == target)    CATALOG_MISMATCH  [must-fix #2]
//	 -> stage atomically into hardened dir                STAGING_IO_FAILED
//	 -> StageResult{STAGED_ACTIVATION_READY, ...}         (never an activation status)

// AuthenticodeVerifier extracts signature evidence from an on-disk file. The
// real implementation (PR1b, windows) drives WinVerifyTrust + chain build +
// EKU + timestamp; the non-windows build and tests inject a fake/stub. A nil
// or stub verifier fails closed.
type AuthenticodeVerifier interface {
	Verify(ctx context.Context, path string) (AuthenticodeEvidence, error)
}

// PEVersionReader reads the version a publisher stamped into (and signed over)
// a binary, so the claimed targetVersion can be bound to the signed artifact
// (must-fix #2). Real impl: PR1b windows PE VersionInfo reader.
type PEVersionReader interface {
	// ReadVersion returns the binary's embedded version string (e.g.
	// "1.2.3" or a Windows "1.2.3.0" file version), or "" when the binary
	// carries no readable version resource.
	ReadVersion(ctx context.Context, path string) (string, error)
}

// BinaryDownloader streams a URL to dst under URL+redirect policy with a hard
// byte cap, returning a bounded ErrorCode (DOWNLOAD_FAILED / DOWNLOAD_TOO_LARGE
// / POLICY_URL_REJECTED) on failure. The cross-platform net/http impl lives in
// download.go.
type BinaryDownloader interface {
	Download(ctx context.Context, rawURL string, pol URLPolicy, maxBytes int64, dst io.Writer) (n int64, code ErrorCode, reason string)
}

// HighWaterStore reads the persisted, ACTIVATED-only version high-water mark
// (must-fix #3). PR1 READS + gates on it but NEVER advances it; PR3 advances it
// after a successful activation. A corrupt store fails closed.
type HighWaterStore interface {
	// ReadMaxSeen returns the highest version this device has ACTIVATED, "" if
	// none is recorded yet (first install). A non-nil error means the store is
	// present but unreadable/corrupt and the caller must fail closed.
	ReadMaxSeen(ctx context.Context) (string, error)
}

// StagingStore atomically commits the verified bytes into a hardened staging
// directory (must-fix #4: hardened DACL, reparse-point guard, no overwrite).
// The portable (non-windows) impl in staging_portable.go is for tests only and
// refuses to run on windows; the hardened windows impl lands in PR1b.
type StagingStore interface {
	// Commit moves the already-verified file at tempPath into the protected
	// staging area under the opaque stagingID and returns the on-disk staged
	// path (local-only; never returned to the backend). It must apply the
	// hardened ACL and refuse symlink/junction/overwrite targets.
	Commit(ctx context.Context, tempPath, stagingID string) (stagedPath string, err error)
}

// Stager runs the PR1 verify+stage pipeline. All collaborators are injected so
// the security ordering is testable with fakes; production wiring (PR2) injects
// the real Windows implementations.
type Stager struct {
	Verifier      AuthenticodeVerifier
	VersionReader PEVersionReader
	Downloader    BinaryDownloader
	HighWater     HighWaterStore
	Staging       StagingStore

	// Allowlist is the LOCAL signer trust anchor — the ONLY "may I run this"
	// authority (backend claims are never consulted).
	Allowlist SignerAllowlist
	// TierPolicy / URLPolicy are the local download + tier guardrails.
	TierPolicy TierPolicy
	URLPolicy  URLPolicy

	// HardMaxBytes is the absolute local download cap. The payload's MaxBytes
	// may only LOWER the effective cap, never raise it (must-fix #4: a backend
	// value is audit/DoS-limiting input, never authority-raising). Must be > 0.
	HardMaxBytes int64
	// GOOS overrides the platform string fed to the preflight platform gate.
	// Empty => runtime.GOOS (production). Tests set "windows" to exercise the
	// pipeline on a non-windows CI host; the real Windows collaborators are
	// still injected as fakes.
	GOOS string
	// TempDir is the directory for the in-progress download temp file (same
	// volume as the staging root so the final move is an atomic rename).
	TempDir string
	// NewStagingID mints an opaque correlation handle (NOT derived from the URL
	// or version). Injected for deterministic tests; defaults to a random id.
	NewStagingID func() string

	// ExpectedHash, when non-empty, is a TRUSTED LOCAL expected SHA-256 (hex)
	// sourced from a future signed release catalog — NOT the backend claim.
	// When set, the recomputed hash must equal it (HASH_MISMATCH otherwise).
	// Empty in v1: the signature + signer-allowlist + version-bind are the
	// authority, and the backend's claimedSha256 is audit-only (must-fix #1).
	ExpectedHash string
}

// errStubVerifier is returned by the non-windows / unconfigured verifier.
var errStubVerifier = errors.New("authenticode verification unavailable on this platform")

// Stage runs the full PR1 pipeline for a payload and returns a bounded
// StageResult. currentVersion is the running agent's version. It performs no
// activation and returns no activation status.
func (s *Stager) Stage(ctx context.Context, payload UpdateAgentPayload, currentVersion string) StageResult {
	// --- must-fix #3: read the ACTIVATED-only high-water mark, fail closed on
	// a corrupt store BEFORE any version decision. A missing store ("") is a
	// first-install and is handled by EvaluateVersionPolicy.
	maxSeen, err := s.readMaxSeen(ctx)
	if err != nil {
		return Failed(ErrVersionUnparseable, "high-water state unreadable; failing closed")
	}

	// --- PR0 non-I/O gates: platform -> shape -> tier -> version -> url.
	pre := EvaluatePreflight(PreflightInput{
		Platform:       s.goos(),
		CurrentVersion: currentVersion,
		MaxSeenVersion: maxSeen,
		Payload:        payload,
		URLPolicy:      s.URLPolicy,
		TierPolicy:     s.TierPolicy,
	})
	if pre.Noop {
		return pre.Result
	}
	if !pre.Proceed {
		return pre.Result
	}

	if s.HardMaxBytes <= 0 {
		return Failed(ErrStagingIO, "stager misconfigured: no download cap")
	}
	if s.Downloader == nil || s.Verifier == nil || s.VersionReader == nil || s.Staging == nil {
		return Failed(ErrStagingIO, "stager misconfigured: missing collaborator")
	}

	// --- download to a temp file while streaming the SHA-256.
	tmp, err := os.CreateTemp(s.TempDir, "agent-update-*.tmp")
	if err != nil {
		return Failed(ErrStagingIO, "could not create temp download file")
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup of the temp artifact on every exit (a successful
	// Commit moves the bytes out first, so removing the temp name is safe).
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	h := sha256.New()
	effMax := s.effectiveMaxBytes(payload.MaxBytes)
	if _, code, reason := s.Downloader.Download(ctx, payload.BinaryURL, s.URLPolicy, effMax, io.MultiWriter(tmp, h)); code != "" {
		return Failed(code, reason)
	}
	if err := tmp.Sync(); err != nil {
		return Failed(ErrStagingIO, "could not flush temp download file")
	}
	actualSha := hex.EncodeToString(h.Sum(nil))

	// --- must-fix #1: the recomputed hash is EVIDENCE. It is compared ONLY to
	// a TRUSTED LOCAL expected hash (signed catalog), never to the backend's
	// audit-only claimedSha256. In v1 ExpectedHash is empty, so signature +
	// allowlist + version-bind are the authority.
	if s.ExpectedHash != "" && !strings.EqualFold(actualSha, strings.TrimSpace(s.ExpectedHash)) {
		return Failed(ErrHashMismatch, "staged bytes do not match the trusted local expected hash")
	}

	// --- Authenticode verification (signature shape/validity) + EKU + timestamp.
	ev, verr := s.Verifier.Verify(ctx, tmpPath)
	if verr != nil {
		return Failed(ErrSignatureInvalid, "authenticode verification failed")
	}
	if ad := EvaluateAuthenticodePolicy(ev, payload.SigningTier); !ad.Allowed {
		return Failed(ad.Code, ad.Reason)
	}

	// --- LOCAL signer-allowlist AUTHORITY gate (the verified thumbprint only).
	if sd := EvaluateSignerPolicy(ev.SignerThumbprint, s.Allowlist); !sd.Allowed {
		return Failed(sd.Code, sd.Reason)
	}

	// --- must-fix #2: bind the claimed target to the SIGNED artifact's stamp.
	peVersion, rerr := s.VersionReader.ReadVersion(ctx, tmpPath)
	if rerr != nil {
		return Failed(ErrCatalogMismatch, "could not read the binary version stamp")
	}
	if code, reason := EvaluateArtifactVersionBinding(peVersion, payload.TargetVersion); code != "" {
		return Failed(code, reason)
	}

	// --- stage atomically into the hardened directory.
	stagingID := s.mintStagingID()
	stagedPath, serr := s.Staging.Commit(ctx, tmpPath, stagingID)
	if serr != nil {
		return Failed(ErrStagingIO, "could not stage the verified binary")
	}
	_ = stagedPath // local-only; intentionally NOT placed on the wire.

	return StageResult{
		StageStatus:            StageReady,
		StagingID:              stagingID,
		ActivationPlanID:       stagingID,
		OldVersion:             currentVersion,
		TargetVersion:          payload.TargetVersion,
		ActualSha256:           actualSha,
		ActualSignerThumbprint: ev.SignerThumbprint,
		SigningTier:            payload.SigningTier,
		Reason:                 "verified and staged; awaiting activation",
	}
}

// readMaxSeen reads the activated-version high-water mark, treating a nil store
// as "no record" (first install). A present-but-corrupt store returns an error
// so the caller fails closed.
func (s *Stager) readMaxSeen(ctx context.Context) (string, error) {
	if s.HighWater == nil {
		return "", nil
	}
	return s.HighWater.ReadMaxSeen(ctx)
}

// goos returns the platform string for the preflight gate: the injected
// override when set, else the real runtime.GOOS.
func (s *Stager) goos() string {
	if s.GOOS != "" {
		return s.GOOS
	}
	return defaultGOOS()
}

// effectiveMaxBytes returns the download cap: the local hard cap, optionally
// LOWERED (never raised) by a positive payload MaxBytes.
func (s *Stager) effectiveMaxBytes(payloadMax int64) int64 {
	eff := s.HardMaxBytes
	if payloadMax > 0 && payloadMax < eff {
		eff = payloadMax
	}
	return eff
}

// mintStagingID returns an opaque correlation handle.
func (s *Stager) mintStagingID() string {
	if s.NewStagingID != nil {
		return s.NewStagingID()
	}
	return randomStagingID()
}

// stagedNameFor is a small helper used by staging implementations to keep the
// on-disk staged filename opaque (NOT derived from the URL/version) and within
// the staging root.
func stagedNameFor(root, stagingID string) string {
	return filepath.Join(root, "staged-"+stagingID+".bin")
}
