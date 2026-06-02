package winget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Path C — Faz 22 Codex 019e893a AGREE Opsiyon C.
//
// detect_file.go contains the cross-platform FILE_* detector dispatch
// and shared path-safety / streaming-hash machinery used by all three
// FILE_* rule types. Windows-specific FILE_VERSION reads PE VersionInfo
// in detect_file_windows.go; non-Windows platforms return
// FAILED_UNSUPPORTED_PLATFORM from detect_file_other.go (mirrors the
// AG-027 install_winget cross-platform stub pattern).
//
// HARD RULE No Fake Work — every detector returns a deterministic
// Satisfied bool + DetectionMethod label + an error path that maps to
// the canonical AG-027 failure-final-statuses; there is no silent
// "satisfied=false because we don't know" branch. An unknown error
// surfaces explicitly so the executor maps it to
// FinalStatusFailedInternal (not FAILED_VERIFICATION which would
// mis-attribute the cause).
//
// HARD RULE Uzun Vadeli Kalıcı Çözüm — path safety guards reject
// every documented Windows-path injection vector (relative `..`,
// `%ENV%`, `$env:`, `\\?\`, `\\.\`, UNC `\\server\`, missing drive
// letter on Windows). SHA-256 streaming is hard-capped so an attacker
// cannot stall the agent by pointing a rule at a multi-TB file. A
// detector deadline (default 30s) bounds the worst-case probe.

// Errors surfaced from file-detector validation. The executor maps
// these to FinalStatusFailedUnsupportedDetectionRule (validation) and
// FinalStatusFailedInternal (IO surprise) so the audit trail can
// distinguish "operator gave a bad rule" from "device IO failed".

var (
	// ErrFilePathInvalid is returned by ValidateFileRule when the rule's
	// Path is missing, relative, env-expansion-laden, UNC, device or
	// otherwise unsafe.
	ErrFilePathInvalid = errors.New("path C1: file rule path failed safety validation")

	// ErrFileSizeCap is returned when SHA-256 streaming encounters a
	// file larger than the configured MaxHashBytes cap.
	ErrFileSizeCap = errors.New("path C1: file size exceeds hash cap")

	// ErrFileSha256Empty is returned when a FILE_SHA256 rule is missing
	// its ExpectedSha256 value (validator rejects fail-closed).
	ErrFileSha256Empty = errors.New("path C1: FILE_SHA256 rule missing ExpectedSha256")
)

// ProbeViaFile is the cross-platform entry point for FILE_EXISTS /
// FILE_SHA256 / FILE_VERSION detection. Windows-only rules
// (FILE_VERSION) dispatch into the build-tagged
// `probeFileVersionWindows` (or stub) below. The function returns a
// PreDetectResult sufficient for both pre-detect and post-verify
// consumers (the executor reuses the same value with DetectionMethod
// tag changed). Errors fall through to the executor's existing
// FAILED_INTERNAL / FAILED_UNSUPPORTED_DETECTION_RULE mapping.
func ProbeViaFile(ctx context.Context, rule DetectionRule) (PreDetectResult, error) {
	if err := ValidateFileRule(rule); err != nil {
		return PreDetectResult{DetectionMethod: detectionMethodForFileRule(rule.Type)}, err
	}

	ctx, cancel := context.WithTimeout(ctx, FileDetectorDeadline)
	defer cancel()

	switch rule.Type {
	case DetectionRuleTypeFileExists:
		return probeFileExists(ctx, rule)
	case DetectionRuleTypeFileSha256:
		return probeFileSha256(ctx, rule)
	case DetectionRuleTypeFileVersion:
		return probeFileVersion(ctx, rule)
	default:
		return PreDetectResult{}, fmt.Errorf(
			"path C1 ProbeViaFile called with non-file rule type %q",
			rule.Type)
	}
}

// detectionMethodForFileRule maps a FILE_* rule type to its audit-trail
// method label.
func detectionMethodForFileRule(t DetectionRuleType) string {
	switch t {
	case DetectionRuleTypeFileExists:
		return DetectionMethodFileExists
	case DetectionRuleTypeFileSha256:
		return DetectionMethodFileSha256
	case DetectionRuleTypeFileVersion:
		return DetectionMethodFileVersion
	default:
		return ""
	}
}

// ValidateFileRule applies path-safety + per-type required-field
// validation BEFORE any IO. Codex 019e893a P1 absorb: every rejected
// vector below corresponds to a real attack/authoring mistake.
func ValidateFileRule(rule DetectionRule) error {
	if rule.Path == "" {
		return fmt.Errorf("%w: empty path", ErrFilePathInvalid)
	}
	if err := validateFilePathSafety(rule.Path); err != nil {
		return err
	}

	switch rule.Type {
	case DetectionRuleTypeFileExists:
		// path-only; nothing else to validate.
		return nil
	case DetectionRuleTypeFileSha256:
		if rule.ExpectedSha256 == "" {
			return ErrFileSha256Empty
		}
		// Lowercase hex 64 chars.
		if len(rule.ExpectedSha256) != 64 {
			return fmt.Errorf("%w: ExpectedSha256 must be 64 hex chars (got %d)",
				ErrFileSha256Empty, len(rule.ExpectedSha256))
		}
		for _, c := range rule.ExpectedSha256 {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return fmt.Errorf("%w: ExpectedSha256 must be lowercase hex (bad char %q)",
					ErrFileSha256Empty, c)
			}
		}
		return nil
	case DetectionRuleTypeFileVersion:
		if rule.VersionPredicate == nil {
			return fmt.Errorf("%w: FILE_VERSION rule missing VersionPredicate",
				ErrFilePathInvalid)
		}
		// VersionPredicate.Spec validation reuses the WinGet predicate
		// contract — empty allowed for LATEST, required for EXACT/MIN/RANGE.
		// FileVersionField defaults to FileVersion when empty.
		if rule.FileVersionField != "" &&
			rule.FileVersionField != FileVersionFieldFileVersion &&
			rule.FileVersionField != FileVersionFieldProductVersion {
			return fmt.Errorf("%w: FileVersionField must be FILE_VERSION or PRODUCT_VERSION (got %q)",
				ErrFilePathInvalid, rule.FileVersionField)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported file rule type %q",
			ErrFilePathInvalid, rule.Type)
	}
}

// validateFilePathSafety rejects every documented Windows-path
// injection vector. The agent only ever reads (never writes) the
// target file, but a rule that points at `\\?\GLOBALROOT\Device\...`
// or `%PROGRAMDATA%\..\..\..\Windows\System32\config\SAM` could leak
// arbitrary content via hash echo or be used to wedge the agent on
// special handles. Fail-closed.
func validateFilePathSafety(path string) error {
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("%w: NUL byte in path", ErrFilePathInvalid)
	}
	// Reject Windows env-var expansion syntax (`%FOO%`, `$env:FOO`).
	if strings.Contains(path, "%") {
		return fmt.Errorf("%w: %%-style env expansion not allowed",
			ErrFilePathInvalid)
	}
	if strings.HasPrefix(path, "$env:") || strings.HasPrefix(path, "$Env:") {
		return fmt.Errorf("%w: PowerShell-style env expansion not allowed",
			ErrFilePathInvalid)
	}
	// Reject Windows device namespaces + UNC.
	if strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) {
		return fmt.Errorf("%w: device namespace not allowed",
			ErrFilePathInvalid)
	}
	if strings.HasPrefix(path, `\\`) {
		return fmt.Errorf("%w: UNC path not allowed",
			ErrFilePathInvalid)
	}
	// Reject relative segments. `..` either at the start, embedded
	// (e.g. `C:\Program Files\..\Windows`) or as a sole component.
	// (forward and backward separators both checked because Windows
	// accepts both.)
	for _, sep := range []string{`\`, `/`} {
		parts := strings.Split(path, sep)
		for _, p := range parts {
			if p == ".." || p == "." {
				return fmt.Errorf("%w: relative segment %q not allowed",
					ErrFilePathInvalid, p)
			}
		}
	}
	// Reject embedded NUL-like control characters (CR/LF/TAB) that
	// could be used to inject log lines or smuggle commands.
	for _, r := range path {
		if r < 0x20 {
			return fmt.Errorf("%w: control char %d not allowed",
				ErrFilePathInvalid, r)
		}
	}
	// Windows-only absoluteness check: must look like `<DRIVE>:\...` —
	// non-Windows platforms hit the FILE_VERSION cross-platform stub
	// before reaching here, so this guard is safe to apply uniformly.
	if !looksLikeAbsoluteWindowsPath(path) {
		return fmt.Errorf("%w: path is not an absolute Windows path (need drive letter + backslash)",
			ErrFilePathInvalid)
	}
	return nil
}

// looksLikeAbsoluteWindowsPath returns true when path starts with
// `<letter>:\...`. This is the canonical form a SYSTEM-level agent on
// Windows would see; non-Windows test runs use the same form because
// rules are authored against Windows endpoints regardless of where
// they happen to be unit-tested.
func looksLikeAbsoluteWindowsPath(path string) bool {
	if len(path) < 3 {
		return false
	}
	c := path[0]
	if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
		return false
	}
	if path[1] != ':' {
		return false
	}
	if path[2] != '\\' && path[2] != '/' {
		return false
	}
	return true
}

// probeFileExists is the FILE_EXISTS probe. It returns Satisfied=true
// when the path resolves to an existing regular file (not a directory,
// not a symlink to a directory, not a special device). Path safety has
// already gated the input.
func probeFileExists(_ context.Context, rule DetectionRule) (PreDetectResult, error) {
	info, err := os.Stat(rule.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return PreDetectResult{
				Satisfied:       false,
				DetectionMethod: DetectionMethodFileExists,
			}, nil
		}
		return PreDetectResult{DetectionMethod: DetectionMethodFileExists}, err
	}
	if info.IsDir() {
		// A FILE_EXISTS rule pointing at a directory is operator
		// error, not a denial — fail loud (Codex 019e893a P3:
		// fail-loud on contract drift).
		return PreDetectResult{DetectionMethod: DetectionMethodFileExists},
			fmt.Errorf("%w: path is a directory, not a file",
				ErrFilePathInvalid)
	}
	return PreDetectResult{
		Satisfied:       true,
		DetectionMethod: DetectionMethodFileExists,
		MatchedVersion:  "",
	}, nil
}

// probeFileSha256 streams the file content through SHA-256 with a
// hard size cap. Returns Satisfied=true only when the lowercase-hex
// digest equals ExpectedSha256.
func probeFileSha256(ctx context.Context, rule DetectionRule) (PreDetectResult, error) {
	info, err := os.Stat(rule.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return PreDetectResult{
				Satisfied:       false,
				DetectionMethod: DetectionMethodFileSha256,
			}, nil
		}
		return PreDetectResult{DetectionMethod: DetectionMethodFileSha256}, err
	}
	if info.IsDir() {
		return PreDetectResult{DetectionMethod: DetectionMethodFileSha256},
			fmt.Errorf("%w: path is a directory, not a file",
				ErrFilePathInvalid)
	}

	cap := rule.MaxHashBytes
	if cap <= 0 {
		cap = FileMaxHashBytes
	}
	if info.Size() > cap {
		return PreDetectResult{
			Satisfied:       false,
			DetectionMethod: DetectionMethodFileSha256,
		}, fmt.Errorf("%w: %d > %d", ErrFileSizeCap, info.Size(), cap)
	}

	f, err := os.Open(rule.Path)
	if err != nil {
		return PreDetectResult{DetectionMethod: DetectionMethodFileSha256}, err
	}
	defer f.Close()

	h := sha256.New()
	// Wrap reader in a context-aware copier that honours the deadline
	// + size cap. io.CopyN with cap+1 lets us detect a size that
	// exceeds the cap mid-stream (race against a growing file).
	written, err := copyCancellable(ctx, h, f, cap+1)
	if err != nil {
		return PreDetectResult{DetectionMethod: DetectionMethodFileSha256}, err
	}
	if written > cap {
		return PreDetectResult{
			Satisfied:       false,
			DetectionMethod: DetectionMethodFileSha256,
		}, fmt.Errorf("%w: streamed %d > %d", ErrFileSizeCap, written, cap)
	}

	digest := hex.EncodeToString(h.Sum(nil))
	return PreDetectResult{
		Satisfied:       digest == rule.ExpectedSha256,
		DetectionMethod: DetectionMethodFileSha256,
	}, nil
}

// copyCancellable copies up to `limit` bytes from src to dst,
// observing ctx cancellation between chunks. This bounds the per-read
// blocking time so a slow / hostile filesystem cannot starve the
// detector deadline.
func copyCancellable(ctx context.Context, dst io.Writer, src io.Reader, limit int64) (int64, error) {
	const chunk = 256 * 1024
	buf := make([]byte, chunk)
	var total int64
	for total < limit {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
		remaining := limit - total
		if remaining < int64(len(buf)) {
			buf = buf[:remaining]
		}
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// probeFileVersion dispatches to the platform-specific implementation.
// On Windows it reads PE VersionInfo and compares against the
// VersionPredicate. On non-Windows it returns the
// FAILED_UNSUPPORTED_PLATFORM-style stub.
func probeFileVersion(ctx context.Context, rule DetectionRule) (PreDetectResult, error) {
	return probeFileVersionPlatform(ctx, rule)
}

// fileVersionTimeoutTrace is exposed so tests can verify that the
// detector deadline is respected without flake. Unused in production.
var fileVersionTimeoutTrace = time.Duration(0)

// matchesFileVersion is the platform-independent comparison helper
// used by both Windows and other platforms (latter only in tests).
// Reuses the WinGet version comparator so the operator-facing
// authoring contract is uniform.
func matchesFileVersion(installed string, predicate VersionPredicate) bool {
	if predicate.Type == VersionPredicateLatest || predicate.Type == "" {
		// LATEST / unspecified — presence of any version is enough.
		return installed != ""
	}
	if installed == "" {
		return false
	}
	switch predicate.Type {
	case VersionPredicateExact:
		return compareVersions(installed, predicate.Spec) == 0
	case VersionPredicateMinimum:
		return compareVersions(installed, predicate.Spec) >= 0
	case VersionPredicateRange:
		return rangeSatisfied(installed, predicate.Spec)
	default:
		return false
	}
}
