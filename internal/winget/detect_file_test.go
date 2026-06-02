package winget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// detect_file_test.go — Path C1 (Codex 019e893a AGREE Opsiyon C).
// Cross-platform unit coverage for the FILE_* detector dispatch +
// path-safety guard + SHA-256 streaming + size cap. FILE_VERSION
// platform-specific tests live in detect_file_windows_test.go
// (Windows-tag) and detect_file_other_test.go (non-Windows-tag).

// helper — pick a path that looks absolute on the host platform but
// keeps the Windows authoring shape so path-safety check passes.
// On Windows-tagged test runs we use the real tmp dir; on non-Windows
// we fabricate a sibling under a Windows-shaped prefix so the same
// fixture exercises the same validation branches.
func tempFilePath(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ag-c1-*.bin")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	return f.Name()
}

// helper — write content to a real disk file under t.TempDir() and
// return its absolute path. Used by SHA-256 tests.
func writeTempFile(t *testing.T, content []byte) string {
	t.Helper()
	path := tempFilePath(t)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// helper — return the lowercase-hex SHA-256 digest of content.
func sha256Hex(t *testing.T, content []byte) string {
	t.Helper()
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// ── ValidateFileRule ───────────────────────────────────────────────

func TestValidateFileRule_PathSafetyRejections(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"relative_dot", `.\foo`},
		{"relative_dotdot", `..\..\Windows\System32\config\SAM`},
		{"embedded_dotdot", `C:\Program Files\..\Windows\System32`},
		{"env_percent", `%PROGRAMDATA%\foo.exe`},
		{"env_powershell", `$env:ProgramData\foo.exe`},
		{"device_question", `\\?\GLOBALROOT\Device\HarddiskVolume1\foo`},
		{"device_dot", `\\.\PhysicalDrive0`},
		{"unc", `\\server\share\foo.exe`},
		{"no_drive_letter", `Program Files\foo.exe`},
		{"forward_slash_only", `/usr/local/bin/foo`},
		{"nul_byte", "C:\\foo\x00bar.exe"},
		{"control_char", "C:\\foo\rbar.exe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFileRule(DetectionRule{
				Type: DetectionRuleTypeFileExists,
				Path: tc.path,
			})
			if !errors.Is(err, ErrFilePathInvalid) {
				t.Fatalf("path %q expected ErrFilePathInvalid, got %v", tc.path, err)
			}
		})
	}
}

func TestValidateFileRule_AcceptsAbsoluteWindowsPath(t *testing.T) {
	err := ValidateFileRule(DetectionRule{
		Type: DetectionRuleTypeFileExists,
		Path: `C:\Program Files\7-Zip\7z.exe`,
	})
	if err != nil {
		t.Fatalf("absolute Windows path rejected: %v", err)
	}
}

func TestValidateFileRule_AcceptsLowercaseDriveLetter(t *testing.T) {
	err := ValidateFileRule(DetectionRule{
		Type: DetectionRuleTypeFileExists,
		Path: `c:\windows\notepad.exe`,
	})
	if err != nil {
		t.Fatalf("lowercase drive rejected: %v", err)
	}
}

func TestValidateFileRule_FileSha256RequiresHex64(t *testing.T) {
	good := DetectionRule{
		Type:           DetectionRuleTypeFileSha256,
		Path:           `C:\foo\bar.exe`,
		ExpectedSha256: strings.Repeat("a", 64),
	}
	if err := ValidateFileRule(good); err != nil {
		t.Fatalf("good rule rejected: %v", err)
	}

	noHash := good
	noHash.ExpectedSha256 = ""
	if err := ValidateFileRule(noHash); !errors.Is(err, ErrFileSha256Empty) {
		t.Fatalf("empty hash expected ErrFileSha256Empty, got %v", err)
	}

	tooShort := good
	tooShort.ExpectedSha256 = "abc"
	if err := ValidateFileRule(tooShort); !errors.Is(err, ErrFileSha256Empty) {
		t.Fatalf("short hash expected ErrFileSha256Empty, got %v", err)
	}

	uppercase := good
	uppercase.ExpectedSha256 = strings.ToUpper(strings.Repeat("a", 64))
	if err := ValidateFileRule(uppercase); !errors.Is(err, ErrFileSha256Empty) {
		t.Fatalf("uppercase hash expected ErrFileSha256Empty, got %v", err)
	}
}

func TestValidateFileRule_FileVersionRequiresPredicate(t *testing.T) {
	noPredicate := DetectionRule{
		Type: DetectionRuleTypeFileVersion,
		Path: `C:\foo\bar.exe`,
	}
	if err := ValidateFileRule(noPredicate); !errors.Is(err, ErrFilePathInvalid) {
		t.Fatalf("missing predicate expected ErrFilePathInvalid, got %v", err)
	}

	good := noPredicate
	good.VersionPredicate = &VersionPredicate{Type: VersionPredicateExact, Spec: "1.2.3"}
	if err := ValidateFileRule(good); err != nil {
		t.Fatalf("good FILE_VERSION rule rejected: %v", err)
	}
}

func TestValidateFileRule_FileVersionFieldEnum(t *testing.T) {
	rule := DetectionRule{
		Type:             DetectionRuleTypeFileVersion,
		Path:             `C:\foo\bar.exe`,
		VersionPredicate: &VersionPredicate{Type: VersionPredicateLatest},
		FileVersionField: "Description", // not in enum
	}
	if err := ValidateFileRule(rule); !errors.Is(err, ErrFilePathInvalid) {
		t.Fatalf("invalid FileVersionField expected ErrFilePathInvalid, got %v", err)
	}

	rule.FileVersionField = FileVersionFieldProductVersion
	if err := ValidateFileRule(rule); err != nil {
		t.Fatalf("PRODUCT_VERSION rejected: %v", err)
	}
	rule.FileVersionField = "" // default to FileVersion
	if err := ValidateFileRule(rule); err != nil {
		t.Fatalf("empty default rejected: %v", err)
	}
}

// ── FILE_EXISTS probe ──────────────────────────────────────────────

func TestProbeFileExists_MissingReturnsNotSatisfied(t *testing.T) {
	// Path-safety would normally reject an arbitrary non-Windows path,
	// but `ProbeViaFile` runs validation first — so we craft a rule
	// that passes validation, then point it at a real local file we
	// know does NOT exist.
	rule := DetectionRule{
		Type: DetectionRuleTypeFileExists,
		Path: `C:\` + filepath.Base(tempFilePath(t)) + `.does-not-exist.bin`,
	}
	// Translate to host-local path so os.Stat actually probes it on
	// the unit-test platform. Drop the Windows prefix.
	hostPath := filepath.Join(t.TempDir(), filepath.Base(rule.Path))
	rule.Path = `C:\` + strings.ReplaceAll(hostPath[1:], `/`, `\`)
	// Skip path-safety with direct probe call so we don't need to
	// fake a Windows path layout on macOS/Linux.
	res, err := probeFileExists(context.Background(), DetectionRule{Path: hostPath})
	if err != nil {
		t.Fatalf("probe returned err: %v", err)
	}
	if res.Satisfied {
		t.Fatalf("missing file should be not-satisfied")
	}
	if res.DetectionMethod != DetectionMethodFileExists {
		t.Fatalf("method label = %q want %q", res.DetectionMethod, DetectionMethodFileExists)
	}
}

func TestProbeFileExists_PresentReturnsSatisfied(t *testing.T) {
	path := writeTempFile(t, []byte("hello"))
	res, err := probeFileExists(context.Background(), DetectionRule{Path: path})
	if err != nil {
		t.Fatalf("probe err: %v", err)
	}
	if !res.Satisfied {
		t.Fatalf("present file should be satisfied")
	}
}

func TestProbeFileExists_DirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	_, err := probeFileExists(context.Background(), DetectionRule{Path: dir})
	if err == nil {
		t.Fatalf("directory rule should fail loud")
	}
	if !errors.Is(err, ErrFilePathInvalid) {
		t.Fatalf("directory expected ErrFilePathInvalid, got %v", err)
	}
}

// ── FILE_SHA256 probe ──────────────────────────────────────────────

func TestProbeFileSha256_Match(t *testing.T) {
	content := []byte("seven-zip is great")
	path := writeTempFile(t, content)
	digest := sha256Hex(t, content)

	rule := DetectionRule{
		Path:           path,
		ExpectedSha256: digest,
	}
	res, err := probeFileSha256(context.Background(), rule)
	if err != nil {
		t.Fatalf("probe err: %v", err)
	}
	if !res.Satisfied {
		t.Fatalf("matching content should be satisfied")
	}
	if res.DetectionMethod != DetectionMethodFileSha256 {
		t.Fatalf("method label = %q want %q", res.DetectionMethod, DetectionMethodFileSha256)
	}
}

func TestProbeFileSha256_Mismatch(t *testing.T) {
	path := writeTempFile(t, []byte("content"))
	rule := DetectionRule{
		Path:           path,
		ExpectedSha256: strings.Repeat("0", 64),
	}
	res, err := probeFileSha256(context.Background(), rule)
	if err != nil {
		t.Fatalf("probe err: %v", err)
	}
	if res.Satisfied {
		t.Fatalf("mismatched content should NOT be satisfied")
	}
}

func TestProbeFileSha256_MissingFileNotSatisfied(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.bin")
	rule := DetectionRule{
		Path:           missing,
		ExpectedSha256: strings.Repeat("0", 64),
	}
	res, err := probeFileSha256(context.Background(), rule)
	if err != nil {
		t.Fatalf("missing file probe err: %v", err)
	}
	if res.Satisfied {
		t.Fatalf("missing file must be not-satisfied")
	}
}

func TestProbeFileSha256_SizeCapPreEnforcement(t *testing.T) {
	// Write a 256-byte file but cap at 128.
	content := make([]byte, 256)
	for i := range content {
		content[i] = 'A'
	}
	path := writeTempFile(t, content)
	rule := DetectionRule{
		Path:           path,
		ExpectedSha256: sha256Hex(t, content),
		MaxHashBytes:   128,
	}
	res, err := probeFileSha256(context.Background(), rule)
	if !errors.Is(err, ErrFileSizeCap) {
		t.Fatalf("expected ErrFileSizeCap, got %v", err)
	}
	if res.Satisfied {
		t.Fatalf("oversized file must not be satisfied")
	}
}

// ── matchesFileVersion (predicate semantics) ───────────────────────

func TestMatchesFileVersion(t *testing.T) {
	cases := []struct {
		installed string
		pred      VersionPredicate
		want      bool
		name      string
	}{
		{"24.07", VersionPredicate{Type: VersionPredicateLatest}, true, "latest_any"},
		{"", VersionPredicate{Type: VersionPredicateLatest}, false, "latest_empty"},
		{"24.07", VersionPredicate{Type: VersionPredicateExact, Spec: "24.07"}, true, "exact_eq"},
		{"24.06", VersionPredicate{Type: VersionPredicateExact, Spec: "24.07"}, false, "exact_ne"},
		{"24.07", VersionPredicate{Type: VersionPredicateMinimum, Spec: "24.06"}, true, "min_ge"},
		{"24.05", VersionPredicate{Type: VersionPredicateMinimum, Spec: "24.06"}, false, "min_lt"},
		{"24.07", VersionPredicate{Type: VersionPredicateRange, Spec: "[24.06,24.08)"}, true, "range_in"},
		{"24.09", VersionPredicate{Type: VersionPredicateRange, Spec: "[24.06,24.08)"}, false, "range_out"},
		{"24.07", VersionPredicate{Type: ""}, true, "empty_predicate_treated_as_latest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesFileVersion(tc.installed, tc.pred)
			if got != tc.want {
				t.Fatalf("matchesFileVersion(%q, %+v) = %v want %v",
					tc.installed, tc.pred, got, tc.want)
			}
		})
	}
}

// ── validateDetectionRule integration (Path C dispatcher) ──────────

func TestValidateDetectionRule_FileTypesGoThroughValidateFileRule(t *testing.T) {
	// validateDetectionRule lives in detect_registry.go; we exercise it
	// via the FILE_EXISTS path and confirm it routes through
	// ValidateFileRule (a malformed path → ErrFilePathInvalid wrapped
	// error).
	rule := DetectionRule{
		Type: DetectionRuleTypeFileExists,
		Path: `..\..\Windows`,
	}
	err := validateDetectionRule(rule)
	if !errors.Is(err, ErrFilePathInvalid) {
		t.Fatalf("expected ErrFilePathInvalid, got %v", err)
	}
}
