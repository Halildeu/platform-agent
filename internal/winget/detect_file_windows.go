//go:build windows

package winget

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// detect_file_windows.go — Windows-only PE VersionInfo reader for
// FILE_VERSION detection. Codex 019e893a P1: use the Win32 version
// API (GetFileVersionInfoW + VerQueryValueW), NOT a PowerShell
// shell-out. The shell-out path would (a) require SYSTEM-context
// PowerShell launch (fragile under Session-0), (b) leak the binary
// path into a child process command line (audit smell), and (c)
// hand attacker-controlled output through a shell parser.
//
// The Win32 API uses the language-neutral translation block
// (`040904B0` — English (US) / Unicode) when the requested
// translation is missing, mirroring how Explorer's properties
// dialog selects a value. A binary with no version resource at all
// returns Satisfied=false (operator authoring error / unsigned
// binary), never panics.

var (
	versionDLL                 = syscall.NewLazyDLL("version.dll")
	procGetFileVersionInfoSize = versionDLL.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfo     = versionDLL.NewProc("GetFileVersionInfoW")
	procVerQueryValue          = versionDLL.NewProc("VerQueryValueW")

	// Language-neutral translation block: 040904B0 == English (US) +
	// Unicode codepage. Tried last after the binary's own preferred
	// translation if present.
	defaultTranslation = uint32(0x040904B0)

	errVersionResourceMissing = errors.New("path C1 windows: PE has no VersionInfo resource")
)

func probeFileVersionPlatform(_ context.Context, rule DetectionRule) (PreDetectResult, error) {
	version, err := readPeVersion(rule.Path, rule.FileVersionField)
	if err != nil {
		if errors.Is(err, errVersionResourceMissing) {
			// Not a denial of the agent; operator authoring error +
			// missing PE version resource. Fail-loud so the catalog
			// stops shipping rules against binaries without a
			// readable version stamp.
			return PreDetectResult{DetectionMethod: DetectionMethodFileVersion}, err
		}
		// Genuine IO error.
		return PreDetectResult{DetectionMethod: DetectionMethodFileVersion}, err
	}
	if version == "" {
		// Empty FileVersion (rare): treat as no version, predicate
		// drives Satisfied.
		return PreDetectResult{
			Satisfied:        false,
			MatchedVersion: "",
			DetectionMethod:  DetectionMethodFileVersion,
		}, nil
	}

	predicate := VersionPredicate{}
	if rule.VersionPredicate != nil {
		predicate = *rule.VersionPredicate
	}
	return PreDetectResult{
		Satisfied:        matchesFileVersion(version, predicate),
		MatchedVersion: version,
		DetectionMethod:  DetectionMethodFileVersion,
	}, nil
}

// readPeVersion reads the requested PE version field from `path`.
// `field` defaults to FileVersion when empty.
func readPeVersion(path, field string) (string, error) {
	utf16Path, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", fmt.Errorf("path C1 windows: utf16 path: %w", err)
	}

	var handle uint32
	size, _, _ := procGetFileVersionInfoSize.Call(
		uintptr(unsafe.Pointer(utf16Path)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if size == 0 {
		return "", errVersionResourceMissing
	}

	buf := make([]byte, size)
	ret, _, callErr := procGetFileVersionInfo.Call(
		uintptr(unsafe.Pointer(utf16Path)),
		0,
		uintptr(size),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if ret == 0 {
		if callErr != nil {
			return "", fmt.Errorf("path C1 windows: GetFileVersionInfoW: %w", callErr)
		}
		return "", errVersionResourceMissing
	}

	// Resolve translation block.
	translation, err := resolveTranslation(buf)
	if err != nil {
		// Fall back to the language-neutral 040904B0 block.
		translation = defaultTranslation
	}

	keyName := "FileVersion"
	if field == FileVersionFieldProductVersion {
		keyName = "ProductVersion"
	}

	subBlock := fmt.Sprintf(`\StringFileInfo\%08X\%s`, translation, keyName)
	subBlockUtf16, err := syscall.UTF16PtrFromString(subBlock)
	if err != nil {
		return "", fmt.Errorf("path C1 windows: utf16 subblock: %w", err)
	}

	var ptr unsafe.Pointer
	var length uint32
	ret, _, _ = procVerQueryValue.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(subBlockUtf16)),
		uintptr(unsafe.Pointer(&ptr)),
		uintptr(unsafe.Pointer(&length)),
	)
	if ret == 0 || length == 0 || ptr == nil {
		// Try a second time with the canonical language-neutral block.
		if translation != defaultTranslation {
			altBlock := fmt.Sprintf(`\StringFileInfo\%08X\%s`, defaultTranslation, keyName)
			altBlockUtf16, perr := syscall.UTF16PtrFromString(altBlock)
			if perr != nil {
				return "", errVersionResourceMissing
			}
			ret, _, _ = procVerQueryValue.Call(
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(unsafe.Pointer(altBlockUtf16)),
				uintptr(unsafe.Pointer(&ptr)),
				uintptr(unsafe.Pointer(&length)),
			)
			if ret == 0 || length == 0 || ptr == nil {
				return "", errVersionResourceMissing
			}
		} else {
			return "", errVersionResourceMissing
		}
	}

	// `length` is in UTF-16 code units including the trailing NUL.
	if length == 0 {
		return "", nil
	}
	utf16Slice := unsafe.Slice((*uint16)(ptr), length)
	// Trim trailing NULs.
	for len(utf16Slice) > 0 && utf16Slice[len(utf16Slice)-1] == 0 {
		utf16Slice = utf16Slice[:len(utf16Slice)-1]
	}
	return syscall.UTF16ToString(utf16Slice), nil
}

// resolveTranslation reads the first translation block from a PE
// VersionInfo buffer. The translation block is the conventional
// `\VarFileInfo\Translation` value which yields a 4-byte (language,
// codepage) tuple. We use the first tuple when present.
func resolveTranslation(buf []byte) (uint32, error) {
	subBlock := `\VarFileInfo\Translation`
	subBlockUtf16, err := syscall.UTF16PtrFromString(subBlock)
	if err != nil {
		return 0, err
	}
	var ptr unsafe.Pointer
	var length uint32
	ret, _, _ := procVerQueryValue.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(subBlockUtf16)),
		uintptr(unsafe.Pointer(&ptr)),
		uintptr(unsafe.Pointer(&length)),
	)
	if ret == 0 || length < 4 || ptr == nil {
		return 0, errVersionResourceMissing
	}
	// First (language, codepage) = 4 bytes little-endian.
	bytes := unsafe.Slice((*byte)(ptr), 4)
	language := uint32(bytes[0]) | uint32(bytes[1])<<8
	codepage := uint32(bytes[2]) | uint32(bytes[3])<<8
	return (language << 16) | codepage, nil
}
