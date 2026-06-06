//go:build windows

package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// version_windows.go — AG-029 PR1b Windows PE VersionInfo reader. Mirrors the
// AG-027 file-version detector pattern and avoids PowerShell in SYSTEM context.

var (
	selfUpdateVersionDLL                 = syscall.NewLazyDLL("version.dll")
	selfUpdateProcGetFileVersionInfoSize = selfUpdateVersionDLL.NewProc("GetFileVersionInfoSizeW")
	selfUpdateProcGetFileVersionInfo     = selfUpdateVersionDLL.NewProc("GetFileVersionInfoW")
	selfUpdateProcVerQueryValue          = selfUpdateVersionDLL.NewProc("VerQueryValueW")

	selfUpdateDefaultTranslation = uint32(0x040904B0)
	errSelfUpdateVersionMissing  = errors.New("self-update: PE has no VersionInfo resource")
)

// WindowsPEVersionReader reads ProductVersion first, then FileVersion when the
// product stamp is absent. ProductVersion is the preferred app-version bind;
// FileVersion is kept as a compatibility fallback for publisher tooling.
type WindowsPEVersionReader struct{}

// ReadVersion implements PEVersionReader.
func (WindowsPEVersionReader) ReadVersion(ctx context.Context, path string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	version, err := readWindowsPEVersion(path, "ProductVersion")
	if err == nil && version != "" {
		return version, nil
	}
	return readWindowsPEVersion(path, "FileVersion")
}

func readWindowsPEVersion(path, field string) (string, error) {
	utf16Path, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", fmt.Errorf("self-update: utf16 path: %w", err)
	}

	var handle uint32
	size, _, _ := selfUpdateProcGetFileVersionInfoSize.Call(
		uintptr(unsafe.Pointer(utf16Path)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if size == 0 {
		return "", errSelfUpdateVersionMissing
	}

	buf := make([]byte, size)
	ret, _, callErr := selfUpdateProcGetFileVersionInfo.Call(
		uintptr(unsafe.Pointer(utf16Path)),
		0,
		uintptr(size),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if ret == 0 {
		if callErr != nil {
			return "", fmt.Errorf("self-update: GetFileVersionInfoW: %w", callErr)
		}
		return "", errSelfUpdateVersionMissing
	}

	translation, err := selfUpdateResolveTranslation(buf)
	if err != nil {
		translation = selfUpdateDefaultTranslation
	}
	if field == "" {
		field = "FileVersion"
	}
	version, err := selfUpdateQueryVersionString(buf, translation, field)
	if err == nil {
		return version, nil
	}
	if translation != selfUpdateDefaultTranslation {
		return selfUpdateQueryVersionString(buf, selfUpdateDefaultTranslation, field)
	}
	return "", err
}

func selfUpdateQueryVersionString(buf []byte, translation uint32, field string) (string, error) {
	subBlock := fmt.Sprintf(`\StringFileInfo\%08X\%s`, translation, field)
	subBlockUtf16, err := syscall.UTF16PtrFromString(subBlock)
	if err != nil {
		return "", fmt.Errorf("self-update: utf16 subblock: %w", err)
	}
	var ptr unsafe.Pointer
	var length uint32
	ret, _, _ := selfUpdateProcVerQueryValue.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(subBlockUtf16)),
		uintptr(unsafe.Pointer(&ptr)),
		uintptr(unsafe.Pointer(&length)),
	)
	if ret == 0 || length == 0 || ptr == nil {
		return "", errSelfUpdateVersionMissing
	}
	utf16Slice := unsafe.Slice((*uint16)(ptr), length)
	for len(utf16Slice) > 0 && utf16Slice[len(utf16Slice)-1] == 0 {
		utf16Slice = utf16Slice[:len(utf16Slice)-1]
	}
	return syscall.UTF16ToString(utf16Slice), nil
}

func selfUpdateResolveTranslation(buf []byte) (uint32, error) {
	subBlockUtf16, err := syscall.UTF16PtrFromString(`\VarFileInfo\Translation`)
	if err != nil {
		return 0, err
	}
	var ptr unsafe.Pointer
	var length uint32
	ret, _, _ := selfUpdateProcVerQueryValue.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(subBlockUtf16)),
		uintptr(unsafe.Pointer(&ptr)),
		uintptr(unsafe.Pointer(&length)),
	)
	if ret == 0 || length < 4 || ptr == nil {
		return 0, errSelfUpdateVersionMissing
	}
	bytes := unsafe.Slice((*byte)(ptr), 4)
	language := uint32(bytes[0]) | uint32(bytes[1])<<8
	codepage := uint32(bytes[2]) | uint32(bytes[3])<<8
	return (language << 16) | codepage, nil
}
