package dataprotection

import (
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stripComments blanks comment bytes (preserving newlines + byte length) so
// the forbidden-token scans inspect CODE only. Without this an accurate
// comment ("opens with FILE_READ_ATTRIBUTES, never GENERIC_READ") would
// false-positive the guard.
func stripComments(src []byte) string {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, nil, scanner.ScanComments)
	out := make([]byte, len(src))
	copy(out, src)
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.COMMENT {
			start := file.Offset(pos)
			for i := start; i < start+len(lit) && i < len(out); i++ {
				if out[i] != '\n' {
					out[i] = ' '
				}
			}
		}
	}
	return string(out)
}

// TestNoContentReadImports is the machine-enforced metadata-only guard
// (contract invariant #1; Codex 019ec28a P0). It scans every non-test source
// file in this package and fails if any of them imports a content-reading
// package or calls a content-reading function. SHA256 / content hash / raw
// file reads would turn the "dry-run" into actual data access — this test
// makes that a compile-of-the-suite failure, not a code-review hope.
func TestNoContentReadImports(t *testing.T) {
	forbiddenImports := map[string]bool{
		"io":        true, // io.ReadAll / io.Copy can stream content (io/fs is fine)
		"bufio":     true,
		"io/ioutil": true,
		"mmap":      true,
	}
	forbiddenImportPrefixes := []string{"crypto", "hash"}
	// Denylist of content-read / hash entry points. Codex 019ec2bb P1/P2: the
	// guard must catch future content-read regressions, not just the obvious
	// os.ReadFile. We forbid the named read APIs across the os / io / ioutil /
	// syscall / x-sys / mmap surfaces AND the generic ".Read(" method call and
	// "ReadFile(" — a metadata-only package legitimately needs neither (it uses
	// os.ReadDir + os.Lstat + CreateFile(FILE_READ_ATTRIBUTES) only).
	forbiddenCallSubstrings := []string{
		"os.Open(", "os.OpenFile(", "os.ReadFile(", "os.NewFile(",
		"io.ReadAll(", "io.Copy(", "ioutil.ReadFile(", "ioutil.ReadAll(",
		"bufio.NewReader(", "bufio.NewScanner(",
		".Read(", "ReadFile(", "ReadAll(",
		"syscall.Read", "unix.Read", "unix.Pread", "windows.ReadFile",
		"MapViewOfFile", "Mmap(", "Mmap (",
		"sha256.", "sha1.", "md5.", "sha512.", "blake", ".Sum(", "crc32.", "fnv.",
	}

	files := packageGoFiles(t, false)
	if len(files) == 0 {
		t.Fatal("no source files found to scan")
	}
	fset := token.NewFileSet()
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		text := stripComments(src)
		af, err := parser.ParseFile(fset, f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range af.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if forbiddenImports[p] {
				t.Errorf("%s imports forbidden content-read package %q", filepath.Base(f), p)
			}
			for _, pre := range forbiddenImportPrefixes {
				if p == pre || strings.HasPrefix(p, pre+"/") {
					t.Errorf("%s imports forbidden package %q (prefix %q)", filepath.Base(f), p, pre)
				}
			}
		}
		for _, bad := range forbiddenCallSubstrings {
			if strings.Contains(text, bad) {
				t.Errorf("%s contains forbidden content-read call %q", filepath.Base(f), bad)
			}
		}
	}
}

// TestWindowsHandleIsMetadataOnly asserts the Windows canonicalizer opens its
// handle with FILE_READ_ATTRIBUTES and never requests read access. This runs
// on any host (the file is scanned as text, not compiled).
func TestWindowsHandleIsMetadataOnly(t *testing.T) {
	path := "backupmanifest_windows.go"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := stripComments(src)
	if !strings.Contains(text, "FILE_READ_ATTRIBUTES") {
		t.Error("windows canonicalizer must open with FILE_READ_ATTRIBUTES (metadata only)")
	}
	for _, forbidden := range []string{"GENERIC_READ", "FILE_GENERIC_READ", "GENERIC_ALL", "GENERIC_WRITE"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("windows canonicalizer must NOT request %s (content/write access)", forbidden)
		}
	}
	// We must resolve reparse targets (escape detection), so the reparse-open
	// flag must be ABSENT.
	if strings.Contains(text, "FILE_FLAG_OPEN_REPARSE_POINT") {
		t.Error("windows canonicalizer must NOT set FILE_FLAG_OPEN_REPARSE_POINT (target must resolve for escape detection)")
	}
}

func packageGoFiles(t *testing.T, includeTests bool) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if !includeTests && strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, name)
	}
	return out
}
