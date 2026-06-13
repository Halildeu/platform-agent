package dataprotection

import "os"

// readDirNames lists the immediate child names of a directory. This is a
// directory LISTING (metadata) — it never opens or reads file content, so it
// satisfies the metadata-only invariant. os.ReadDir is on the guard test's
// allowlist (os.Open/os.ReadFile/os.OpenFile are not).
func readDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// lstatInfo returns file metadata (size/mode/mtime) WITHOUT following the
// final symlink and WITHOUT opening the file for reading. os.Lstat is a
// metadata syscall (stat family) — no content access.
func lstatInfo(path string) (fileInfo, error) {
	return os.Lstat(path)
}
