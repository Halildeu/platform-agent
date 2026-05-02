package files

import (
	"errors"
	"path"
	"strings"
)

var (
	ErrEmptyPath      = errors.New("empty path")
	ErrUnsafePath     = errors.New("unsafe path")
	ErrPathOutOfScope = errors.New("path out of allowed scope")
)

func NormalizeRelativePath(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", ErrEmptyPath
	}

	normalized := strings.ReplaceAll(trimmed, "\\", "/")
	if strings.HasPrefix(normalized, "/") || strings.Contains(normalized, ":") {
		return "", ErrUnsafePath
	}

	cleaned := path.Clean(normalized)
	if cleaned == "." {
		return ".", nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", ErrUnsafePath
	}

	for _, segment := range strings.Split(cleaned, "/") {
		if segment == ".." || strings.TrimSpace(segment) == "" {
			return "", ErrUnsafePath
		}
	}

	return cleaned, nil
}

func IsWithinAllowedRoot(root string, resolvedPath string, caseInsensitive bool) bool {
	canonicalRoot := canonicalPath(root)
	canonicalResolved := canonicalPath(resolvedPath)
	if caseInsensitive {
		canonicalRoot = strings.ToLower(canonicalRoot)
		canonicalResolved = strings.ToLower(canonicalResolved)
	}

	return canonicalResolved == canonicalRoot || strings.HasPrefix(canonicalResolved, canonicalRoot+"/")
}

func ValidateResolvedPath(root string, resolvedPath string, caseInsensitive bool) error {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(resolvedPath) == "" {
		return ErrEmptyPath
	}
	if !IsWithinAllowedRoot(root, resolvedPath, caseInsensitive) {
		return ErrPathOutOfScope
	}
	return nil
}

func canonicalPath(input string) string {
	normalized := strings.ReplaceAll(strings.TrimSpace(input), "\\", "/")
	for strings.Contains(normalized, "//") {
		normalized = strings.ReplaceAll(normalized, "//", "/")
	}
	if len(normalized) > 1 {
		normalized = strings.TrimRight(normalized, "/")
	}
	return normalized
}
