//go:build !windows

package ptyexec

// MaybeRunActiveSessionConPTYHelper is a Windows-only helper entrypoint.
func MaybeRunActiveSessionConPTYHelper(_ []string) (bool, int) { return false, 0 }
