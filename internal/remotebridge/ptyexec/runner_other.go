//go:build !windows

package ptyexec

import "context"

func defaultConPTYRunner(ctx context.Context, exePath, commandLine string, cols, rows int16) ([]byte, uint32, error) {
	return RunConPTY(ctx, exePath, commandLine, cols, rows)
}
