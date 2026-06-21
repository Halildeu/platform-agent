//go:build windows

package ptyexec

import "context"

func defaultConPTYRunner(ctx context.Context, exePath, commandLine string, cols, rows int16) ([]byte, uint32, error) {
	out, code, err := RunConPTYInActiveSession(ctx, exePath, commandLine, cols, rows)
	if !shouldUseDirectCaptureFallback(ctx, out, err) {
		return out, code, err
	}

	// The active-session helper can complete but return no relayed stdout on some Windows hosts. Keep the
	// same broker permit + allowlist + command-hash gate, then fall back to the service-mode direct capture
	// path already used by RunConPTY. This preserves the no-shell bounded executor contract.
	return RunConPTY(ctx, exePath, commandLine, cols, rows)
}
