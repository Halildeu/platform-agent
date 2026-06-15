package dataplane

import (
	"os"
	"strings"
	"testing"
	"time"
)

// captureOutFlag, when present in os.Args as "--dpcapture-out=<path>", switches
// the test binary into capture-HELPER mode: it grabs ONE VIEW_ONLY frame and
// writes the encoded PNG to <path>, then exits — it does NOT run the test suite.
// The real-pixel gold-proof launches THIS binary (via the session-launcher) in
// the interactive session with that flag, so the capture runs where GDI can read
// the real desktop. The signal is a command-line ARG, not an env var, because
// CreateProcessAsUser hands the helper the USER's environment block (not ours).
const captureOutFlag = "--dpcapture-out="

func TestMain(m *testing.M) {
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, captureOutFlag) {
			os.Exit(runCaptureHelper(strings.TrimPrefix(a, captureOutFlag)))
		}
	}
	os.Exit(m.Run())
}

// runCaptureHelper captures one frame and writes its encoded bytes to outPath.
// Returns a process exit code (0 = ok). It runs in whatever session the launcher
// placed it (session 1 for the gold-proof; on a non-interactive/non-windows
// context the producer yields no frame → non-zero, fail-closed).
func runCaptureHelper(outPath string) int {
	if outPath == "" {
		return 3
	}
	p := NewWindowsFrameProducer(NewPNGEncoder(), 50*time.Millisecond, 3)
	defer func() { _ = p.Close() }()
	f, ok := p.Next()
	if !ok {
		return 2 // capture failed (non-interactive session / unsupported platform)
	}
	if err := os.WriteFile(outPath, f.Payload, 0o600); err != nil {
		return 4
	}
	return 0
}
