package dataplane

import (
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

// Helper-mode flags switch the test binary out of the suite into a capture
// helper, so the real-pixel / streaming gold-proofs can launch THIS binary (via
// the session-launcher) in the interactive session where GDI can read the real
// desktop. Signals are command-line ARGS, not env vars, because
// CreateProcessAsUser hands the helper the USER's environment block (not ours).
//
//	--dpcapture-out=<path>      one-shot: capture ONE frame → write PNG to <path>
//	--dppipe-client=<pipename>  stream: dial the pipe, handshake, stream frames
//	--dppipe-nonce=<hex>        the launch nonce for the stream handshake
const (
	captureOutFlag = "--dpcapture-out="
	pipeClientFlag = "--dppipe-client="
	pipeNonceFlag  = "--dppipe-nonce="
)

// streamProofBandHeight is the active-indicator band height (px) the stream
// helper applies to EVERY streamed frame, so the streaming gold-proof can
// confirm the exfil control (slice-5a/5b) survives the real e2e stream. The band
// is red (BGRA 0,0,0xFF,0xFF). Kept small relative to the desktop so most of the
// frame stays genuine captured content (verified by the below-band variance
// check). The one-shot real-pixel proof keeps capturing RAW (no indicator).
const streamProofBandHeight = 24

func TestMain(m *testing.M) {
	var pipeName, pipeNonce string
	for _, a := range os.Args[1:] {
		switch {
		case strings.HasPrefix(a, captureOutFlag):
			os.Exit(runCaptureHelper(strings.TrimPrefix(a, captureOutFlag)))
		case strings.HasPrefix(a, pipeClientFlag):
			pipeName = strings.TrimPrefix(a, pipeClientFlag)
		case strings.HasPrefix(a, pipeNonceFlag):
			pipeNonce = strings.TrimPrefix(a, pipeNonceFlag)
		}
	}
	if pipeName != "" {
		os.Exit(runStreamHelper(pipeName, pipeNonce))
	}
	os.Exit(m.Run())
}

// runStreamHelper dials the secured pipe, sends the launch-nonce handshake, then
// streams a few captured VIEW_ONLY frames and a graceful EOF. Returns a process
// exit code (0 = ok). Runs in the interactive session (the launcher placed it).
func runStreamHelper(pipeName, nonceHex string) int {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != ipcNonceLen {
		return 5
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := DialAndHandshake(ctx, pipeName, nonce)
	if err != nil {
		return 6
	}
	defer func() { _ = conn.Close() }()
	// Production-representative: apply the VIEW_ONLY active-indicator to every
	// streamed frame (the exfil control the gold-proof verifies survives the
	// real e2e stream). The producer applies it before encode (slice-5b wiring).
	indicator := func(fr *RawFrame) { ApplyActiveIndicator(fr, streamProofBandHeight, 0, 0, 0xFF, 0xFF) }
	p := NewWindowsFrameProducer(NewPNGEncoder(), 50*time.Millisecond, 3, indicator)
	defer func() { _ = p.Close() }()
	for i := 0; i < 2; i++ {
		f, ok := p.Next()
		if !ok {
			return 7
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := WriteFrame(conn, f.Payload); err != nil {
			return 8
		}
	}
	_ = WriteEOF(conn)
	return 0
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
