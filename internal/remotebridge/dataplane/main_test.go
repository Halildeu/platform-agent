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
//	--dpbanner-out=<path>       show the endpoint banner, self-verify, write result
const (
	captureOutFlag = "--dpcapture-out="
	pipeClientFlag = "--dppipe-client="
	pipeNonceFlag  = "--dppipe-nonce="
	bannerOutFlag  = "--dpbanner-out="
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
		case strings.HasPrefix(a, bannerOutFlag):
			os.Exit(runBannerHelper(strings.TrimPrefix(a, bannerOutFlag)))
		}
	}
	if pipeName != "" {
		os.Exit(runStreamHelper(pipeName, pipeNonce))
	}
	os.Exit(m.Run())
}

// runBannerHelper shows the endpoint-awareness banner, self-verifies the window
// is present + visible IN this (interactive) session, holds it briefly (so a
// visual screenshot can capture it), then tears it down and writes "OK" or
// "FAIL: <reason>" to outPath. Returns a process exit code. Runs in session 1
// (the launcher placed it there). On a non-windows/headless context ShowActiveBanner
// + bannerSelfVerify report unsupported → "FAIL", fail-closed.
func runBannerHelper(outPath string) int {
	if outPath == "" {
		return 3
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- ShowActiveBanner(ctx) }()
	time.Sleep(700 * time.Millisecond) // let the window create + show
	verifyErr := bannerSelfVerify()
	// Pixel proof: with the (topmost) banner up, capture the real desktop via the
	// proven GDI path and write the PNG next to outPath — the gold-proof then
	// confirms the red banner is actually RENDERED at top-center (no dependency on
	// host-side window visibility). The banner is WS_EX_TOPMOST so it composites
	// above other windows in the screenshot.
	if verifyErr == nil {
		p := NewWindowsFrameProducer(NewPNGEncoder(), 50*time.Millisecond, 3)
		if f, ok := p.Next(); ok {
			_ = os.WriteFile(outPath+".png", f.Payload, 0o600)
		}
		_ = p.Close()
	}
	time.Sleep(2 * time.Second) // brief extra hold
	cancel()
	<-errCh // wait for the pump to exit cleanly
	if verifyErr != nil {
		_ = os.WriteFile(outPath, []byte("FAIL: "+verifyErr.Error()), 0o600)
		return 2
	}
	_ = os.WriteFile(outPath, []byte("OK"), 0o600)
	return 0
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
