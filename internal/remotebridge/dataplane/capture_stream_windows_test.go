//go:build windows

package dataplane

import (
	"bytes"
	"encoding/hex"
	"errors"
	"image/png"
	"io"
	"os"
	"testing"
	"time"
)

// TestRealStreamCaptureInSession is the STREAMING gold-proof: it ties together
// launcher (3a-i) + secured pipe (3a-ii-B-1) + frame-IPC (3a-ii-A) + GDI capture
// (slice-2). From SYSTEM (Session 0) the test creates a DACL-restricted pipe,
// launches THIS binary as a stream helper IN the interactive session (passing
// the pipe name + nonce as ARGS), then the helper dials the pipe, handshakes with
// the nonce, and streams real-desktop frames which the SYSTEM test reads + decodes.
//
// Gated (DATAPLANE_REAL_STREAM=1) + must run as SYSTEM on a Windows desktop
// session (the Win11 VM via `prlctl exec`).
func TestRealStreamCaptureInSession(t *testing.T) {
	if os.Getenv("DATAPLANE_REAL_STREAM") != "1" {
		t.Skip("set DATAPLANE_REAL_STREAM=1 as SYSTEM on a Windows desktop session")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	sid, err := ActiveSessionUserSID()
	if err != nil {
		t.Fatalf("ActiveSessionUserSID: %v", err)
	}
	name, err := RandomPipeName()
	if err != nil {
		t.Fatalf("RandomPipeName: %v", err)
	}
	l, err := ListenSecurePipe(name, sid)
	if err != nil {
		t.Fatalf("ListenSecurePipe: %v", err)
	}
	defer l.Close()
	nonce, _ := NewLaunchNonce()

	h, err := LaunchInActiveSession(self, pipeClientFlag+name, pipeNonceFlag+hex.EncodeToString(nonce))
	if err != nil {
		t.Fatalf("launch stream helper in interactive session: %v", err)
	}
	defer func() { _ = h.Terminate() }()

	conn, err := AcceptAndVerify(l, nonce, 15*time.Second)
	if err != nil {
		t.Fatalf("accept + nonce-verify: %v", err)
	}
	defer conn.Close()

	frames := 0
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	for {
		payload, rerr := ReadFrame(conn)
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			t.Fatalf("read frame %d: %v", frames, rerr)
		}
		img, derr := png.Decode(bytes.NewReader(payload))
		if derr != nil {
			t.Fatalf("frame %d not valid PNG: %v", frames, derr)
		}
		b := img.Bounds()
		if b.Dx() <= 0 || b.Dy() <= 0 || len(payload) < 2048 {
			t.Fatalf("frame %d not a real desktop (%dx%d, %d bytes)", frames, b.Dx(), b.Dy(), len(payload))
		}
		frames++
	}
	if frames == 0 {
		t.Fatal("no frames streamed over the secured pipe")
	}
	t.Logf("STREAMING GOLD-PROOF OK: %d real-desktop frame(s) streamed session-1 → SYSTEM over the DACL-restricted, nonce-authenticated pipe", frames)
}
