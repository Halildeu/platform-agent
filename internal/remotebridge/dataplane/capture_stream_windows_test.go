//go:build windows

package dataplane

import (
	"bytes"
	"encoding/hex"
	"errors"
	"image"
	"image/png"
	"io"
	"os"
	"testing"
	"time"
)

// TestRealStreamCaptureInSession is the STREAMING+EXFIL gold-proof: it ties
// together launcher (3a-i) + secured pipe (3a-ii-B-1) + frame-IPC (3a-ii-A) + GDI
// capture (slice-2) + exfil pipeline-wiring (slice-5b). From SYSTEM (Session 0)
// the test creates a DACL-restricted pipe, launches THIS binary as a stream
// helper IN the interactive session (passing the pipe name + nonce as ARGS); the
// helper dials the pipe, handshakes with the nonce, applies the VIEW_ONLY
// active-indicator to each captured frame, and streams real-desktop frames which
// the SYSTEM test reads + decodes — then asserts the indicator band SURVIVED the
// real e2e stream (the exfil control egressed, not just a unit buffer).
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
		// Exfil proof: the active-indicator band the helper applied must SURVIVE
		// the real e2e stream — every frame's top band is red, and the rest is a
		// genuine desktop (not a uniform fill). This is the real-stream twin of
		// the OS-agnostic unit proof, answering "did the control egress?".
		assertActiveIndicatorSurvivedStream(t, img, frames)
		frames++
	}
	if frames == 0 {
		t.Fatal("no frames streamed over the secured pipe")
	}
	t.Logf("STREAMING+EXFIL GOLD-PROOF OK: %d real-desktop frame(s) streamed session-1 → SYSTEM over the DACL-restricted, nonce-authenticated pipe, each carrying the active-indicator band (exfil control survived the e2e stream)", frames)
}

// assertActiveIndicatorSurvivedStream verifies a streamed, decoded frame carries
// the VIEW_ONLY active-indicator the helper applied: the top streamProofBandHeight
// rows are solid red, and the region below the band has genuine desktop colour
// variety (not an all-red fill). This proves the exfil control egressed through
// the real capture→encode→pipe→decode path, not just a unit buffer.
func assertActiveIndicatorSurvivedStream(t *testing.T, img image.Image, frameIdx int) {
	t.Helper()
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if h <= streamProofBandHeight+8 {
		t.Fatalf("frame %d too short (%dpx) to verify band + desktop", frameIdx, h)
	}
	xs := []int{b.Min.X + w/4, b.Min.X + w/2, b.Min.X + 3*w/4}
	// Band rows must be red (indicator applied + survived encode+stream).
	for _, y := range []int{b.Min.Y + 2, b.Min.Y + streamProofBandHeight - 2} {
		for _, x := range xs {
			r, g, bl, _ := img.At(x, y).RGBA()
			if uint8(r>>8) != 0xFF || uint8(g>>8) != 0 || uint8(bl>>8) != 0 {
				t.Fatalf("frame %d band pixel (%d,%d) not red (%02x %02x %02x) — active-indicator did NOT survive the stream",
					frameIdx, x, y, uint8(r>>8), uint8(g>>8), uint8(bl>>8))
			}
		}
	}
	// Band must be BOUNDED: the row just below it must NOT be all indicator-red
	// (catches a band that overflowed its height or filled the whole frame — a
	// real desktop strip is ~never uniformly pure 0xFF0000).
	belowY := b.Min.Y + streamProofBandHeight + 2
	nonRedBelow := false
	for _, x := range xs {
		r, g, bl, _ := img.At(x, belowY).RGBA()
		if uint8(r>>8) != 0xFF || uint8(g>>8) != 0 || uint8(bl>>8) != 0 {
			nonRedBelow = true
			break
		}
	}
	if !nonRedBelow {
		t.Fatalf("frame %d row just below the band (y=%d) is all indicator-red — band overflowed / filled the frame", frameIdx, belowY)
	}
	// Below the band: require colour variety (genuine desktop, not a red fill).
	seen := map[uint32]bool{}
	stepX := (w / 12) + 1
	stepY := (h / 12) + 1
	for y := b.Min.Y + streamProofBandHeight + 4; y < b.Max.Y; y += stepY {
		for x := b.Min.X; x < b.Max.X; x += stepX {
			r, g, bl, _ := img.At(x, y).RGBA()
			seen[uint32(uint8(r>>8))<<16|uint32(uint8(g>>8))<<8|uint32(uint8(bl>>8))] = true
		}
	}
	if len(seen) < 3 {
		t.Fatalf("frame %d below-band region has <3 distinct colours (%d) — not a genuine desktop capture (band may have overwritten the frame)", frameIdx, len(seen))
	}
}
