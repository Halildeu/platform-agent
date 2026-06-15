//go:build windows

package dataplane

import (
	"bytes"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRealPixelCaptureInSession is the real-pixel GOLD-PROOF: from SYSTEM
// (Session 0) the session-launcher starts THIS test binary as a capture helper
// IN the interactive session (session 1) — passing the --dpcapture-out flag —
// where it grabs the real desktop and writes a PNG. We then decode it and
// confirm it is a real, non-trivial screen frame (valid dims + a payload far
// larger than a flat-colour image would compress to). This ties slice-3a-i
// (launcher) + slice-2 (GDI capture + codec) into the end-to-end interactive
// capture the agent's SYSTEM service cannot do directly.
//
// Gated (DATAPLANE_REAL_CAPTURE_SESSION=1) + must run as SYSTEM on a Windows
// desktop session (the Win11 VM via `prlctl exec`).
func TestRealPixelCaptureInSession(t *testing.T) {
	if os.Getenv("DATAPLANE_REAL_CAPTURE_SESSION") != "1" {
		t.Skip("set DATAPLANE_REAL_CAPTURE_SESSION=1 as SYSTEM on a Windows desktop session")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	// machine-wide path readable from both Session 0 (this test) and session 1
	// (the helper).
	progData := os.Getenv("ProgramData")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	outPath := filepath.Join(progData, "dpcap_realpixel.png")
	_ = os.Remove(outPath)
	defer func() { _ = os.Remove(outPath) }()

	h, err := LaunchInActiveSession(self, captureOutFlag+outPath)
	if err != nil {
		t.Fatalf("launch capture helper in interactive session: %v", err)
	}
	defer func() { _ = h.Terminate() }()

	// poll for the helper to write the PNG (it captures one frame then exits)
	var data []byte
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if b, rerr := os.ReadFile(outPath); rerr == nil && len(b) > 0 {
			data = b
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if len(data) == 0 {
		t.Fatal("capture helper did not produce a frame in the interactive session")
	}

	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("captured frame is not valid PNG: %v", err)
	}
	b := img.Bounds()
	if b.Dx() <= 0 || b.Dy() <= 0 {
		t.Fatalf("captured frame bad dims %dx%d", b.Dx(), b.Dy())
	}
	// A real screen compresses to many KB; a flat/blank frame would be tiny.
	if len(data) < 2048 {
		t.Fatalf("captured PNG only %d bytes — likely a blank/flat frame, not a real desktop", len(data))
	}
	// Content-quality check (Codex review): a real desktop has colour variance;
	// a uniform/flat frame does not. Sample a grid and require >1 distinct colour.
	fr, fg, fb, _ := img.At(b.Min.X, b.Min.Y).RGBA()
	stepX, stepY := b.Dx()/16+1, b.Dy()/16+1
	distinct := false
	for y := b.Min.Y; y < b.Max.Y && !distinct; y += stepY {
		for x := b.Min.X; x < b.Max.X; x += stepX {
			if r, g, bl, _ := img.At(x, y).RGBA(); r != fr || g != fg || bl != fb {
				distinct = true
				break
			}
		}
	}
	if !distinct {
		t.Fatal("captured frame is a uniform colour — not a real desktop (blank-frame false-positive guard)")
	}
	t.Logf("REAL-PIXEL GOLD-PROOF OK: session-1 GDI capture via launcher → %dx%d PNG, %d bytes, colour-variance confirmed", b.Dx(), b.Dy(), len(data))
}
