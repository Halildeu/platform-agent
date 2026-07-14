//go:build windows

package screenview

import (
	"bytes"
	"context"
	"image/png"
	"os"
	"testing"
)

// TestRealScreenViewProductionCaptureInSession is the PRODUCTION-PATH gold-proof:
// from SYSTEM (Session 0) it runs the real NewWindowsProducerFactory, which
// launches THIS binary as the active-session VIEW_ONLY helper over the
// DACL-restricted nonce-verified pipe. The factory only returns a producer once
// the helper has shown + self-verified the banner and produced a first frame
// (READY), so a successful factory call already proves banner + capture liveness.
// We then read frames and assert they are real primary-monitor PNGs carrying the
// mandatory active-indicator red band, and that Close terminates the helper.
//
// Gated (SCREENVIEW_REAL=1) + must run as SYSTEM on a Windows desktop session with
// an interactive user logged in (the Win11 VM via `prlctl exec`).
func TestRealScreenViewProductionCaptureInSession(t *testing.T) {
	if os.Getenv("SCREENVIEW_REAL") != "1" {
		t.Skip("set SCREENVIEW_REAL=1 as SYSTEM on a Windows desktop session")
	}

	maskPolicy, err := ParseMaskPolicy(os.Getenv("SCREENVIEW_MASK_RECT_BPS"))
	if err != nil {
		t.Fatalf("SCREENVIEW_MASK_RECT_BPS: %v", err)
	}
	factory := NewWindowsProducerFactory(maskPolicy)
	// A successful factory call proves: helper launched in the active session, banner
	// shown + BannerSelfVerify passed, and the first frame arrived (fail-closed READY).
	producer, err := factory(context.Background(), "gold-proof-session", "gold-proof-stream")
	if err != nil {
		t.Fatalf("production factory failed (no live bannered capture): %v", err)
	}
	defer producer.Close()

	const want = 3
	got := 0
	for got < want {
		f, ok := producer.Next()
		if !ok {
			t.Fatalf("producer exhausted after %d/%d frames", got, want)
		}
		img, derr := png.Decode(bytes.NewReader(f.Payload))
		if derr != nil {
			t.Fatalf("frame %d is not valid PNG: %v", got, derr)
		}
		b := img.Bounds()
		if b.Dx() <= 0 || b.Dy() <= 0 || len(f.Payload) < 2048 {
			t.Fatalf("frame %d not a real desktop capture (%dx%d, %d bytes)", got, b.Dx(), b.Dy(), len(f.Payload))
		}
		// MANDATORY active-indicator: the top indicatorBand rows are painted red
		// (ApplyActiveIndicator b=0,g=0,r=0xFF). Sample the top-LEFT region (the banner
		// is top-CENTER, so the left edge isolates the full-width indicator band).
		red, total := 0, 0
		y := b.Min.Y + 5 // within the indicatorBand (28px) for any DPI
		for x := b.Min.X + 4; x < b.Min.X+b.Dx()/8; x += 6 {
			r, g, bl, _ := img.At(x, y).RGBA()
			r8, g8, b8 := uint8(r>>8), uint8(g>>8), uint8(bl>>8)
			total++
			if r8 >= 180 && g8 < 70 && b8 < 70 {
				red++
			}
		}
		if total == 0 || red*100/total < 70 {
			t.Fatalf("frame %d missing the mandatory active-indicator red band: %d/%d red samples", got, red, total)
		}
		if maskPolicy.Enabled() {
			x0 := b.Min.X + b.Dx()*maskPolicy.X/maskBasisPoints
			y0 := b.Min.Y + b.Dy()*maskPolicy.Y/maskBasisPoints
			x1 := b.Min.X + (b.Dx()*(maskPolicy.X+maskPolicy.Width)+maskBasisPoints-1)/maskBasisPoints
			y1 := b.Min.Y + (b.Dy()*(maskPolicy.Y+maskPolicy.Height)+maskBasisPoints-1)/maskBasisPoints
			black, samples := 0, 0
			for y := y0; y < y1; y += max(1, (y1-y0)/12) {
				for x := x0; x < x1; x += max(1, (x1-x0)/12) {
					r, g, bl, a := img.At(x, y).RGBA()
					samples++
					if uint8(r>>8) == 0 && uint8(g>>8) == 0 && uint8(bl>>8) == 0 && uint8(a>>8) == 0xFF {
						black++
					}
				}
			}
			if samples == 0 || black != samples {
				t.Fatalf("frame %d DLP mask is not opaque black across policy region: %d/%d", got, black, samples)
			}
		}
		got++
	}

	// Close terminates the helper (the orphan-safety + Close->Terminate path is code-
	// reviewed + the dataplane LaunchedHelper.Terminate primitive is separately tested);
	// here we assert Close is clean on the live producer.
	if cerr := producer.Close(); cerr != nil {
		t.Fatalf("producer Close: %v", cerr)
	}
	t.Logf("SCREENVIEW PRODUCTION GOLD-PROOF OK: factory launched the active-session helper, banner self-verified, %d real primary-monitor frames each carrying the active-indicator band, clean Close (SYSTEM/Session-0 -> session-1)", got)
}
