//go:build windows

package dataplane

import (
	"bytes"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// (procFindWindowW + bannerSelfVerify were lifted to production as
// dataplane.BannerSelfVerify in banner_windows.go — the VIEW_ONLY capture helper
// needs the real fail-closed self-verify, not a test-only one.)

// TestRealBannerInSession is the BANNER gold-proof: from SYSTEM (Session 0) it
// launches THIS binary as a banner helper IN the interactive session (the only
// place a window is visible to the user), which shows the endpoint banner,
// self-verifies it (FindWindow + IsWindowVisible) from within that session, and
// writes the result to a machine-wide file the SYSTEM test then reads. Ties
// together launcher (3a-i) + the banner (slice-7).
//
// Gated (DATAPLANE_REAL_BANNER=1) + must run as SYSTEM on a Windows desktop
// session (the Win11 VM via `prlctl exec`).
func TestRealBannerInSession(t *testing.T) {
	if os.Getenv("DATAPLANE_REAL_BANNER") != "1" {
		t.Skip("set DATAPLANE_REAL_BANNER=1 as SYSTEM on a Windows desktop session")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	result := filepath.Join(pd, "dpbanner_result.txt")
	_ = os.Remove(result)

	h, err := LaunchInActiveSession(self, bannerOutFlag+result)
	if err != nil {
		t.Fatalf("launch banner helper in interactive session: %v", err)
	}
	defer func() { _ = h.Terminate() }()

	// Poll for the helper's result (it shows the banner ~3.7s then writes).
	deadline := time.Now().Add(20 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		if b, rerr := os.ReadFile(result); rerr == nil && len(b) > 0 {
			data = b
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	_ = os.Remove(result)
	if len(data) == 0 {
		t.Fatal("banner helper wrote no result (window never shown/verified in session 1)")
	}
	if got := strings.TrimSpace(string(data)); got != "OK" {
		t.Fatalf("banner self-verify failed: %q", got)
	}

	// Pixel proof: the helper captured the real desktop (banner up) → confirm the
	// red bar is actually RENDERED at top-center. Sample the banner's LEFT region
	// (the white text is centered, so the left part is solid red background).
	pngPath := result + ".png"
	defer os.Remove(pngPath)
	raw, perr := os.ReadFile(pngPath)
	if perr != nil || len(raw) == 0 {
		t.Fatalf("no desktop screenshot written (banner pixel proof): %v", perr)
	}
	img, derr := png.Decode(bytes.NewReader(raw))
	if derr != nil {
		t.Fatalf("desktop screenshot not valid PNG: %v", derr)
	}
	b := img.Bounds()
	w := b.Dx()
	bannerLeft := b.Min.X + w/10 // bannerBounds: 4/5 width, centered → w/10 margin
	red, total := 0, 0
	y := b.Min.Y + 10 // within the >=48px band for any DPI
	for x := bannerLeft + 5; x < bannerLeft+w/4; x += 8 {
		r, g, bl, _ := img.At(x, y).RGBA()
		r8, g8, b8 := uint8(r>>8), uint8(g>>8), uint8(bl>>8)
		total++
		if r8 >= 150 && r8 <= 230 && g8 < 60 && b8 < 60 { // banner red ~ (200,0,0)
			red++
		}
	}
	if total == 0 || red*100/total < 60 {
		t.Fatalf("banner not rendered red at top-center: %d/%d red samples", red, total)
	}
	t.Logf("BANNER GOLD-PROOF OK: endpoint banner shown + verified (FindWindow+IsWindowVisible) AND captured rendered red on the real session-1 desktop (%d/%d top-center samples red), launched from SYSTEM/Session-0", red, total)
}
