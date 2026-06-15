package dataplane

import "testing"

func TestScaleForDPI(t *testing.T) {
	cases := []struct {
		base, dpi, want int
	}{
		{48, 96, 48},   // 100%
		{48, 192, 96},  // 200%
		{48, 144, 72},  // 150%
		{48, 120, 60},  // 125%
		{48, 0, 48},    // failed DPI query → 100% fallback (never 0)
		{48, -1, 48},   // negative → fallback
		{100, 96, 100}, // identity at base DPI
	}
	for _, c := range cases {
		if got := scaleForDPI(c.base, c.dpi); got != c.want {
			t.Errorf("scaleForDPI(%d,%d)=%d want %d", c.base, c.dpi, got, c.want)
		}
	}
}

func TestBannerBoundsTopCentered(t *testing.T) {
	// Normal 1920x1080, 48px bar: 4/5 width, centered, pinned to top.
	x, y, w := bannerBounds(1920, 1080, 48)
	if w != 1920*4/5 {
		t.Fatalf("width=%d want %d", w, 1920*4/5)
	}
	if y != 0 {
		t.Fatalf("y=%d want 0 (top-pinned)", y)
	}
	if x != (1920-w)/2 {
		t.Fatalf("x=%d not centered (want %d)", x, (1920-w)/2)
	}
	if x < 0 || x+w > 1920 {
		t.Fatalf("bar off-screen: x=%d w=%d screen=1920", x, w)
	}
}

func TestBannerBoundsClamps(t *testing.T) {
	// Degenerate screen → minimum visible bar at origin, never zero/negative.
	x, y, w := bannerBounds(0, 0, 48)
	if x != 0 || y != 0 || w != bannerMinWidth {
		t.Fatalf("degenerate: got (%d,%d,%d) want (0,0,%d)", x, y, w, bannerMinWidth)
	}
	// Tiny screen narrower than the minimum → clamp width to screen, x>=0.
	x, _, w = bannerBounds(200, 200, 48)
	if w > 200 {
		t.Fatalf("width %d exceeds tiny screen 200", w)
	}
	if x < 0 {
		t.Fatalf("x=%d negative on tiny screen", x)
	}
}

func TestRGBPacking(t *testing.T) {
	// COLORREF is 0x00BBGGRR.
	if got := rgb(255, 0, 0); got != 0x0000FF {
		t.Errorf("rgb red = %#06x want 0x0000FF", got)
	}
	if got := rgb(0, 0, 255); got != 0xFF0000 {
		t.Errorf("rgb blue = %#06x want 0xFF0000", got)
	}
	if got := rgb(255, 255, 255); got != 0xFFFFFF {
		t.Errorf("rgb white = %#06x want 0xFFFFFF", got)
	}
}
