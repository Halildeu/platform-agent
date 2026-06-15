package dataplane

import (
	"bytes"
	"image/png"
	"testing"
)

// solidFrame builds a w×h BGRA frame filled with (b,g,r,255).
func solidFrame(w, h int, b, g, r byte) RawFrame {
	stride := w * 4
	pix := make([]byte, stride*h)
	for i := 0; i < w*h; i++ {
		pix[i*4+0], pix[i*4+1], pix[i*4+2], pix[i*4+3] = b, g, r, 0xFF
	}
	return RawFrame{Width: w, Height: h, Stride: stride, Pixels: pix}
}

func pixAt(f RawFrame, x, y int) (b, g, r, a byte) {
	i := y*f.Stride + x*4
	return f.Pixels[i], f.Pixels[i+1], f.Pixels[i+2], f.Pixels[i+3]
}

func TestApplyActiveIndicatorBandOnlyTop(t *testing.T) {
	f := solidFrame(10, 10, 0, 0, 0)              // black
	ApplyActiveIndicator(&f, 3, 0, 0, 0xFF, 0xFF) // red band, top 3 rows
	for y := 0; y < 3; y++ {
		if b, g, r, a := pixAt(f, 5, y); b != 0 || g != 0 || r != 0xFF || a != 0xFF {
			t.Fatalf("band row %d not red: %d %d %d %d", y, b, g, r, a)
		}
	}
	// below the band: unchanged (black)
	if _, _, r, _ := pixAt(f, 5, 4); r != 0 {
		t.Fatalf("row 4 should be untouched black, got r=%d", r)
	}
}

func TestApplyActiveIndicatorClampsAndNoops(t *testing.T) {
	f := solidFrame(4, 4, 0, 0, 0)
	ApplyActiveIndicator(&f, 100, 0, 0, 0xFF, 0xFF) // bandHeight > height → clamp to 4
	if _, _, r, _ := pixAt(f, 0, 3); r != 0xFF {
		t.Fatal("clamped band should cover the whole frame")
	}
	ApplyActiveIndicator(&f, 0, 0, 0, 0xFF, 0xFF)                            // no-op
	ApplyActiveIndicator(nil, 3, 0, 0, 0xFF, 0xFF)                           // nil no-op (no panic)
	bad := RawFrame{Width: 4, Height: 4, Stride: 4, Pixels: make([]byte, 4)} // malformed
	ApplyActiveIndicator(&bad, 2, 0, 0, 0xFF, 0xFF)                          // no panic / no write
}

func TestMaskRectClampsAndIsolates(t *testing.T) {
	f := solidFrame(10, 10, 0xFF, 0xFF, 0xFF) // white
	MaskRect(&f, 2, 2, 3, 3, 0, 0, 0, 0xFF)   // black 3×3 at (2,2)
	if _, _, r, _ := pixAt(f, 3, 3); r != 0 {
		t.Fatal("masked region should be black")
	}
	if _, _, r, _ := pixAt(f, 0, 0); r != 0xFF {
		t.Fatal("outside the mask should stay white")
	}
	if _, _, r, _ := pixAt(f, 5, 5); r != 0xFF {
		t.Fatal("just outside the mask should stay white")
	}
	// off-frame / negative rects must not panic and must clamp
	MaskRect(&f, -5, -5, 3, 3, 0, 0, 0, 0xFF) // partial top-left
	MaskRect(&f, 100, 100, 5, 5, 0, 0, 0, 0xFF)
	MaskRect(&f, 8, 8, 100, 100, 0, 0, 0, 0xFF) // clamps to frame edge
	if _, _, r, _ := pixAt(f, 9, 9); r != 0 {
		t.Fatal("bottom-right corner should be masked by the clamped rect")
	}
}

// The active-indicator must survive PNG encode/decode (it egresses with the frame).
func TestActiveIndicatorSurvivesEncode(t *testing.T) {
	f := solidFrame(8, 8, 0, 0, 0)
	ApplyActiveIndicator(&f, 2, 0, 0, 0xFF, 0xFF) // red band BGRA → R=0xFF
	out, err := NewPNGEncoder().Encode(f)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	r, g, b, _ := img.At(4, 0).RGBA() // top band → red
	if uint8(r>>8) != 0xFF || uint8(g>>8) != 0 || uint8(b>>8) != 0 {
		t.Fatalf("decoded band pixel not red: %02x %02x %02x", uint8(r>>8), uint8(g>>8), uint8(b>>8))
	}
}
