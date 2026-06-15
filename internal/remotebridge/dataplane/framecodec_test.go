package dataplane

import (
	"bytes"
	"image/png"
	"testing"
	"time"
)

// bgraFrame builds a tiny top-down BGRA RawFrame with optional row padding.
func bgraFrame(w, h, pad int) RawFrame {
	stride := w*4 + pad
	pix := make([]byte, stride*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := y*stride + x*4
			pix[i+0] = 0x10 // B
			pix[i+1] = 0x20 // G
			pix[i+2] = 0x30 // R
			pix[i+3] = 0x00 // A (undefined from GDI)
		}
	}
	return RawFrame{Width: w, Height: h, Stride: stride, Pixels: pix}
}

func TestPNGEncoderRoundTripAndBGRASwap(t *testing.T) {
	enc := NewPNGEncoder()
	if enc.Name() != "png" {
		t.Fatalf("Name = %q, want png", enc.Name())
	}
	out, err := enc.Encode(bgraFrame(4, 3, 0))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	b := img.Bounds()
	if b.Dx() != 4 || b.Dy() != 3 {
		t.Fatalf("decoded dims %dx%d, want 4x3", b.Dx(), b.Dy())
	}
	// BGRA (B=0x10,G=0x20,R=0x30) must decode to RGBA R=0x30,G=0x20,B=0x10, opaque.
	r, g, bl, a := img.At(0, 0).RGBA()
	if uint8(r>>8) != 0x30 || uint8(g>>8) != 0x20 || uint8(bl>>8) != 0x10 {
		t.Fatalf("pixel RGB = %02x %02x %02x, want 30 20 10 (BGRA→RGBA swap)", uint8(r>>8), uint8(g>>8), uint8(bl>>8))
	}
	if uint8(a>>8) != 0xFF {
		t.Fatalf("alpha = %02x, want FF (forced opaque)", uint8(a>>8))
	}
}

func TestPNGEncoderHonoursStridePadding(t *testing.T) {
	// pad>0 must not bleed into the image (rows read Width*4, skip padding).
	out, err := NewPNGEncoder().Encode(bgraFrame(2, 2, 8))
	if err != nil {
		t.Fatalf("encode padded: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(out)); err != nil {
		t.Fatalf("decode padded: %v", err)
	}
}

func TestPNGEncoderFailClosedOnBadInput(t *testing.T) {
	enc := NewPNGEncoder()
	cases := []RawFrame{
		{Width: 0, Height: 1, Stride: 4, Pixels: make([]byte, 4)},   // bad width
		{Width: 1, Height: 0, Stride: 4, Pixels: make([]byte, 4)},   // bad height
		{Width: 4, Height: 1, Stride: 4, Pixels: make([]byte, 16)},  // stride < width*4
		{Width: 4, Height: 4, Stride: 16, Pixels: make([]byte, 16)}, // buffer < stride*height
	}
	for i, c := range cases {
		if _, err := enc.Encode(c); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}

// WindowsFrameProducer must satisfy FrameProducer on every platform (real GDI
// on windows, stub elsewhere) so cmd/agent references it unconditionally.
var _ FrameProducer = (*WindowsFrameProducer)(nil)

func TestWindowsFrameProducerCloseIdempotent(t *testing.T) {
	p := NewWindowsFrameProducer(nil, 10*time.Millisecond, 0)
	if err := p.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// After Close, Next must not produce on any platform (stub: always false;
	// windows: stop channel closed → false).
	if _, ok := p.Next(); ok {
		t.Fatal("Next after Close must report ok=false")
	}
}
