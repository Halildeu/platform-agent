package dataplane

import (
	"bytes"
	"errors"
	"fmt"
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

func TestBoundedPNGEncoderFitsHighEntropy1080pAndReappliesControls(t *testing.T) {
	frame := RawFrame{
		Width:  1920,
		Height: 1080,
		Stride: 1920 * 4,
		Pixels: make([]byte, 1920*1080*4),
	}
	// Deterministic high-entropy pixels model the worst case for lossless PNG.
	var state uint32 = 0x9e3779b9
	for i := range frame.Pixels {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		frame.Pixels[i] = byte(state)
	}
	original := append([]byte(nil), frame.Pixels...)

	maskCenter := func(fr *RawFrame) {
		MaskRect(fr, fr.Width/4, fr.Height/4, fr.Width/2, fr.Height/2, 0, 0, 0, 0xFF)
	}
	indicator := func(fr *RawFrame) {
		ApplyActiveIndicator(fr, 28, 0, 0, 0xFF, 0xFF)
	}
	payload, err := NewBoundedPNGEncoder(ScreenFramePayloadBudget, maskCenter, indicator).Encode(frame)
	if err != nil {
		t.Fatalf("bounded encode: %v", err)
	}
	if len(payload) > ScreenFramePayloadBudget {
		t.Fatalf("payload bytes = %d, budget = %d", len(payload), ScreenFramePayloadBudget)
	}
	if !bytes.Equal(frame.Pixels, original) {
		t.Fatal("bounded encoder mutated the captured source frame")
	}
	img, err := png.Decode(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("decode bounded PNG: %v", err)
	}
	bounds := img.Bounds()
	if bounds.Dx() >= frame.Width || bounds.Dy() >= frame.Height {
		t.Fatalf("high-entropy frame was not downscaled: got %dx%d", bounds.Dx(), bounds.Dy())
	}
	r, g, b, a := img.At(bounds.Dx()/2, bounds.Dy()/2).RGBA()
	if r != 0 || g != 0 || b != 0 || a != 0xFFFF {
		t.Fatalf("DLP center pixel = rgba(%04x,%04x,%04x,%04x), want opaque black", r, g, b, a)
	}
	r, g, b, a = img.At(bounds.Dx()/2, 0).RGBA()
	if r != 0xFFFF || g != 0 || b != 0 || a != 0xFFFF {
		t.Fatalf("indicator pixel = rgba(%04x,%04x,%04x,%04x), want opaque red", r, g, b, a)
	}
}

func TestBoundedPNGEncoderRejectsInvalidBudget(t *testing.T) {
	_, err := NewBoundedPNGEncoder(0).Encode(bgraFrame(1, 1, 0))
	if !errors.Is(err, ErrFramePayloadBudget) {
		t.Fatalf("zero budget err = %v, want ErrFramePayloadBudget", err)
	}
}

func TestBoundedPNGEncoderKeepsDimensionsWhenPayloadFits(t *testing.T) {
	frame := bgraFrame(100, 75, 0)
	payload, err := NewBoundedPNGEncoder(ScreenFramePayloadBudget).Encode(frame)
	if err != nil {
		t.Fatalf("bounded encode: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := img.Bounds(); got.Dx() != frame.Width || got.Dy() != frame.Height {
		t.Fatalf("decoded dims = %dx%d, want unchanged %dx%d", got.Dx(), got.Dy(), frame.Width, frame.Height)
	}
}

func TestHalfScaleRawFrameOddAndSingleDimensions(t *testing.T) {
	for _, tc := range []struct {
		width, height int
		wantW, wantH  int
	}{
		{3, 1, 2, 1},
		{1, 5, 1, 3},
		{7, 3, 4, 2},
		{1, 1, 1, 1},
	} {
		t.Run(fmt.Sprintf("%dx%d", tc.width, tc.height), func(t *testing.T) {
			got := halfScaleRawFrame(bgraFrame(tc.width, tc.height, 4))
			if got.Width != tc.wantW || got.Height != tc.wantH {
				t.Fatalf("half-scale dims = %dx%d, want %dx%d", got.Width, got.Height, tc.wantW, tc.wantH)
			}
			if _, err := NewPNGEncoder().Encode(got); err != nil {
				t.Fatalf("half-scaled frame must remain encodable: %v", err)
			}
		})
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
