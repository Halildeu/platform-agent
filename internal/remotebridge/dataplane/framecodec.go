package dataplane

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
)

// RawFrame is one uncompressed captured frame in the GDI/DXGI-native pixel
// order: TOP-DOWN BGRA. Stride is the row length in bytes (>= Width*4; may carry
// alignment padding). RawFrame + Encoder are the producer-internal capture→encode
// seam so the codec can change with NO wire change (the wire carries opaque
// encoded Frame.Payload bytes — Codex 019ecbc5 review).
type RawFrame struct {
	Width, Height int
	Stride        int    // bytes per row (>= Width*4)
	Pixels        []byte // top-down BGRA, len >= Stride*Height
}

// Encoder turns a RawFrame into encoded Frame.Payload bytes. PNGEncoder is the
// slice-2 default; a later slice may swap a delta/video codec with no wire
// change. Name identifies the codec for telemetry/negotiation only — an Encoder
// MUST NOT log or print frame content (screen pixels are PII).
type Encoder interface {
	Encode(RawFrame) ([]byte, error)
	Name() string
}

// PNGEncoder encodes a RawFrame to lossless PNG (std-lib, adequate for the
// low-fps VIEW_ONLY seed; BestSpeed keeps per-frame CPU bounded).
type PNGEncoder struct {
	enc png.Encoder
}

// NewPNGEncoder returns a PNGEncoder tuned for low latency over ratio.
func NewPNGEncoder() *PNGEncoder {
	return &PNGEncoder{enc: png.Encoder{CompressionLevel: png.BestSpeed}}
}

// Name implements Encoder.
func (p *PNGEncoder) Name() string { return "png" }

// Encode converts top-down BGRA → RGBA (with forced-opaque alpha, since GDI
// BitBlt leaves the alpha byte undefined) → PNG. It validates dims/stride/buffer
// fail-closed (a malformed frame errors rather than reading out of bounds).
func (p *PNGEncoder) Encode(f RawFrame) ([]byte, error) {
	if f.Width <= 0 || f.Height <= 0 {
		return nil, fmt.Errorf("dataplane: invalid frame dims %dx%d", f.Width, f.Height)
	}
	if f.Stride < f.Width*4 {
		return nil, fmt.Errorf("dataplane: stride %d < width*4 (%d)", f.Stride, f.Width*4)
	}
	if len(f.Pixels) < f.Stride*f.Height {
		return nil, fmt.Errorf("dataplane: pixel buffer %d < stride*height (%d)", len(f.Pixels), f.Stride*f.Height)
	}
	img := image.NewRGBA(image.Rect(0, 0, f.Width, f.Height))
	for y := 0; y < f.Height; y++ {
		src := f.Pixels[y*f.Stride : y*f.Stride+f.Width*4]
		dst := img.Pix[y*img.Stride : y*img.Stride+f.Width*4]
		for x := 0; x < f.Width; x++ {
			// BGRA (src) → RGBA (dst); alpha forced opaque (GDI alpha is undefined)
			dst[x*4+0] = src[x*4+2] // R
			dst[x*4+1] = src[x*4+1] // G
			dst[x*4+2] = src[x*4+0] // B
			dst[x*4+3] = 0xFF       // A (opaque)
		}
	}
	var buf bytes.Buffer
	if err := p.enc.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("dataplane: png encode: %w", err)
	}
	return buf.Bytes(), nil
}
