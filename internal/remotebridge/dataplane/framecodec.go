package dataplane

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/png"
)

const (
	// ScreenFramePayloadBudget stays below the broker's default 256 KiB
	// DataFrame.payload ceiling. The explicit margin keeps the client contract
	// conservative without relying on gRPC/protobuf envelope size.
	ScreenFramePayloadBudget = 240 * 1024
)

// ErrFramePayloadBudget means an encoded frame could not be made small enough
// for the screen-frame wire contract. It carries no pixel content.
var ErrFramePayloadBudget = errors.New("dataplane: frame payload budget exceeded")

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
	if err := validateRawFrame(f); err != nil {
		return nil, err
	}
	return encodePNG(p.enc, f)
}

// BoundedPNGEncoder emits the largest candidate-resolution PNG that fits
// maxPayloadBytes.
// It halves a frame with a deterministic box filter only when the current PNG
// is too large. Processors are applied to a fresh copy at every candidate size,
// so a basis-point DLP mask and the active-session indicator remain aligned and
// visible after downscaling rather than being blurred away by it.
type BoundedPNGEncoder struct {
	enc             png.Encoder
	maxPayloadBytes int
	processors      []func(*RawFrame)
}

// NewBoundedPNGEncoder returns a PNG encoder with a fail-closed payload budget.
// A non-positive budget is rejected by Encode. Nil processors are ignored.
func NewBoundedPNGEncoder(maxPayloadBytes int, processors ...func(*RawFrame)) *BoundedPNGEncoder {
	filtered := make([]func(*RawFrame), 0, len(processors))
	for _, processor := range processors {
		if processor != nil {
			filtered = append(filtered, processor)
		}
	}
	return &BoundedPNGEncoder{
		enc:             png.Encoder{CompressionLevel: png.BestSpeed},
		maxPayloadBytes: maxPayloadBytes,
		processors:      filtered,
	}
}

// Name implements Encoder. The wire codec remains image/png.
func (p *BoundedPNGEncoder) Name() string { return "png" }

// Encode implements Encoder without ever returning an over-budget payload.
func (p *BoundedPNGEncoder) Encode(f RawFrame) ([]byte, error) {
	if p.maxPayloadBytes <= 0 {
		return nil, ErrFramePayloadBudget
	}
	if err := validateRawFrame(f); err != nil {
		return nil, err
	}

	// candidate may initially share the caller's pixels because processors only
	// touch the fresh processed clone. A downscale always allocates a new frame.
	candidate := f
	for {
		processed := cloneRawFrame(candidate)
		applyFrameProcessors(&processed, p.processors)
		payload, err := encodePNG(p.enc, processed)
		if err != nil {
			return nil, err
		}
		if len(payload) <= p.maxPayloadBytes {
			return payload, nil
		}
		if candidate.Width == 1 && candidate.Height == 1 {
			return nil, ErrFramePayloadBudget
		}
		candidate = halfScaleRawFrame(candidate)
	}
}

func validateRawFrame(f RawFrame) error {
	if f.Width <= 0 || f.Height <= 0 {
		return fmt.Errorf("dataplane: invalid frame dims %dx%d", f.Width, f.Height)
	}
	if f.Stride < f.Width*4 {
		return fmt.Errorf("dataplane: stride %d < width*4 (%d)", f.Stride, f.Width*4)
	}
	if len(f.Pixels) < f.Stride*f.Height {
		return fmt.Errorf("dataplane: pixel buffer %d < stride*height (%d)", len(f.Pixels), f.Stride*f.Height)
	}
	return nil
}

func encodePNG(enc png.Encoder, f RawFrame) ([]byte, error) {
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
	if err := enc.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("dataplane: png encode: %w", err)
	}
	return buf.Bytes(), nil
}

func cloneRawFrame(f RawFrame) RawFrame {
	return RawFrame{
		Width:  f.Width,
		Height: f.Height,
		Stride: f.Stride,
		Pixels: append([]byte(nil), f.Pixels[:f.Stride*f.Height]...),
	}
}

// halfScaleRawFrame applies a 2x2 box filter in BGRA space. It is deterministic,
// dependency-free and preserves one pixel for odd/single-pixel dimensions.
func halfScaleRawFrame(src RawFrame) RawFrame {
	dstW := (src.Width + 1) / 2
	dstH := (src.Height + 1) / 2
	dst := RawFrame{
		Width:  dstW,
		Height: dstH,
		Stride: dstW * 4,
		Pixels: make([]byte, dstW*dstH*4),
	}
	for dy := 0; dy < dstH; dy++ {
		for dx := 0; dx < dstW; dx++ {
			var sum [4]int
			count := 0
			for oy := 0; oy < 2; oy++ {
				sy := dy*2 + oy
				if sy >= src.Height {
					continue
				}
				for ox := 0; ox < 2; ox++ {
					sx := dx*2 + ox
					if sx >= src.Width {
						continue
					}
					i := sy*src.Stride + sx*4
					for channel := 0; channel < 4; channel++ {
						sum[channel] += int(src.Pixels[i+channel])
					}
					count++
				}
			}
			i := dy*dst.Stride + dx*4
			for channel := 0; channel < 4; channel++ {
				dst.Pixels[i+channel] = byte(sum[channel] / count)
			}
		}
	}
	return dst
}
