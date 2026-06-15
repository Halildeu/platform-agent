package dataplane

// Faz 22.6 T-4 VIEW_ONLY exfil controls (ADR-0034 D10 must-lands): in-place,
// OS-agnostic pixel operations applied to a captured RawFrame BEFORE it is
// encoded + streamed, so every egressed frame carries the controls. They are
// the frame-side half of the D10 exfil set (the user local-abort is the
// dataplane gate, slice-1). Disabled-by-default; LIVE owner-gated (§13/D10).
//
//   - ApplyActiveIndicator: a solid band marking the frame as a live remote
//     capture — a visible "remote-support active" indicator + watermark.
//   - MaskRect: blanks a sensitive region (screen-mask), policy-driven.
//
// All ops are bounds-clamped + fail-safe on a malformed frame (they no-op
// rather than write out of bounds).

// frameWritable reports whether f is a usable BGRA frame for in-place writes.
func frameWritable(f *RawFrame) bool {
	return f != nil && f.Width > 0 && f.Height > 0 &&
		f.Stride >= f.Width*4 && len(f.Pixels) >= f.Stride*f.Height
}

// ApplyActiveIndicator overlays a solid colour band across the top bandHeight
// rows (BGRA). It is the VIEW_ONLY "remote-support active" visible indicator +
// per-frame watermark: a viewer (and, on the endpoint, the user) always sees a
// remote capture is active, and every streamed frame is marked as such.
func ApplyActiveIndicator(f *RawFrame, bandHeight int, b, g, r, a byte) {
	if !frameWritable(f) || bandHeight <= 0 {
		return
	}
	if bandHeight > f.Height {
		bandHeight = f.Height
	}
	for y := 0; y < bandHeight; y++ {
		row := f.Pixels[y*f.Stride : y*f.Stride+f.Width*4]
		for x := 0; x < f.Width; x++ {
			row[x*4+0], row[x*4+1], row[x*4+2], row[x*4+3] = b, g, r, a
		}
	}
}

// MaskRect blanks the rectangle (x0,y0,w,h) to a solid colour (BGRA) — a
// screen-mask for a sensitive region. Coordinates are clamped to the frame; an
// off-frame or empty rect is a no-op (never writes out of bounds).
func MaskRect(f *RawFrame, x0, y0, w, h int, b, g, r, a byte) {
	if !frameWritable(f) || w <= 0 || h <= 0 {
		return
	}
	if x0 < 0 {
		w += x0
		x0 = 0
	}
	if y0 < 0 {
		h += y0
		y0 = 0
	}
	if x0 >= f.Width || y0 >= f.Height || w <= 0 || h <= 0 {
		return
	}
	if x0+w > f.Width {
		w = f.Width - x0
	}
	if y0+h > f.Height {
		h = f.Height - y0
	}
	for y := y0; y < y0+h; y++ {
		row := f.Pixels[y*f.Stride : y*f.Stride+f.Width*4]
		for x := x0; x < x0+w; x++ {
			row[x*4+0], row[x*4+1], row[x*4+2], row[x*4+3] = b, g, r, a
		}
	}
}

// applyFrameProcessors runs procs in order against f, skipping nil entries. It
// is the single point where the capture pipeline applies its exfil controls
// before encode, so the windows producer and any other capture source share one
// audited path. Each proc is responsible for its own fail-safe (frameWritable);
// a nil frame or empty/nil procs is a safe no-op.
func applyFrameProcessors(f *RawFrame, procs []func(*RawFrame)) {
	for _, p := range procs {
		if p != nil {
			p(f)
		}
	}
}
