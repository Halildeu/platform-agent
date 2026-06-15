//go:build windows

package dataplane

import (
	"bytes"
	"image/png"
	"os"
	"testing"
	"time"
)

// TestWindowsRealCapture does a real GDI grab. Gated (DATAPLANE_REAL_CAPTURE=1)
// because CI runners may be headless / Session-0 with no desktop — run it on a
// Windows desktop session (e.g. the Parallels Win11 VM). Proves the GDI path
// yields a decodable, non-empty PNG via the fail-closed pipeline.
func TestWindowsRealCapture(t *testing.T) {
	if os.Getenv("DATAPLANE_REAL_CAPTURE") != "1" {
		t.Skip("set DATAPLANE_REAL_CAPTURE=1 on a Windows desktop session for the real GDI capture")
	}
	p := NewWindowsFrameProducer(NewPNGEncoder(), 50*time.Millisecond, 3)
	defer func() { _ = p.Close() }()
	f, ok := p.Next()
	if !ok {
		t.Fatalf("real capture failed (consecutiveErrors=%d)", p.ConsecutiveErrors())
	}
	if len(f.Payload) == 0 {
		t.Fatal("captured frame payload is empty")
	}
	img, err := png.Decode(bytes.NewReader(f.Payload))
	if err != nil {
		t.Fatalf("captured frame is not valid PNG: %v", err)
	}
	b := img.Bounds()
	if b.Dx() <= 0 || b.Dy() <= 0 {
		t.Fatalf("captured frame has bad dims %dx%d", b.Dx(), b.Dy())
	}
	t.Logf("real GDI capture OK: seq=%d dims=%dx%d png=%d bytes", f.Seq, b.Dx(), b.Dy(), len(f.Payload))
}
