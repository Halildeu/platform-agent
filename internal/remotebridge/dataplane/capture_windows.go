//go:build windows

package dataplane

import (
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Real VIEW_ONLY screen capture via GDI BitBlt. Disabled-by-default + owner-gated
// for LIVE: a WindowsFrameProducer is only constructed when the remote-view-only
// feature is enabled. GDI (not DXGI) is the deliberate seed — pure user32/gdi32
// syscalls (no COM/D3D), adequate for the low-fps VIEW_ONLY pilot; DXGI
// Desktop-Duplication is a later perf slice. It grabs the virtual screen of the
// session this process runs IN. Every GDI handle is acquired AND released per
// frame (no persistent handle, leak-safe, no cross-goroutine GDI sharing).
//
// SESSION-CONTEXT (verified on the Win11 VM, 2026-06-15): GDI BitBlt can only
// read the desktop of the CALLER's Windows session. The agent runs as a SYSTEM
// service in Session 0 (non-interactive), which CANNOT BitBlt the logged-in
// user's interactive desktop (session 1) — capture there fails and this
// producer's kill-switch fail-closes (proven). To capture the user's screen the
// producer MUST be launched IN the interactive session (WTSGetActiveConsoleSessionId
// + WTSQueryUserToken + CreateProcessAsUser, or a session-1 helper). That
// "service → interactive-session launcher" is the NEXT slice and is where the
// real-pixel gold-proof belongs; THIS slice provides the capture algorithm +
// codec + kill-safe lifecycle, NOT a real-pixel-verified stream.

var (
	user32 = syscall.NewLazyDLL("user32.dll")
	gdi32  = syscall.NewLazyDLL("gdi32.dll")

	procGetDC                  = user32.NewProc("GetDC")
	procReleaseDC              = user32.NewProc("ReleaseDC")
	procGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procGetDIBits              = gdi32.NewProc("GetDIBits")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
)

const (
	smXVirtualScreen  = 76
	smYVirtualScreen  = 77
	smCXVirtualScreen = 78
	smCYVirtualScreen = 79

	srcCopy                  = 0x00CC0020
	captureSRCCopyCAPTUREBLT = 0x40000000 // include layered windows
	biRGB                    = 0
	dibRGBColors             = 0
)

// bitmapInfoHeader mirrors Win32 BITMAPINFOHEADER (40 bytes). A negative Height
// requests TOP-DOWN rows (matching RawFrame).
type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

// DefaultCaptureInterval is the VIEW_ONLY frame cadence (5 fps). Low fps keeps
// CPU + bandwidth bounded; the real-time feel is a later (DXGI) slice concern.
const DefaultCaptureInterval = 200 * time.Millisecond

// DefaultMaxConsecutiveErrors trips a fail-closed kill-switch: after this many
// back-to-back capture failures the producer stops (Next → ok=false) rather
// than spinning on a broken display/session (Codex review #2 must-have).
const DefaultMaxConsecutiveErrors = 10

// WindowsFrameProducer implements FrameProducer via GDI. Close interrupts a
// rate-limit wait immediately (the hard-contract the dataplane Pump relies on
// for instant local-abort).
type WindowsFrameProducer struct {
	enc      Encoder
	interval time.Duration
	maxErr   int
	// processors are the exfil controls (active-indicator / screen-mask) applied
	// in order to each captured RawFrame BEFORE encode, so every egressed frame
	// carries them (ADR-0034 D10). Empty = none.
	processors []func(*RawFrame)
	// captureFn grabs one RawFrame. Default = capture (full virtual screen);
	// the VIEW_ONLY primary-screen producer injects capturePrimaryScreen so the
	// captured region matches the primary-monitor banner.
	captureFn func() (RawFrame, error)

	stop     chan struct{}
	stopOnce sync.Once

	mu      sync.Mutex
	seq     int64
	consErr int
	lastErr error
	started bool
}

// NewWindowsFrameProducer builds a GDI producer. A nil encoder defaults to PNG;
// interval<=0 and maxErr<=0 take the documented defaults. Optional processors
// (exfil controls — active-indicator / screen-mask) are applied in order to each
// captured RawFrame before encode; nil entries are skipped. Passing none keeps
// the raw capture unmodified.
func NewWindowsFrameProducer(enc Encoder, interval time.Duration, maxErr int, processors ...func(*RawFrame)) *WindowsFrameProducer {
	return newWindowsFrameProducer(enc, interval, maxErr, capture, processors...)
}

// NewWindowsPrimaryScreenFrameProducer is NewWindowsFrameProducer but captures
// ONLY the primary monitor (capturePrimaryScreen) — used by VIEW_ONLY screen
// observation so the captured region matches the primary-monitor banner.
func NewWindowsPrimaryScreenFrameProducer(enc Encoder, interval time.Duration, maxErr int, processors ...func(*RawFrame)) *WindowsFrameProducer {
	return newWindowsFrameProducer(enc, interval, maxErr, capturePrimaryScreen, processors...)
}

func newWindowsFrameProducer(enc Encoder, interval time.Duration, maxErr int, captureFn func() (RawFrame, error), processors ...func(*RawFrame)) *WindowsFrameProducer {
	if enc == nil {
		enc = NewPNGEncoder()
	}
	if interval <= 0 {
		interval = DefaultCaptureInterval
	}
	if maxErr <= 0 {
		maxErr = DefaultMaxConsecutiveErrors
	}
	if captureFn == nil {
		captureFn = capture
	}
	procs := make([]func(*RawFrame), 0, len(processors))
	for _, p := range processors {
		if p != nil {
			procs = append(procs, p)
		}
	}
	return &WindowsFrameProducer{enc: enc, interval: interval, maxErr: maxErr, processors: procs, captureFn: captureFn, stop: make(chan struct{})}
}

// Next captures, encodes, and returns the next frame. It rate-limits with a
// stop-aware wait (Close releases it at once). On a capture/encode error it
// counts a consecutive failure and retries on the next tick; after maxErr
// back-to-back failures it trips the fail-closed kill-switch (ok=false). Never
// logs frame content.
func (w *WindowsFrameProducer) Next() (Frame, bool) {
	// First call emits immediately; later calls wait one interval (stop-aware).
	w.mu.Lock()
	first := !w.started
	w.started = true
	w.mu.Unlock()
	if !first {
		select {
		case <-w.stop:
			return Frame{}, false
		case <-time.After(w.interval):
		}
	}
	for {
		select {
		case <-w.stop:
			return Frame{}, false
		default:
		}
		captureFn := w.captureFn
		if captureFn == nil {
			captureFn = capture
		}
		raw, err := captureFn()
		if err == nil {
			// Exfil controls run BEFORE encode so every egressed frame carries
			// them (active-indicator band, screen-masks). frameWritable-guarded
			// in-place ops; no processors leaves the capture untouched.
			applyFrameProcessors(&raw, w.processors)
			payload, encErr := w.enc.Encode(raw)
			if encErr == nil {
				w.mu.Lock()
				w.consErr = 0
				w.lastErr = nil
				w.seq++
				seq := w.seq
				w.mu.Unlock()
				return Frame{Seq: seq, Payload: payload}, true
			}
			err = encErr
		}
		// failure: count + kill-switch
		w.mu.Lock()
		w.consErr++
		w.lastErr = err
		tripped := w.consErr >= w.maxErr
		w.mu.Unlock()
		if tripped {
			return Frame{}, false // fail-closed: stop rather than spin
		}
		// back off one interval (stop-aware) then retry
		select {
		case <-w.stop:
			return Frame{}, false
		case <-time.After(w.interval):
		}
	}
}

// Close stops the producer and releases any rate-limit wait immediately
// (idempotent). GDI handles are per-frame, so there is nothing else to free.
func (w *WindowsFrameProducer) Close() error {
	w.stopOnce.Do(func() { close(w.stop) })
	return nil
}

// Err returns a bounded sentinel when the consecutive-error kill-switch ended
// capture. Raw GDI/encoder details remain local and never cross the control wire.
func (w *WindowsFrameProducer) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.consErr >= w.maxErr && w.lastErr != nil {
		return ErrCaptureFailed
	}
	return nil
}

// ConsecutiveErrors snapshots the kill-switch counter (telemetry/tests).
func (w *WindowsFrameProducer) ConsecutiveErrors() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.consErr
}

func getSystemMetric(i int) int {
	r, _, _ := procGetSystemMetrics.Call(uintptr(i))
	return int(int32(r))
}

// capture grabs the full virtual screen (all monitors) as top-down BGRA.
func capture() (RawFrame, error) {
	return captureRegion(
		getSystemMetric(smXVirtualScreen), getSystemMetric(smYVirtualScreen),
		getSystemMetric(smCXVirtualScreen), getSystemMetric(smCYVirtualScreen))
}

// capturePrimaryScreen grabs ONLY the primary monitor (origin 0,0) as top-down
// BGRA. VIEW_ONLY screen observation uses this so the captured region matches the
// primary-monitor endpoint-awareness banner — no secondary monitor is captured
// without the user seeing the "remote active" banner (banner/capture parity;
// Codex 019f1132). Multi-monitor coverage (banner + capture on every monitor) is
// a GA follow-up.
func capturePrimaryScreen() (RawFrame, error) {
	return captureRegion(0, 0, getSystemMetric(smCXScreen), getSystemMetric(smCYScreen))
}

// captureRegion grabs the given screen rectangle as top-down BGRA. Every GDI
// handle is released before return (defers run LIFO), including on the error
// paths.
func captureRegion(x, y, wdt, hgt int) (RawFrame, error) {
	if wdt <= 0 || hgt <= 0 {
		return RawFrame{}, fmt.Errorf("dataplane: invalid capture region %dx%d", wdt, hgt)
	}

	hScreen, _, _ := procGetDC.Call(0)
	if hScreen == 0 {
		return RawFrame{}, fmt.Errorf("dataplane: GetDC(0) failed")
	}
	defer procReleaseDC.Call(0, hScreen)

	hMem, _, _ := procCreateCompatibleDC.Call(hScreen)
	if hMem == 0 {
		return RawFrame{}, fmt.Errorf("dataplane: CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(hMem)

	hBmp, _, _ := procCreateCompatibleBitmap.Call(hScreen, uintptr(wdt), uintptr(hgt))
	if hBmp == 0 {
		return RawFrame{}, fmt.Errorf("dataplane: CreateCompatibleBitmap failed")
	}
	defer procDeleteObject.Call(hBmp)

	old, _, _ := procSelectObject.Call(hMem, hBmp)
	if old == 0 || old == ^uintptr(0) {
		return RawFrame{}, fmt.Errorf("dataplane: SelectObject bitmap failed")
	}
	selected := true
	restoreSelected := func() {
		if selected {
			procSelectObject.Call(hMem, old)
			selected = false
		}
	}
	defer restoreSelected()

	// CAPTUREBLT includes layered/transparent windows in the grab.
	ret, _, _ := procBitBlt.Call(hMem, 0, 0, uintptr(wdt), uintptr(hgt),
		hScreen, uintptr(int32(x)), uintptr(int32(y)), srcCopy|captureSRCCopyCAPTUREBLT)
	if ret == 0 {
		return RawFrame{}, fmt.Errorf("dataplane: BitBlt failed")
	}
	// GetDIBits requires the target bitmap to be deselected from the DC.
	restoreSelected()

	stride := wdt * 4
	buf := make([]byte, stride*hgt)
	bmi := bitmapInfoHeader{
		Size:        40,
		Width:       int32(wdt),
		Height:      -int32(hgt), // top-down
		Planes:      1,
		BitCount:    32,
		Compression: biRGB,
	}
	ret, _, _ = procGetDIBits.Call(hMem, hBmp, 0, uintptr(hgt),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bmi)), dibRGBColors)
	if ret == 0 {
		return RawFrame{}, fmt.Errorf("dataplane: GetDIBits failed")
	}
	return RawFrame{Width: wdt, Height: hgt, Stride: stride, Pixels: buf}, nil
}
