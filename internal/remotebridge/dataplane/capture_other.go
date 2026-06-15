//go:build !windows

package dataplane

import "time"

// WindowsFrameProducer is a not-supported stub off Windows so cmd/agent code
// can reference it unconditionally (build-tag parity with capture_windows.go).
// "Not supported" is signalled by Next returning ok=false; Close is a no-op.
type WindowsFrameProducer struct{}

// NewWindowsFrameProducer returns the stub (the real GDI capture is windows-only).
func NewWindowsFrameProducer(_ Encoder, _ time.Duration, _ int) *WindowsFrameProducer {
	return &WindowsFrameProducer{}
}

// Next reports unsupported.
func (w *WindowsFrameProducer) Next() (Frame, bool) { return Frame{}, false }

// Close is a no-op on the stub.
func (w *WindowsFrameProducer) Close() error { return nil }

// ConsecutiveErrors is always 0 on the stub.
func (w *WindowsFrameProducer) ConsecutiveErrors() int { return 0 }
