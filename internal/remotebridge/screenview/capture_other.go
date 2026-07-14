//go:build !windows

package screenview

import (
	"context"
	"errors"

	"platform-agent/internal/remotebridge/dataplane"
)

// errCaptureUnavailable is returned by the VIEW_ONLY producer factory off Windows:
// there is no active-desktop capture, so VIEW_ONLY may be WIRED (gate + routing are
// exercised) but never egresses a frame. Fail-closed.
var errCaptureUnavailable = errors.New("screenview: active-session screen capture is Windows-only")

// MaybeRunActiveSessionScreenViewHelper is a no-op off Windows (there is no
// active-session capture helper to run): the process is never the helper.
func MaybeRunActiveSessionScreenViewHelper(_ []string) (bool, int) { return false, 0 }

// NewWindowsProducerFactory returns a fail-closed factory off Windows so the
// dispatcher opens no gate and emits no frame (build-tag parity with the Windows
// implementation).
func NewWindowsProducerFactory(_ MaskPolicy) ProducerFactory {
	return func(context.Context, string, string) (dataplane.FrameProducer, error) {
		return nil, errCaptureUnavailable
	}
}
