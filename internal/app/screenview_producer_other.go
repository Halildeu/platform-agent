//go:build !windows

package app

import (
	"context"
	"errors"

	"platform-agent/internal/remotebridge/dataplane"
	"platform-agent/internal/remotebridge/screenview"
)

// errScreenCaptureUnavailable is returned by the VIEW_ONLY producer factory on a platform with no
// active-desktop screen-capture implementation. Fail-closed: the dispatcher opens no gate and emits no frame.
var errScreenCaptureUnavailable = errors.New("remote-bridge view-only: screen capture unavailable on this platform")

// newScreenViewProducerFactory returns the platform VIEW_ONLY capture factory. Off Windows there is no
// active-desktop capture, so it is fail-closed (every call errors): VIEW_ONLY may be WIRED (its gate + routing
// are exercised) but never egresses a frame. The real active-session capture lives on Windows (sub-slice #6).
func newScreenViewProducerFactory() screenview.ProducerFactory {
	return func(context.Context, string) (dataplane.FrameProducer, error) {
		return nil, errScreenCaptureUnavailable
	}
}
