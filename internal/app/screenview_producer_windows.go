//go:build windows

package app

import (
	"context"
	"errors"

	"platform-agent/internal/remotebridge/dataplane"
	"platform-agent/internal/remotebridge/screenview"
)

// errScreenCaptureUnavailable is returned by the VIEW_ONLY producer factory until the active-session capture
// helper is wired. Fail-closed: the dispatcher opens no gate and emits no frame.
var errScreenCaptureUnavailable = errors.New("remote-bridge view-only: active-session screen capture not yet wired (Faz 22.6 #1580 sub-slice #6)")

// newScreenViewProducerFactory returns the Windows VIEW_ONLY capture factory.
//
// The agent runs as a Session-0 service; an in-process GDI producer (dataplane.NewWindowsFrameProducer) cannot
// capture the INTERACTIVE user desktop from Session-0. Production capture must run in the ACTIVE session via the
// launcher/pipe helper, and MUST be fail-closed on endpoint awareness (no visible banner ⇒ no session) and bind
// the active-indicator frame processor (no unindicated capture). That helper-backed factory is sub-slice #6,
// validated on a real Windows host (a hardware gate). Until then VIEW_ONLY is fail-closed on Windows too — never
// a fake/partial capture (no in-process Session-0 producer, no unbannered/unindicated frames).
func newScreenViewProducerFactory() screenview.ProducerFactory {
	return func(context.Context, string) (dataplane.FrameProducer, error) {
		return nil, errScreenCaptureUnavailable
	}
}
