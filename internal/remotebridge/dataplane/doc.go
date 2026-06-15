// Package dataplane is the Faz 22.6 T-4 VIEW_ONLY screen-share DATA-plane
// safety runtime for the remote-access bridge. It owns the fail-closed source
// gate that EVERY captured frame must pass before it can leave the endpoint:
// a frame is admitted ONLY while recording is ready AND the session is the
// active VIEW_ONLY screen-view AND no local abort has fired. The instant any
// of those drops, the in-flight queue is flushed/dropped — no frame egresses
// after the gate closes (ADR-0034 D3 recording-mandate + D8 VIEW_ONLY pilot +
// the D10 exfil-control expectations; Codex 019ecbc5 AGREE).
//
// This package is the SAFETY CORE only: it carries NO real screen capture
// (the Windows DXGI/Desktop-Duplication FrameProducer is a later slice,
// build-tag _windows.go) and NEVER touches the frozen wire (it produces a
// domain Frame; the harness maps it to the proto DataFrame at send time). The
// whole VIEW_ONLY data plane stays disabled-by-default (the remote-view-only
// feature flag is off) and a live session is owner-pilot-gated (ADR-0034
// §13/D10) — building the disabled runtime is permitted (#1388 engineering
// gate lifted), activating it is NOT.
//
// Concurrency: a ViewSession is safe for one producer/pump goroutine offering
// frames and concurrent control-plane callers toggling the gate (SetRecording
// /Activate/Deactivate/Abort). Offer is NON-BLOCKING (bounded queue, drop on
// full) so the DATA path can never delay the CONTROL-plane KILL path.
package dataplane
