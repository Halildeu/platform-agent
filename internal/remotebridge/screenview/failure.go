package screenview

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"

	"platform-agent/internal/remotebridge/dataplane"
)

var pngSignature = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// Failure codes are the complete allowlist that may cross the CONTROL wire.
// Causes stay local and are available only through errors.Is/errors.As; Error
// deliberately returns the bounded code without raw OS details.
const (
	failureUnsupported        = "screen-view-platform-unsupported"
	failureSessionBinding     = "screen-view-session-binding-failed"
	failureHelperResolution   = "screen-view-helper-resolution-failed"
	failureActiveSession      = "screen-view-active-session-failed"
	failureSecurePipe         = "screen-view-secure-pipe-failed"
	failureLaunchNonce        = "screen-view-launch-nonce-failed"
	failureHelperLaunch       = "screen-view-helper-launch-failed"
	failureHelperHandshake    = "screen-view-helper-handshake-failed"
	failureHelperPeer         = "screen-view-helper-peer-failed"
	failureBannerCreate       = "screen-view-banner-create-failed"
	failureBannerNotVisible   = "screen-view-banner-not-visible"
	failureCaptureStart       = "screen-view-capture-start-failed"
	failureCaptureLost        = "screen-view-capture-lost"
	failureHelperExited       = "screen-view-helper-exited-before-frame"
	failureHelperExitedLive   = "screen-view-helper-exited"
	failureFirstFrameTimeout  = "screen-view-first-frame-timeout"
	failureFirstFrameProtocol = "screen-view-first-frame-protocol-failed"
	failureAuthorize          = "screen-view-authorize-failed"
	failureDataSend           = "screen-view-data-send-failed"
)

type failureError struct {
	code  string
	cause error
}

func newStartupError(code string, cause error) error {
	return newFailureError(code, cause)
}

func newFailureError(code string, cause error) error {
	return &failureError{code: code, cause: cause}
}

func (e *failureError) Error() string { return e.code }
func (e *failureError) Unwrap() error { return e.cause }

// ScreenViewFailureCode is consumed by the harness through a narrow interface.
// The harness independently allowlists the returned value before transmission.
func (e *failureError) ScreenViewFailureCode() string { return e.code }

func firstFrameFailureCode(err error) string {
	switch {
	case errors.Is(err, dataplane.ErrBannerCreateFailed):
		return failureBannerCreate
	case errors.Is(err, dataplane.ErrBannerNotVisible):
		return failureBannerNotVisible
	case errors.Is(err, dataplane.ErrCaptureStartupFailed):
		return failureCaptureStart
	case errors.Is(err, io.EOF):
		return failureHelperExited
	default:
		var netErr net.Error
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
			return failureFirstFrameTimeout
		}
		return failureFirstFrameProtocol
	}
}

func writeBannerStartupSignal(w io.Writer, bannerErr error) error {
	switch {
	case errors.Is(bannerErr, dataplane.ErrLocalAbort):
		return dataplane.WriteLocalAbort(w)
	case errors.Is(bannerErr, dataplane.ErrIndicatorLost):
		return dataplane.WriteIndicatorLost(w)
	default:
		return dataplane.WriteBannerCreateFailed(w)
	}
}

func writeCaptureFailureSignal(w io.Writer, framesWritten int64) error {
	if framesWritten == 0 {
		return dataplane.WriteCaptureStartFailed(w)
	}
	return dataplane.WriteCaptureLost(w)
}

func validFirstFramePayload(payload []byte) bool {
	return bytes.HasPrefix(payload, pngSignature)
}

func validateFirstFramePayload(payload []byte) error {
	if validFirstFramePayload(payload) {
		return nil
	}
	return newStartupError(failureFirstFrameProtocol, dataplane.ErrIPCProtocol)
}
