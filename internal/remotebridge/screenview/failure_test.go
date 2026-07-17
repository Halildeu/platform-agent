package screenview

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"platform-agent/internal/remotebridge/dataplane"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "raw timeout detail" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestStartupErrorExposesOnlyBoundedCode(t *testing.T) {
	cause := errors.New("raw OS detail must stay local")
	err := newStartupError(failureHelperLaunch, cause)
	if got := err.Error(); got != failureHelperLaunch {
		t.Fatalf("Error() = %q, want bounded code %q", got, failureHelperLaunch)
	}
	if !errors.Is(err, cause) {
		t.Fatal("startup error must preserve errors.Is for local control flow")
	}
	coded, ok := err.(interface{ ScreenViewFailureCode() string })
	if !ok || coded.ScreenViewFailureCode() != failureHelperLaunch {
		t.Fatalf("failure code = %q, want %q", coded.ScreenViewFailureCode(), failureHelperLaunch)
	}
}

func TestFirstFrameFailureCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"banner-create", dataplane.ErrBannerCreateFailed, failureBannerCreate},
		{"banner-not-visible", fmt.Errorf("wrapped: %w", dataplane.ErrBannerNotVisible), failureBannerNotVisible},
		{"capture", dataplane.ErrCaptureStartupFailed, failureCaptureStart},
		{"helper-exit", io.EOF, failureHelperExited},
		{"timeout", timeoutError{}, failureFirstFrameTimeout},
		{"os-deadline", fmt.Errorf("wrapped: %w", os.ErrDeadlineExceeded), failureFirstFrameTimeout},
		{"protocol", dataplane.ErrIPCProtocol, failureFirstFrameProtocol},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstFrameFailureCode(tc.err); got != tc.want {
				t.Fatalf("firstFrameFailureCode() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHelperFailureSignalsArePayloadFreeAndStageCorrect(t *testing.T) {
	tests := []struct {
		name  string
		write func(io.Writer) error
		want  error
	}{
		{"banner-create", func(w io.Writer) error { return writeBannerStartupSignal(w, errors.New("raw")) }, dataplane.ErrBannerCreateFailed},
		{"banner-local-abort", func(w io.Writer) error { return writeBannerStartupSignal(w, dataplane.ErrLocalAbort) }, dataplane.ErrLocalAbort},
		{"banner-indicator-lost", func(w io.Writer) error { return writeBannerStartupSignal(w, dataplane.ErrIndicatorLost) }, dataplane.ErrIndicatorLost},
		{"capture-start", func(w io.Writer) error { return writeCaptureFailureSignal(w, 0) }, dataplane.ErrCaptureStartupFailed},
		{"capture-lost", func(w io.Writer) error { return writeCaptureFailureSignal(w, 3) }, dataplane.ErrCaptureFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.write(&buf); err != nil {
				t.Fatalf("write signal: %v", err)
			}
			if _, err := dataplane.ReadFrame(&buf); !errors.Is(err, tc.want) {
				t.Fatalf("ReadFrame err = %v, want %v", err, tc.want)
			}
			if buf.Len() != 0 {
				t.Fatalf("signal left unread payload bytes: %d", buf.Len())
			}
		})
	}
}

func TestValidFirstFramePayloadRequiresPNGSignature(t *testing.T) {
	valid := append(append([]byte(nil), pngSignature...), []byte("payload")...)
	if !validFirstFramePayload(valid) {
		t.Fatal("PNG signature must be accepted")
	}
	if validFirstFramePayload([]byte("not-png")) {
		t.Fatal("non-PNG first payload must fail closed")
	}
	if err := validateFirstFramePayload([]byte("not-png")); err == nil {
		t.Fatal("non-PNG first payload must return a typed failure")
	} else {
		coded, ok := err.(interface{ ScreenViewFailureCode() string })
		if !ok || coded.ScreenViewFailureCode() != failureFirstFrameProtocol {
			t.Fatalf("invalid first payload code = %v, want %q", err, failureFirstFrameProtocol)
		}
		if !errors.Is(err, dataplane.ErrIPCProtocol) {
			t.Fatalf("invalid first payload must preserve ErrIPCProtocol, got %v", err)
		}
	}
}
