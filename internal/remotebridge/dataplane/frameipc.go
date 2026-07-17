package dataplane

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Faz 22.6 T-4 slice-3a-ii-A — the service↔helper IPC wire protocol. The
// session-launcher (slice-3a-i) starts a capture helper in the interactive
// session; the helper streams encoded VIEW_ONLY frames back to the SYSTEM
// service over a transport (a Windows named pipe in slice-3a-ii-B). This file
// is the OS-agnostic protocol over any io.ReadWriter, fully unit-testable
// without Windows.
//
// Wire message: [version u8][type u8][u32-BE length][payload]. Every message is
// versioned + typed so a stream desync / wrong peer fails CLOSED rather than
// being silently misinterpreted (Codex 019ecbc5 review). Types:
//   HANDSHAKE — the helper's FIRST message; payload is the launch-nonce the
//     service generated and handed it out-of-band, proving it is THIS
//     launcher's child (not an arbitrary user-session process). Constant-time
//     compared.
//   FRAME — one encoded VIEW_ONLY frame; length-bounded (anti-DoS, reject
//     before alloc).
//   EOF — graceful end-of-stream.
//   LOCAL_ABORT — the endpoint user explicitly ended the attended session.
//   INDICATOR_LOST — the mandatory endpoint-awareness UI disappeared.
//   BANNER_CREATE_FAILED / BANNER_NOT_VISIBLE / CAPTURE_START_FAILED / CAPTURE_LOST — fixed,
//     payload-free helper startup diagnostics. They reveal no Win32 details,
//     desktop content, user identity, pipe name or launch nonce.
//
// Disabled-by-default + LIVE owner-gated (ADR-0034 §13/D10): plumbing, not an
// activation. The named-pipe ACL + client-PID verification + read/write
// deadlines are slice-3a-ii-B (the transport).

const (
	ipcProtocolVersion = 1
	// MaxIPCFrameSize bounds one IPC payload (anti-DoS). VIEW_ONLY PNG frames fit.
	MaxIPCFrameSize = 16 << 20 // 16 MiB
	// ipcNonceLen is the launch-nonce handshake length (256-bit).
	ipcNonceLen   = 32
	ipcHeaderSize = 6 // version(1) + type(1) + length(4)
)

type ipcMsgType byte

const (
	msgHandshake          ipcMsgType = 1
	msgFrame              ipcMsgType = 2
	msgEOF                ipcMsgType = 3
	msgLocalAbort         ipcMsgType = 4
	msgIndicatorLost      ipcMsgType = 5
	msgBannerCreateFailed ipcMsgType = 6
	msgBannerNotVisible   ipcMsgType = 7
	msgCaptureStartFailed ipcMsgType = 8
	msgCaptureLost        ipcMsgType = 9
)

var (
	// ErrIPCFrameTooLarge: a header declared a length over MaxIPCFrameSize.
	ErrIPCFrameTooLarge = errors.New("dataplane: ipc frame exceeds max size")
	// ErrIPCHandshake: the peer's launch-nonce did not match (spoof/wrong peer).
	ErrIPCHandshake = errors.New("dataplane: ipc handshake mismatch")
	// ErrIPCProtocol: wrong version or an unexpected message type (fail-closed).
	ErrIPCProtocol = errors.New("dataplane: ipc protocol violation")
)

// NewLaunchNonce returns a cryptographically-random 256-bit launch nonce the
// service generates per launch and hands to the helper out-of-band.
func NewLaunchNonce() ([]byte, error) {
	b := make([]byte, ipcNonceLen)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("dataplane: launch nonce: %w", err)
	}
	return b, nil
}

// writeMsg writes one versioned+typed message. An io.Writer must consume all of
// p or report an error (io.Writer contract), so a single Write per segment is
// sufficient.
func writeMsg(w io.Writer, t ipcMsgType, payload []byte) error {
	if len(payload) > MaxIPCFrameSize {
		return ErrIPCFrameTooLarge
	}
	var hdr [ipcHeaderSize]byte
	hdr[0] = ipcProtocolVersion
	hdr[1] = byte(t)
	binary.BigEndian.PutUint32(hdr[2:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("dataplane: write ipc header: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("dataplane: write ipc payload: %w", err)
		}
	}
	return nil
}

// readMsg reads one message, validating version + length bound BEFORE
// allocating the payload (fail-closed).
func readMsg(r io.Reader) (ipcMsgType, []byte, error) {
	var hdr [ipcHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	if hdr[0] != ipcProtocolVersion {
		return 0, nil, fmt.Errorf("%w: version %d", ErrIPCProtocol, hdr[0])
	}
	t := ipcMsgType(hdr[1])
	n := binary.BigEndian.Uint32(hdr[2:])
	if n > MaxIPCFrameSize {
		return 0, nil, ErrIPCFrameTooLarge
	}
	if n == 0 {
		return t, []byte{}, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return t, buf, nil
}

// WriteHandshake sends the launch nonce as the first (HANDSHAKE) message.
func WriteHandshake(w io.Writer, nonce []byte) error {
	if len(nonce) != ipcNonceLen {
		return fmt.Errorf("dataplane: handshake nonce must be %d bytes, got %d", ipcNonceLen, len(nonce))
	}
	return writeMsg(w, msgHandshake, nonce)
}

// ReadVerifyHandshake reads the first message, requires it to be a HANDSHAKE,
// and constant-time-compares the nonce to expected. Fail-closed on wrong type,
// wrong version, or mismatch. The service calls this BEFORE any frame.
func ReadVerifyHandshake(r io.Reader, expected []byte) error {
	if len(expected) != ipcNonceLen {
		return fmt.Errorf("dataplane: expected nonce must be %d bytes", ipcNonceLen)
	}
	t, got, err := readMsg(r)
	if err != nil {
		return fmt.Errorf("dataplane: read handshake: %w", err)
	}
	if t != msgHandshake {
		return fmt.Errorf("%w: expected handshake, got type %d", ErrIPCProtocol, t)
	}
	if subtle.ConstantTimeCompare(got, expected) != 1 {
		return ErrIPCHandshake
	}
	return nil
}

// WriteFrame writes one FRAME message.
func WriteFrame(w io.Writer, payload []byte) error {
	return writeMsg(w, msgFrame, payload)
}

// WriteEOF signals a graceful end-of-stream.
func WriteEOF(w io.Writer) error { return writeMsg(w, msgEOF, nil) }

// WriteLocalAbort reports an explicit endpoint-user termination. It carries no
// caller-controlled payload, so the service can map it to the fixed allowlisted
// broker audit event without trusting helper text.
func WriteLocalAbort(w io.Writer) error { return writeMsg(w, msgLocalAbort, nil) }

// WriteIndicatorLost reports that the mandatory visible endpoint indicator was
// closed or otherwise lost while the stream was active.
func WriteIndicatorLost(w io.Writer) error { return writeMsg(w, msgIndicatorLost, nil) }

// WriteBannerCreateFailed reports that the helper could not create the
// mandatory awareness UI. It intentionally carries no raw Win32 error.
func WriteBannerCreateFailed(w io.Writer) error { return writeMsg(w, msgBannerCreateFailed, nil) }

// WriteBannerNotVisible reports that the helper created no self-verifiable
// visible awareness window. It intentionally carries no window metadata.
func WriteBannerNotVisible(w io.Writer) error { return writeMsg(w, msgBannerNotVisible, nil) }

// WriteCaptureStartFailed reports that no first frame could be captured. It
// intentionally carries no frame bytes, dimensions or encoder/GDI details.
func WriteCaptureStartFailed(w io.Writer) error { return writeMsg(w, msgCaptureStartFailed, nil) }

// WriteCaptureLost reports that capture failed closed after one or more frames
// were produced. It intentionally carries no frame or OS failure detail.
func WriteCaptureLost(w io.Writer) error { return writeMsg(w, msgCaptureLost, nil) }

// ReadFrame reads the next FRAME payload. A graceful EOF message surfaces as
// io.EOF; any other (unexpected) type is a fail-closed protocol violation.
func ReadFrame(r io.Reader) ([]byte, error) {
	t, payload, err := readMsg(r)
	if err != nil {
		return nil, err
	}
	switch t {
	case msgFrame:
		return payload, nil
	case msgEOF:
		return nil, io.EOF
	case msgLocalAbort:
		if len(payload) != 0 {
			return nil, fmt.Errorf("%w: local-abort payload must be empty", ErrIPCProtocol)
		}
		return nil, ErrLocalAbort
	case msgIndicatorLost:
		if len(payload) != 0 {
			return nil, fmt.Errorf("%w: indicator-lost payload must be empty", ErrIPCProtocol)
		}
		return nil, ErrIndicatorLost
	case msgBannerCreateFailed:
		if len(payload) != 0 {
			return nil, fmt.Errorf("%w: banner-create-failed payload must be empty", ErrIPCProtocol)
		}
		return nil, ErrBannerCreateFailed
	case msgBannerNotVisible:
		if len(payload) != 0 {
			return nil, fmt.Errorf("%w: banner-not-visible payload must be empty", ErrIPCProtocol)
		}
		return nil, ErrBannerNotVisible
	case msgCaptureStartFailed:
		if len(payload) != 0 {
			return nil, fmt.Errorf("%w: capture-start-failed payload must be empty", ErrIPCProtocol)
		}
		return nil, ErrCaptureStartupFailed
	case msgCaptureLost:
		if len(payload) != 0 {
			return nil, fmt.Errorf("%w: capture-lost payload must be empty", ErrIPCProtocol)
		}
		return nil, ErrCaptureFailed
	default:
		return nil, fmt.Errorf("%w: expected frame, got type %d", ErrIPCProtocol, t)
	}
}
