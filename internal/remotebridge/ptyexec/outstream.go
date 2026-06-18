package ptyexec

import (
	"errors"
	"io"

	pb "platform-agent/internal/remotebridge/pb"
)

const (
	// DefaultDataFrameChunk is the max payload bytes per emitted DataFrame — conservatively below the
	// broker's maxDataFrameBytes (256 KiB) so a frame never trips the broker's stream-layer cap.
	DefaultDataFrameChunk = 16 * 1024
	// MaxDataFrameChunk caps a caller-supplied chunk: still well below the broker's 256 KiB cap, leaving
	// headroom for envelope/proto overhead. A larger requested chunk is clamped to this (never rejected),
	// so a frame can never exceed the broker's per-frame limit.
	MaxDataFrameChunk = 64 * 1024
	// PTYContentType marks the DATA frames as a constrained-PTY terminal stream (raw VT bytes from the
	// pseudo-console; the operator console renders them).
	PTYContentType = "application/x-conpty-stream"
)

// ErrStreamerClosed is returned by Write after the streamer has been closed.
var ErrStreamerClosed = errors.New("ptyexec: output streamer already closed")

// OutputStreamer chunks a byte stream into ordered pb.DataFrame messages for the bridge DATA stream:
// per-stream monotonic FrameSeq from 0, payload ≤ chunk bytes, and a final EndStream frame on Close. It is an
// io.WriteCloser, so it composes with ANY output source — the ConPTY output (slice-5 wires it) or a live
// reader — and is OS-agnostic + testable without a process. It does NOT open or own the gRPC Data stream; it
// emits frames to the injected send func (the harness owns the live stream — slice-5).
type OutputStreamer struct {
	streamID    string
	contentType string
	chunk       int
	send        func(*pb.DataFrame) error
	seq         int64
	closed      bool
}

// NewOutputStreamer builds a streamer for streamID. chunk<=0 takes DefaultDataFrameChunk; a blank contentType
// takes PTYContentType. streamID + send must be non-empty/non-nil (fail-closed).
func NewOutputStreamer(streamID, contentType string, chunk int, send func(*pb.DataFrame) error) (*OutputStreamer, error) {
	if streamID == "" {
		return nil, errors.New("ptyexec: empty streamID")
	}
	if send == nil {
		return nil, errors.New("ptyexec: nil send")
	}
	if chunk <= 0 {
		chunk = DefaultDataFrameChunk
	} else if chunk > MaxDataFrameChunk {
		chunk = MaxDataFrameChunk // clamp below the broker per-frame cap (never reject)
	}
	if contentType == "" {
		contentType = PTYContentType
	}
	return &OutputStreamer{streamID: streamID, contentType: contentType, chunk: chunk, send: send}, nil
}

// Write splits p into payload-sized DataFrames (FrameSeq monotonic, in order) and sends each. Implements
// io.Writer. A send error stops and is returned (n = bytes successfully framed + sent). Errors after Close.
// Each frame owns a COPY of its payload slice (the caller may reuse p).
func (s *OutputStreamer) Write(p []byte) (int, error) {
	if s.closed {
		return 0, ErrStreamerClosed
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > s.chunk {
			n = s.chunk
		}
		if err := s.send(&pb.DataFrame{
			StreamId:    s.streamID,
			FrameSeq:    s.seq,
			ContentType: s.contentType,
			Payload:     append([]byte(nil), p[:n]...),
		}); err != nil {
			return written, err
		}
		s.seq++
		written += n
		p = p[n:]
	}
	return written, nil
}

// Close emits a final, empty EndStream frame marking end-of-output, then refuses further Write. Idempotent
// (a second Close is a no-op, no duplicate end frame).
func (s *OutputStreamer) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.send(&pb.DataFrame{
		StreamId:    s.streamID,
		FrameSeq:    s.seq,
		ContentType: s.contentType,
		EndStream:   true,
	})
}

// StreamOutput copies src into DataFrames via an OutputStreamer for streamID, then closes (final EndStream).
// The canonical "ConPTY output → DATA stream" path — the harness (slice-5) pipes the gated executor's output
// reader here. A copy error closes the streamer + is returned.
func StreamOutput(streamID, contentType string, chunk int, src io.Reader, send func(*pb.DataFrame) error) error {
	s, err := NewOutputStreamer(streamID, contentType, chunk, send)
	if err != nil {
		return err
	}
	if _, err := io.Copy(s, src); err != nil {
		_ = s.Close()
		return err
	}
	return s.Close()
}
