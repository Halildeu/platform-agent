package ptyexec

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	pb "platform-agent/internal/remotebridge/pb"
)

// collector is a send func that records the emitted frames.
type collector struct{ frames []*pb.DataFrame }

func (c *collector) send(f *pb.DataFrame) error { c.frames = append(c.frames, f); return nil }

// reassemble concatenates the non-end frames' payloads (the operator-side view of the stream).
func reassemble(frames []*pb.DataFrame) []byte {
	var b bytes.Buffer
	for _, f := range frames {
		b.Write(f.Payload)
	}
	return b.Bytes()
}

func TestNewOutputStreamerValidation(t *testing.T) {
	c := &collector{}
	if _, err := NewOutputStreamer("", "", 0, c.send); err == nil {
		t.Error("empty streamID must error")
	}
	if _, err := NewOutputStreamer("s", "", 0, nil); err == nil {
		t.Error("nil send must error")
	}
	s, err := NewOutputStreamer("s", "", 0, c.send)
	if err != nil {
		t.Fatalf("valid: %v", err)
	}
	if s.chunk != DefaultDataFrameChunk || s.contentType != PTYContentType {
		t.Errorf("defaults not applied: chunk=%d ct=%q", s.chunk, s.contentType)
	}
	// an oversized chunk is clamped below the broker per-frame cap (never trips it)
	big, _ := NewOutputStreamer("s", "", 1<<20, c.send)
	if big.chunk != MaxDataFrameChunk {
		t.Errorf("oversized chunk not clamped: %d (want %d)", big.chunk, MaxDataFrameChunk)
	}
}

func TestOutputStreamerChunkingSeqAndEnd(t *testing.T) {
	c := &collector{}
	s, _ := NewOutputStreamer("st-1", "application/x-conpty-stream", 4, c.send)
	// 10 bytes, chunk 4 → frames of 4,4,2
	n, err := s.Write([]byte("ABCDEFGHIJ"))
	if err != nil || n != 10 {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := len(c.frames); got != 4 { // 3 data + 1 end
		t.Fatalf("frame count = %d, want 4", got)
	}
	for i, f := range c.frames {
		if f.StreamId != "st-1" {
			t.Errorf("frame %d streamId=%q", i, f.StreamId)
		}
		if f.FrameSeq != int64(i) { // monotonic from 0
			t.Errorf("frame %d seq=%d", i, f.FrameSeq)
		}
	}
	if !c.frames[3].EndStream || len(c.frames[3].Payload) != 0 {
		t.Errorf("last frame must be empty EndStream: end=%v len=%d", c.frames[3].EndStream, len(c.frames[3].Payload))
	}
	for i := 0; i < 3; i++ {
		if c.frames[i].EndStream {
			t.Errorf("data frame %d wrongly EndStream", i)
		}
	}
	if got := string(reassemble(c.frames)); got != "ABCDEFGHIJ" {
		t.Errorf("reassembled = %q", got)
	}
}

func TestOutputStreamerEmptyJustEnds(t *testing.T) {
	c := &collector{}
	s, _ := NewOutputStreamer("st-1", "", 0, c.send)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(c.frames) != 1 || !c.frames[0].EndStream || c.frames[0].FrameSeq != 0 {
		t.Fatalf("empty stream must be a single EndStream frame seq 0, got %+v", c.frames)
	}
}

func TestOutputStreamerWriteAfterClose(t *testing.T) {
	c := &collector{}
	s, _ := NewOutputStreamer("st-1", "", 0, c.send)
	_ = s.Close()
	if _, err := s.Write([]byte("x")); !errors.Is(err, ErrStreamerClosed) {
		t.Errorf("write after close must be ErrStreamerClosed, got %v", err)
	}
	// Close is idempotent — no duplicate end frame
	if err := s.Close(); err != nil {
		t.Errorf("idempotent close: %v", err)
	}
	if len(c.frames) != 1 {
		t.Errorf("duplicate end frame emitted: %d", len(c.frames))
	}
}

func TestOutputStreamerSendErrorPropagates(t *testing.T) {
	boom := errors.New("send boom")
	calls := 0
	send := func(*pb.DataFrame) error {
		calls++
		if calls == 2 {
			return boom // fail on the 2nd frame
		}
		return nil
	}
	s, _ := NewOutputStreamer("st-1", "", 4, send)
	n, err := s.Write([]byte("ABCDEFGH")) // 2 frames of 4 → 2nd fails
	if !errors.Is(err, boom) {
		t.Fatalf("send error not propagated: %v", err)
	}
	if n != 4 { // only the 1st frame's bytes were sent
		t.Errorf("partial write count = %d, want 4", n)
	}
}

func TestStreamOutputReader(t *testing.T) {
	c := &collector{}
	const payload = "the quick brown fox jumps over the lazy dog"
	if err := StreamOutput("st-9", "", 7, strings.NewReader(payload), c.send); err != nil {
		t.Fatalf("StreamOutput: %v", err)
	}
	if len(c.frames) == 0 || !c.frames[len(c.frames)-1].EndStream {
		t.Fatal("stream must end with an EndStream frame")
	}
	if got := string(reassemble(c.frames)); got != payload {
		t.Errorf("reassembled = %q, want %q", got, payload)
	}
	// seq is monotonic across all frames
	for i, f := range c.frames {
		if f.FrameSeq != int64(i) {
			t.Errorf("frame %d seq=%d", i, f.FrameSeq)
		}
	}
}
