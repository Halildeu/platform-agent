package dataplane

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestNewLaunchNonceLenAndRandom(t *testing.T) {
	a, err := NewLaunchNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	if len(a) != ipcNonceLen {
		t.Fatalf("nonce len = %d, want %d", len(a), ipcNonceLen)
	}
	b, _ := NewLaunchNonce()
	if bytes.Equal(a, b) {
		t.Fatal("two nonces identical — not random")
	}
}

func TestHandshakeMatchAndMismatch(t *testing.T) {
	nonce, _ := NewLaunchNonce()

	var buf bytes.Buffer
	if err := WriteHandshake(&buf, nonce); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := ReadVerifyHandshake(&buf, nonce); err != nil {
		t.Fatalf("verify matching nonce: %v", err)
	}

	// mismatch → fail-closed
	var buf2 bytes.Buffer
	_ = WriteHandshake(&buf2, nonce)
	wrong := make([]byte, ipcNonceLen)
	copy(wrong, nonce)
	wrong[0] ^= 0xFF
	if err := ReadVerifyHandshake(&buf2, wrong); !errors.Is(err, ErrIPCHandshake) {
		t.Fatalf("mismatch err = %v, want ErrIPCHandshake", err)
	}

	// short read (peer sent < nonceLen) → error, not silent accept
	if err := ReadVerifyHandshake(bytes.NewReader([]byte{1, 2, 3}), nonce); err == nil {
		t.Fatal("short handshake must error")
	}
	// wrong expected length → guard
	if err := WriteHandshake(&bytes.Buffer{}, []byte{1, 2, 3}); err == nil {
		t.Fatal("short nonce write must error")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payloads := [][]byte{[]byte("hello"), {}, bytes.Repeat([]byte{0xAB}, 4096)}
	for _, p := range payloads {
		if err := WriteFrame(&buf, p); err != nil {
			t.Fatalf("write %d: %v", len(p), err)
		}
	}
	for i, want := range payloads {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d mismatch", i)
		}
	}
	// stream exhausted → EOF
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("exhausted read err = %v, want EOF", err)
	}
}

func TestWriteFrameRejectsOversize(t *testing.T) {
	big := make([]byte, MaxIPCFrameSize+1)
	if err := WriteFrame(io.Discard, big); !errors.Is(err, ErrIPCFrameTooLarge) {
		t.Fatalf("oversize write err = %v, want ErrIPCFrameTooLarge", err)
	}
}

// header builds a raw [version][type][u32 length] header for fail-closed tests.
func header(version byte, t ipcMsgType, length uint32) []byte {
	h := make([]byte, ipcHeaderSize)
	h[0] = version
	h[1] = byte(t)
	binary.BigEndian.PutUint32(h[2:], length)
	return h
}

func TestReadFrameRejectsOversizeHeaderBeforeAlloc(t *testing.T) {
	// header claims > max, NO payload following — reject on the header alone.
	r := bytes.NewReader(header(ipcProtocolVersion, msgFrame, MaxIPCFrameSize+1))
	if _, err := ReadFrame(r); !errors.Is(err, ErrIPCFrameTooLarge) {
		t.Fatalf("oversize header read err = %v, want ErrIPCFrameTooLarge", err)
	}
}

func TestReadFrameShortPayloadIsError(t *testing.T) {
	// header says 100 bytes but only 10 follow → unexpected EOF, not silent.
	r := io.MultiReader(bytes.NewReader(header(ipcProtocolVersion, msgFrame, 100)), bytes.NewReader(make([]byte, 10)))
	if _, err := ReadFrame(r); err == nil {
		t.Fatal("short payload must error")
	}
}

func TestReadRejectsWrongVersion(t *testing.T) {
	r := bytes.NewReader(header(ipcProtocolVersion+9, msgFrame, 0))
	if _, err := ReadFrame(r); !errors.Is(err, ErrIPCProtocol) {
		t.Fatalf("wrong-version err = %v, want ErrIPCProtocol", err)
	}
}

func TestReadFrameRejectsUnexpectedType(t *testing.T) {
	// a HANDSHAKE message where a FRAME is expected → fail-closed protocol error.
	r := bytes.NewReader(header(ipcProtocolVersion, msgHandshake, 0))
	if _, err := ReadFrame(r); !errors.Is(err, ErrIPCProtocol) {
		t.Fatalf("unexpected-type err = %v, want ErrIPCProtocol", err)
	}
}

func TestHandshakeRejectsWrongType(t *testing.T) {
	// a FRAME message where the HANDSHAKE is expected → fail-closed.
	var buf bytes.Buffer
	_ = WriteFrame(&buf, []byte("not a handshake"))
	nonce, _ := NewLaunchNonce()
	if err := ReadVerifyHandshake(&buf, nonce); !errors.Is(err, ErrIPCProtocol) {
		t.Fatalf("handshake-wrong-type err = %v, want ErrIPCProtocol", err)
	}
}

func TestWriteEOFSurfacesAsEOF(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteFrame(&buf, []byte("f1"))
	_ = WriteEOF(&buf)
	if _, err := ReadFrame(&buf); err != nil {
		t.Fatalf("first frame: %v", err)
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("after WriteEOF, ReadFrame err = %v, want io.EOF", err)
	}
}
