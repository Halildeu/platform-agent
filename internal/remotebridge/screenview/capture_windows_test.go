//go:build windows

package screenview

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"platform-agent/internal/remotebridge/dataplane"
)

func TestBannerTerminationMapsToTypedIPC(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   error
		want error
	}{
		{"indicator-lost", dataplane.ErrIndicatorLost, dataplane.ErrIndicatorLost},
		{"local-abort", dataplane.ErrLocalAbort, dataplane.ErrLocalAbort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer, reader := net.Pipe()
			defer reader.Close()
			done := make(chan error, 1)
			go func() {
				done <- writeBannerTermination(writer, tc.in)
				_ = writer.Close()
			}()
			_, err := dataplane.ReadFrame(reader)
			if !errors.Is(err, tc.want) {
				t.Fatalf("typed IPC err=%v, want %v", err, tc.want)
			}
			if err := <-done; err != nil {
				t.Fatalf("write typed IPC: %v", err)
			}
		})
	}
}

// flag parsing: a normal startup is NOT a helper invocation; partial helper flags
// are a malformed launch (exit 2). (The full happy path dials a pipe → VM-only.)
func TestMaybeRunScreenViewHelperFlagParsing(t *testing.T) {
	validBinding, err := AcceptanceWindowBinding("sess-test")
	if err != nil {
		t.Fatal(err)
	}
	if handled, code := MaybeRunActiveSessionScreenViewHelper([]string{"--once", "--version"}); handled || code != 0 {
		t.Fatalf("non-helper args must not be handled: handled=%v code=%d", handled, code)
	}
	if handled, code := MaybeRunActiveSessionScreenViewHelper([]string{helperPipeFlag + "somepipe"}); !handled || code != 2 {
		t.Fatalf("pipe flag without nonce must be a malformed launch (true,2): handled=%v code=%d", handled, code)
	}
	if handled, code := MaybeRunActiveSessionScreenViewHelper([]string{helperNonceFlag + "abcd"}); !handled || code != 2 {
		t.Fatalf("nonce flag without pipe must be a malformed launch (true,2): handled=%v code=%d", handled, code)
	}
	if handled, code := MaybeRunActiveSessionScreenViewHelper([]string{
		helperPipeFlag + "somepipe", helperNonceFlag + "abcd", helperMaskFlag + "9000,0,1001,1000",
	}); !handled || code != 2 {
		t.Fatalf("invalid mask policy must fail closed (true,2): handled=%v code=%d", handled, code)
	}
	if handled, code := MaybeRunActiveSessionScreenViewHelper([]string{helperMaskFlag + "0,0,1000,1000"}); !handled || code != 2 {
		t.Fatalf("mask-only helper invocation must fail closed (true,2): handled=%v code=%d", handled, code)
	}
	if handled, code := MaybeRunActiveSessionScreenViewHelper([]string{
		helperPipeFlag + "somepipe", helperNonceFlag + "abcd",
		helperMaskFlag + "0,0,1000,1000", helperMaskFlag + "1000,1000,1000,1000",
	}); !handled || code != 2 {
		t.Fatalf("duplicate mask policy must fail closed (true,2): handled=%v code=%d", handled, code)
	}
	if handled, code := MaybeRunActiveSessionScreenViewHelper([]string{
		helperPipeFlag + "first", helperPipeFlag + "second", helperNonceFlag + "abcd",
	}); !handled || code != 2 {
		t.Fatalf("duplicate pipe flag must fail closed (true,2): handled=%v code=%d", handled, code)
	}
	if handled, code := MaybeRunActiveSessionScreenViewHelper([]string{
		helperPipeFlag + "somepipe", helperNonceFlag + "abcd", helperNonceFlag + "ef01",
	}); !handled || code != 2 {
		t.Fatalf("duplicate nonce flag must fail closed (true,2): handled=%v code=%d", handled, code)
	}
	if handled, code := MaybeRunActiveSessionScreenViewHelper([]string{
		helperPipeFlag + "somepipe", helperNonceFlag + "abcd", helperSessionBindingFlag + "not-a-binding",
	}); !handled || code != 2 {
		t.Fatalf("invalid session binding must fail closed (true,2): handled=%v code=%d", handled, code)
	}
	if handled, code := MaybeRunActiveSessionScreenViewHelper([]string{
		helperPipeFlag + "somepipe", helperNonceFlag + "abcd",
		helperSessionBindingFlag + validBinding, helperSessionBindingFlag + validBinding,
	}); !handled || code != 2 {
		t.Fatalf("duplicate session binding must fail closed (true,2): handled=%v code=%d", handled, code)
	}
}

// ipcFrameProducer replays the prefetched first frame, then reads framed frames off
// the conn, ends ok=false on EOF, and Close is idempotent (nil helper/listener ok).
func TestIPCFrameProducerReplayReadEOFClose(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		_ = c2.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = dataplane.WriteFrame(c2, []byte("F2"))
		_ = dataplane.WriteEOF(c2)
		_ = c2.Close()
	}()
	p := &ipcFrameProducer{conn: c1, first: []byte("F1")}

	if f, ok := p.Next(); !ok || string(f.Payload) != "F1" {
		t.Fatalf("first Next must replay the prefetched frame F1: ok=%v payload=%q", ok, f.Payload)
	}
	if f, ok := p.Next(); !ok || string(f.Payload) != "F2" {
		t.Fatalf("second Next must read F2 off the conn: ok=%v payload=%q", ok, f.Payload)
	}
	if _, ok := p.Next(); ok {
		t.Fatal("Next must return ok=false at EOF (helper done)")
	}
	if err := p.Err(); !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected helper EOF must remain a typed failure, got %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Close(); err != nil { // idempotent
		t.Fatalf("second Close must be a no-op: %v", err)
	}
}

// Close must unblock a Next blocked in ReadFrame (so a session KILL that Closes the
// producer tears down a live stream promptly).
func TestIPCFrameProducerCloseUnblocksRead(t *testing.T) {
	c1, _ := net.Pipe() // no writer → ReadFrame blocks until Close
	p := &ipcFrameProducer{conn: c1, firstUsed: true}
	done := make(chan struct{})
	go func() {
		_, _ = p.Next() // blocks in ReadFrame
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	_ = p.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock a Next blocked in ReadFrame")
	}
}
