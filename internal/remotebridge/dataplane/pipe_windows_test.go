//go:build windows

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func currentUserSID(t *testing.T) string {
	t.Helper()
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	return tu.User.Sid.String()
}

// In-process secured-pipe round-trip on the CI windows runner (same session,
// same user — no launcher needed): the SDDL grants the current user, the client
// dials + handshakes with the right nonce, sends a frame, the server verifies +
// reads it. Proves the winio pipe + SDDL + handshake + frame protocol wire up.
func TestSecurePipeRoundTrip(t *testing.T) {
	sid := currentUserSID(t)
	name, err := RandomPipeName()
	if err != nil {
		t.Fatalf("pipe name: %v", err)
	}
	l, err := ListenSecurePipe(name, sid)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	nonce, _ := NewLaunchNonce()
	want := []byte("a captured frame")
	clientErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, derr := DialAndHandshake(ctx, name, nonce)
		if derr != nil {
			clientErr <- derr
			return
		}
		defer conn.Close()
		clientErr <- WriteFrame(conn, want)
	}()

	conn, err := AcceptAndVerify(l, nonce, 5*time.Second)
	if err != nil {
		t.Fatalf("accept+verify: %v", err)
	}
	defer conn.Close()
	got, err := ReadFrame(conn)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("frame = %q, want %q", got, want)
	}
	if cerr := <-clientErr; cerr != nil {
		t.Fatalf("client: %v", cerr)
	}
}

// A client that handshakes with the WRONG nonce is rejected fail-closed.
func TestSecurePipeRejectsWrongNonce(t *testing.T) {
	sid := currentUserSID(t)
	name, _ := RandomPipeName()
	l, err := ListenSecurePipe(name, sid)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	good, _ := NewLaunchNonce()
	bad, _ := NewLaunchNonce()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if conn, derr := DialAndHandshake(ctx, name, bad); derr == nil {
			_ = conn.Close()
		}
	}()

	if _, err := AcceptAndVerify(l, good, 5*time.Second); !errors.Is(err, ErrIPCHandshake) {
		t.Fatalf("wrong-nonce accept err = %v, want ErrIPCHandshake", err)
	}
}
