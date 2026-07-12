//go:build windows

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// ErrEmptyUserSID is returned rather than building a SYSTEM-only or over-broad
// pipe when the target user SID is missing (fail-closed).
var ErrEmptyUserSID = errors.New("dataplane: empty user SID for pipe DACL")

// ActiveSessionUserSID returns the SID string of the active interactive
// session's user, for the pipe DACL. Fail-closed if there is no interactive
// session (so the service never opens a SYSTEM-only / unscoped capture pipe).
func ActiveSessionUserSID() (string, error) {
	// Match LaunchInActiveSession: the pipe DACL must be scoped to the SAME
	// active interactive user (RDP or console) the helper is launched into.
	session, ok := activeInteractiveSessionId()
	if !ok {
		return "", ErrNoInteractiveSession
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return "", fmt.Errorf("dataplane: WTSQueryUserToken: %w", err)
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("dataplane: GetTokenUser: %w", err)
	}
	return tu.User.Sid.String(), nil
}

// ListenSecurePipe creates a message-mode named pipe whose DACL is restricted to
// SYSTEM + userSID (fail-closed on an empty SID).
func ListenSecurePipe(name, userSID string) (net.Listener, error) {
	if userSID == "" {
		return nil, ErrEmptyUserSID
	}
	l, err := winio.ListenPipe(name, &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL(userSID),
		MessageMode:        true,
	})
	if err != nil {
		return nil, fmt.Errorf("dataplane: listen pipe: %w", err)
	}
	return l, nil
}

// acceptWithDeadline accepts ONE connection but bounds the blocking Accept() by
// BOTH ctx cancellation AND timeout. winio's Accept() otherwise blocks until a
// client dials, so a helper that is launched but never dials (crash/hang before
// the handshake) would hang the caller forever AND orphan the helper process
// (the caller's deferred Terminate never runs). On ctx-cancel or timeout it
// closes the listener — which unblocks the in-flight Accept — and fails closed,
// draining + closing any connection that raced in so none is leaked.
func acceptWithDeadline(ctx context.Context, l net.Listener, timeout time.Duration) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := l.Accept()
		ch <- result{conn, err}
	}()
	var timer <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		timer = t.C
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("dataplane: pipe accept: %w", r.err)
		}
		return r.conn, nil
	case <-ctx.Done():
		_ = l.Close()
		if r := <-ch; r.conn != nil {
			_ = r.conn.Close()
		}
		return nil, fmt.Errorf("dataplane: pipe accept cancelled: %w", ctx.Err())
	case <-timer:
		_ = l.Close()
		if r := <-ch; r.conn != nil {
			_ = r.conn.Close()
		}
		return nil, fmt.Errorf("dataplane: pipe accept timeout after %s", timeout)
	}
}

// AcceptAndVerify accepts ONE connection and reads + constant-time-verifies the
// launch-nonce handshake within timeout before returning the conn for frame
// reads. Fail-closed: a bad/absent/slow handshake closes the conn + errors (the
// peer must hold the nonce AND pass the DACL). The blocking Accept() itself is
// now bounded by timeout via acceptWithDeadline (a helper that never dials no
// longer hangs the caller and orphans the helper). acceptWithDeadline already
// takes a context so a later caller (the VIEW_ONLY capture factory) can abort a
// pending Accept on a session-scoped KILL; this entry point bounds by timeout.
func AcceptAndVerify(l net.Listener, expectedNonce []byte, timeout time.Duration) (net.Conn, error) {
	// A non-positive timeout with a background context would reintroduce the unbounded Accept() this primitive
	// exists to prevent — refuse it fail-closed. (A ctx-bounded caller uses AcceptAndVerifyContext.)
	if timeout <= 0 {
		return nil, fmt.Errorf("dataplane: pipe accept timeout must be positive, got %s", timeout)
	}
	return AcceptAndVerifyContext(context.Background(), l, expectedNonce, timeout)
}

// AcceptAndVerifyContext is AcceptAndVerify with an additional context: a caller
// whose operation is cancelled (e.g. a session-scoped KILL arriving before the
// helper has connected) aborts the pending Accept immediately instead of waiting
// out the timeout. Used by the VIEW_ONLY screen-capture factory, whose dispatch
// context cancels on KILL. timeout still bounds the wait when the context has no
// deadline; the handshake read is bounded by timeout.
func AcceptAndVerifyContext(ctx context.Context, l net.Listener, expectedNonce []byte, timeout time.Duration) (net.Conn, error) {
	conn, err := acceptWithDeadline(ctx, l, timeout)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}
	if err := ReadVerifyHandshake(conn, expectedNonce); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Time{}) // clear the handshake deadline
	return conn, nil
}

// PipeClientProcessID returns the PID of the process on the OTHER end of an
// accepted server pipe connection (GetNamedPipeClientProcessId). The caller
// verifies it equals the PID of the helper it launched — so a same-session process
// that read the launch nonce off the helper's argv and connected first is rejected
// fail-closed (it has a different PID). winio's pipe conn exposes the OS handle via
// a promoted Fd(); if that is ever not the case, this fails closed (cannot verify
// => reject). Anti-spoof for the active-session helper IPC.
func PipeClientProcessID(conn net.Conn) (uint32, error) {
	fdConn, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0, errors.New("dataplane: pipe conn does not expose a handle for client-PID verification")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(fdConn.Fd()), &pid); err != nil {
		return 0, fmt.Errorf("dataplane: GetNamedPipeClientProcessId: %w", err)
	}
	if pid == 0 {
		return 0, errors.New("dataplane: pipe client PID resolved to 0")
	}
	return pid, nil
}

// DialAndHandshake dials the pipe (bounded by ctx) and sends the launch nonce as
// the first message. The caller then WriteFrame's captured frames.
func DialAndHandshake(ctx context.Context, name string, nonce []byte) (net.Conn, error) {
	conn, err := winio.DialPipeContext(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("dataplane: pipe dial: %w", err)
	}
	if err := WriteHandshake(conn, nonce); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dataplane: send handshake: %w", err)
	}
	return conn, nil
}
