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
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF || session == 0 {
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

// AcceptAndVerify accepts ONE connection and reads + constant-time-verifies the
// launch-nonce handshake within timeout before returning the conn for frame
// reads. Fail-closed: a bad/absent/slow handshake closes the conn + errors (the
// peer must hold the nonce AND pass the DACL).
func AcceptAndVerify(l net.Listener, expectedNonce []byte, timeout time.Duration) (net.Conn, error) {
	conn, err := l.Accept()
	if err != nil {
		return nil, fmt.Errorf("dataplane: pipe accept: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	if err := ReadVerifyHandshake(conn, expectedNonce); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Time{}) // clear the handshake deadline
	return conn, nil
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
