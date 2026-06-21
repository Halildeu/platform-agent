//go:build windows

package ptyexec

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"platform-agent/internal/remotebridge/dataplane"
)

const (
	activePTYHelperPipeFlag  = "--rb-pty-helper-pipe="
	activePTYHelperNonceFlag = "--rb-pty-helper-nonce="
	activePTYAcceptTimeout   = 15 * time.Second
	activePTYReadGrace       = 5 * time.Second
)

type activePTYRequest struct {
	ExePath       string `json:"exePath"`
	CommandLine   string `json:"commandLine"`
	Cols          int16  `json:"cols"`
	Rows          int16  `json:"rows"`
	TimeoutMillis int64  `json:"timeoutMillis"`
}

type activePTYResponse struct {
	OutputB64 string `json:"outputB64,omitempty"`
	ExitCode  uint32 `json:"exitCode"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"errorCode,omitempty"`
}

// MaybeRunActiveSessionConPTYHelper turns endpoint-agent into a short-lived helper launched in the active
// user session by the LocalSystem service. The command itself is never passed on argv; it arrives only after
// a DACL-restricted named-pipe nonce handshake.
func MaybeRunActiveSessionConPTYHelper(args []string) (bool, int) {
	var pipeName, nonceHex string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, activePTYHelperPipeFlag):
			pipeName = strings.TrimPrefix(a, activePTYHelperPipeFlag)
		case strings.HasPrefix(a, activePTYHelperNonceFlag):
			nonceHex = strings.TrimPrefix(a, activePTYHelperNonceFlag)
		}
	}
	if pipeName == "" && nonceHex == "" {
		return false, 0
	}
	if pipeName == "" || nonceHex == "" {
		return true, 2
	}
	if err := runActiveSessionConPTYHelper(pipeName, nonceHex); err != nil {
		return true, 1
	}
	return true, 0
}

// RunConPTYInActiveSession runs the already-authorized no-shell ExecPlan in the active interactive Windows
// session. A pseudo-console in service Session-0 can complete with no relayed stdout; this bridges the proven
// service->interactive-session launcher and secure pipe into the production CONSTRAINED_PTY runner.
func RunConPTYInActiveSession(ctx context.Context, exePath, commandLine string, cols, rows int16) ([]byte, uint32, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, 0, fmt.Errorf("ptyexec: helper executable: %w", err)
	}
	sid, err := dataplane.ActiveSessionUserSID()
	if err != nil {
		return nil, 0, err
	}
	pipeName, err := dataplane.RandomPipeName()
	if err != nil {
		return nil, 0, err
	}
	listener, err := dataplane.ListenSecurePipe(pipeName, sid)
	if err != nil {
		return nil, 0, err
	}
	defer listener.Close()
	nonce, err := dataplane.NewLaunchNonce()
	if err != nil {
		return nil, 0, err
	}

	helper, err := dataplane.LaunchInActiveSession(self,
		activePTYHelperPipeFlag+pipeName,
		activePTYHelperNonceFlag+hex.EncodeToString(nonce))
	if err != nil {
		return nil, 0, err
	}
	helperDone := false
	defer func() {
		if helperDone {
			_ = helper.Close()
		} else {
			_ = helper.Terminate()
		}
	}()

	conn, err := dataplane.AcceptAndVerify(listener, nonce, activePTYAcceptTimeout)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	timeout := DefaultExecTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if until := time.Until(deadline); until > 0 && until < timeout {
			timeout = until
		}
	}
	req := activePTYRequest{
		ExePath:       exePath,
		CommandLine:   commandLine,
		Cols:          cols,
		Rows:          rows,
		TimeoutMillis: timeout.Milliseconds(),
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, 0, fmt.Errorf("ptyexec: helper request: %w", err)
	}

	deadline := time.Now().Add(timeout + activePTYReadGrace)
	_ = conn.SetWriteDeadline(deadline)
	if err := dataplane.WriteFrame(conn, reqBytes); err != nil {
		return nil, 0, err
	}
	_ = conn.SetReadDeadline(deadline)
	respBytes, err := dataplane.ReadFrame(conn)
	if err != nil {
		return nil, 0, err
	}
	if _, err := dataplane.ReadFrame(conn); !errors.Is(err, io.EOF) {
		return nil, 0, fmt.Errorf("ptyexec: helper protocol did not terminate cleanly: %w", err)
	}
	helperDone = true

	var resp activePTYResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, 0, fmt.Errorf("ptyexec: helper response: %w", err)
	}
	out, err := base64.StdEncoding.DecodeString(resp.OutputB64)
	if err != nil {
		return nil, 0, fmt.Errorf("ptyexec: helper output decode: %w", err)
	}
	if resp.Error != "" {
		if resp.ErrorCode == "conpty-output-cap" {
			return out, resp.ExitCode, ErrConPTYOutputCap
		}
		return out, resp.ExitCode, errors.New(resp.Error)
	}
	return out, resp.ExitCode, nil
}

func runActiveSessionConPTYHelper(pipeName, nonceHex string) error {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), activePTYAcceptTimeout)
	defer cancel()
	conn, err := dataplane.DialAndHandshake(ctx, pipeName, nonce)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(DefaultExecTimeout + activePTYReadGrace))
	reqBytes, err := dataplane.ReadFrame(conn)
	if err != nil {
		return err
	}
	var req activePTYRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return err
	}
	timeout := time.Duration(req.TimeoutMillis) * time.Millisecond
	if timeout <= 0 || timeout > DefaultExecTimeout {
		timeout = DefaultExecTimeout
	}
	runCtx, runCancel := context.WithTimeout(context.Background(), timeout)
	defer runCancel()

	out, code, runErr := RunConPTY(runCtx, req.ExePath, req.CommandLine, req.Cols, req.Rows)
	resp := activePTYResponse{
		OutputB64: base64.StdEncoding.EncodeToString(out),
		ExitCode:  code,
	}
	if runErr != nil {
		resp.Error = runErr.Error()
		if errors.Is(runErr, ErrConPTYOutputCap) {
			resp.ErrorCode = "conpty-output-cap"
		}
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(activePTYReadGrace))
	if err := dataplane.WriteFrame(conn, respBytes); err != nil {
		return err
	}
	return dataplane.WriteEOF(conn)
}
