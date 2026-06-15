//go:build windows

package dataplane

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// tokenLaunchAccess is the least-privilege token-access set for duplicating the
// user token into a primary token for CreateProcessAsUser (Codex review #2 —
// narrower than TOKEN_ALL_ACCESS).
const tokenLaunchAccess = windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY |
	windows.TOKEN_QUERY | windows.TOKEN_ADJUST_DEFAULT | windows.TOKEN_ADJUST_SESSIONID

// Faz 22.6 T-4 slice-3a-i — the service → interactive-session launcher. The
// agent runs as a SYSTEM service in Session 0, which cannot GDI-capture the
// logged-in user's interactive desktop (session 1). This launches a helper
// process IN the active interactive session so the (slice-2) capture can read
// the real desktop. From SYSTEM (SeTcbPrivilege) WTSQueryUserToken yields the
// active session's user token WITHOUT the user's password — so this is the
// production mechanism AND the way the real-pixel proof becomes testable.
//
// Disabled-by-default + LIVE owner-gated (ADR-0034 §13/D10): nothing calls this
// until the remote-view-only feature is wired + owner-activated. Fail-closed:
// no interactive session / no user token / missing privilege → typed error,
// never a silent Session-0 launch. slice-3a-i = the launch mechanism + handle
// hygiene; the named-pipe IPC (3a-ii) and the real-pixel capture proof (3a-iii)
// are later sub-slices.

var (
	// ErrNoInteractiveSession: WTSGetActiveConsoleSessionId reports no console
	// session (0xFFFFFFFF) or the non-interactive services session (0).
	ErrNoInteractiveSession = errors.New("dataplane: no active interactive Windows session")
	// ErrUserTokenUnavailable: WTSQueryUserToken found no logged-on user token.
	ErrUserTokenUnavailable = errors.New("dataplane: no logged-on user token for the active session")
	// ErrPrivilegeMissing: WTSQueryUserToken denied for lack of SeTcbPrivilege
	// (the launcher must run as SYSTEM). Distinct from "no user" for telemetry.
	ErrPrivilegeMissing = errors.New("dataplane: required privilege not held (launcher must run as SYSTEM)")
)

// LaunchedHelper is a process started in the interactive session. The caller
// owns Process and MUST release it (Close) — and should Terminate it on
// abort/kill/feature-off so no orphan capture survives.
type LaunchedHelper struct {
	Process   windows.Handle
	Pid       uint32
	SessionID uint32

	closeOnce sync.Once
}

// Close releases the process handle WITHOUT terminating the helper. Idempotent
// (the handle is closed exactly once even under concurrent Close/Terminate —
// Codex review #2 race-loose teardown).
func (h *LaunchedHelper) Close() error {
	var err error
	h.closeOnce.Do(func() { err = windows.CloseHandle(h.Process) })
	return err
}

// Terminate force-kills the helper (best-effort) then releases the handle via
// Close. Safe to call concurrently with Close / more than once (abort/kill).
func (h *LaunchedHelper) Terminate() error {
	_ = windows.TerminateProcess(h.Process, 1)
	return h.Close()
}

// LaunchInActiveSession starts exePath (with args) in the active interactive
// session from a SYSTEM service. Every intermediate token/env handle is
// released; the helper is launched with inheritHandles=FALSE (no service handle
// leaks into the user session) on the interactive desktop. Fail-closed with a
// typed error on any precondition failure.
func LaunchInActiveSession(exePath string, args ...string) (*LaunchedHelper, error) {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF || session == 0 {
		return nil, ErrNoInteractiveSession
	}

	var userTok windows.Token
	if err := windows.WTSQueryUserToken(session, &userTok); err != nil {
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			return nil, fmt.Errorf("%w: %v", ErrPrivilegeMissing, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrUserTokenUnavailable, err)
	}
	defer userTok.Close()

	var primaryTok windows.Token
	if err := windows.DuplicateTokenEx(userTok, tokenLaunchAccess, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &primaryTok); err != nil {
		return nil, fmt.Errorf("dataplane: DuplicateTokenEx: %w", err)
	}
	defer primaryTok.Close()

	var envBlock *uint16
	if err := windows.CreateEnvironmentBlock(&envBlock, primaryTok, false); err != nil {
		return nil, fmt.Errorf("dataplane: CreateEnvironmentBlock: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(envBlock)

	appPtr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return nil, fmt.Errorf("dataplane: exe path: %w", err)
	}
	cmdPtr, err := windows.UTF16PtrFromString(buildCommandLine(exePath, args))
	if err != nil {
		return nil, fmt.Errorf("dataplane: command line: %w", err)
	}
	// Attach to the interactive window-station/desktop so a GDI capture (3a-iii)
	// can read it; a bad/missing desktop would otherwise blank the capture.
	deskPtr, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return nil, fmt.Errorf("dataplane: desktop: %w", err)
	}

	si := windows.StartupInfo{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop = deskPtr
	var pi windows.ProcessInformation

	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NO_WINDOW)
	if err := windows.CreateProcessAsUser(primaryTok, appPtr, cmdPtr, nil, nil,
		false /* inheritHandles */, flags, envBlock, nil, &si, &pi); err != nil {
		return nil, fmt.Errorf("dataplane: CreateProcessAsUser: %w", err)
	}
	// the thread handle is not needed
	_ = windows.CloseHandle(pi.Thread)

	// Defense-in-depth (Codex review #2): confirm the helper actually landed in
	// the target interactive session. A mismatch (e.g. Session 0) → terminate +
	// fail-closed rather than trust the launch.
	var actual uint32
	if err := windows.ProcessIdToSessionId(pi.ProcessId, &actual); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Process)
		return nil, fmt.Errorf("dataplane: verify helper session: %w", err)
	}
	if actual != session {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Process)
		return nil, fmt.Errorf("dataplane: helper landed in session %d, expected %d (fail-closed)", actual, session)
	}

	return &LaunchedHelper{Process: pi.Process, Pid: pi.ProcessId, SessionID: session}, nil
}
